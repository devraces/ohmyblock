#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Описание: Автоматическая установка прокси-стека на базе:
#   • Xray (VLESS + xHTTP + Reality)   — маскировочный TLS-прокси
#   • Hysteria2                         — UDP/QUIC прокси с TLS от Let's Encrypt
#   • Telemt (MTProto)                  — прокси для Telegram
#   • HAProxy                           — входная точка, SNI-роутер на порту 443/TCP
#
# Автор: Alexdev
# ─────────────────────────────────────────────────────────────────────────────

# Жёсткий режим: любая необработанная ошибка завершает скрипт,
# обращение к неустановленной переменной — тоже ошибка,
# ошибка в пайпе пробрасывается наружу.
set -Eeuo pipefail

# umask 077 — все создаваемые файлы получат права 600/700 по умолчанию,
# то есть будут доступны только root. Критично для ключей и конфигов.
umask 077

# Ловушка ERR: при любой ошибке в скрипте печатает номер строки в stderr.
trap 'echo "Ошибка на строке $LINENO" >&2' ERR

# ─── Цветовые коды ANSI для вывода в терминал ────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status()  { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info()    { echo -e "${BLUE}[i]${NC} $1"; }

# ─── normalize_host ───────────────────────────────────────────────────────────
# Приводит введённый пользователем хост к единому виду:
#   1. Убирает пробелы
#   2. Срезает префиксы http:// и https://
#   3. Срезает завершающий слэш
#   4. Приводит к нижнему регистру
normalize_host() {
  local h="${1:-}"
  h="${h//[[:space:]]/}"
  h="${h#http://}"
  h="${h#https://}"
  h="${h%/}"
  printf '%s' "$h" | tr '[:upper:]' '[:lower:]'
}

# ─── valid_port ───────────────────────────────────────────────────────────────
# Проверяет, что переданная строка — корректный номер порта (1–65535).
# 10#$1 — принудительный перевод в десятичную, защита от "08" → восьмеричное.
valid_port() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] && (( 1 <= 10#$1 && 10#$1 <= 65535 ))
}

# ─── find_cert_name_for_domain ────────────────────────────────────────────────
# Ищет в базе certbot имя сертификата, который покрывает указанный домен.
# Используется, чтобы переиспользовать уже выпущенный сертификат.
find_cert_name_for_domain() {
  local domain="$1"
  certbot certificates 2>/dev/null | awk -v target="$domain" '
    /^Certificate Name:/ {name=$3}
    /^[[:space:]]+Domains:/ {
      for (i=2; i<=NF; i++) {
        if ($i == target) {
          print name
          exit
        }
      }
    }
  '
}

# ─────────────────────────────────────────────────────────────────────────────
# ПРОВЕРКА ПРАВ: скрипт должен запускаться от root.
# ─────────────────────────────────────────────────────────────────────────────
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  print_error "Скрипт должен запускаться от root"
  exit 1
fi

echo ""
echo "============================================"
echo "   VLESS + Hysteria2 + Telemt  by.Alexdev   "
echo "============================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# БЛОК ИНТЕРАКТИВНОГО ВВОДА ПАРАМЕТРОВ
# ─────────────────────────────────────────────────────────────────────────────
print_info "Параметры"
echo ""

read -rp "Порт HAProxy [443]: " HAPROXY_PORT
HAPROXY_PORT=${HAPROXY_PORT:-443}
valid_port "$HAPROXY_PORT" || { print_error "Неверный HAProxy порт"; exit 1; }

read -rp "Порт Xray/VLESS [8443]: " XRAY_PORT
XRAY_PORT=${XRAY_PORT:-8443}
valid_port "$XRAY_PORT" || { print_error "Неверный Xray порт"; exit 1; }

read -rp "Порт Telemt [9443]: " TELEMT_PORT
TELEMT_PORT=${TELEMT_PORT:-9443}
valid_port "$TELEMT_PORT" || { print_error "Неверный Telemt порт"; exit 1; }

read -rp "SNI для VLESS Reality [github.com]: " XRAY_SNI
XRAY_SNI=${XRAY_SNI:-github.com}
XRAY_SNI="$(normalize_host "$XRAY_SNI")"
# Базовый домен без префикса www. — серверным SNI Xray будет
# одновременно "$XRAY_SNI" и "www.$XRAY_SNI"; защита от "www.www.…".
XRAY_SNI="${XRAY_SNI#www.}"

read -rp "TLS домен для Telemt [www.google.com]: " TELEMT_TLS_DOMAIN
TELEMT_TLS_DOMAIN=${TELEMT_TLS_DOMAIN:-www.google.com}
TELEMT_TLS_DOMAIN="$(normalize_host "$TELEMT_TLS_DOMAIN")"

read -rp "Домен для Hysteria2 (для заглушки и TLS): " HY2_DOMAIN
HY2_DOMAIN="$(normalize_host "$HY2_DOMAIN")"

read -rp "Email для Let's Encrypt: " HY2_EMAIL

read -rp "Первый пользователь [main]: " FIRST_USER
FIRST_USER=${FIRST_USER:-main}

# Внешний IP сервера (fallback-цепочка из трёх методов).
# Используется и здесь, и в lib (см. server_ip()).
detect_server_ip() {
  local ip=""
  ip="$(curl -4 -fsS https://icanhazip.com 2>/dev/null || true)"
  ip="${ip//$'\n'/}"
  if [[ -z "$ip" ]]; then
    ip="$(curl -4 -fsS https://ifconfig.me 2>/dev/null || true)"
    ip="${ip//$'\n'/}"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  printf '%s' "$ip"
}
SERVER_IP="$(detect_server_ip)"
if [[ -z "$SERVER_IP" ]]; then
  print_error "Не удалось определить внешний IP сервера"
  exit 1
fi

read -rp "Публичный хост для ссылок [${SERVER_IP}]: " PUBLIC_HOST
PUBLIC_HOST=${PUBLIC_HOST:-$SERVER_IP}
PUBLIC_HOST="$(normalize_host "$PUBLIC_HOST")"
[[ -z "$PUBLIC_HOST" ]] && PUBLIC_HOST="$SERVER_IP"

# ─── Финальная валидация ──────────────────────────────────────────────────────
if [[ -z "$XRAY_SNI" || -z "$TELEMT_TLS_DOMAIN" || -z "$HY2_DOMAIN" || -z "$HY2_EMAIL" ]]; then
  print_error "Не все параметры заданы"
  exit 1
fi

if ! [[ "$FIRST_USER" =~ ^[A-Za-z0-9._-]+$ ]]; then
  print_error "Имя пользователя должно содержать только A-Za-z0-9._-"
  exit 1
fi

if [[ "$XRAY_SNI" == "$TELEMT_TLS_DOMAIN" ]]; then
  print_error "SNI для Xray и Telemt должны быть разными"
  exit 1
fi

if [[ "$HY2_DOMAIN" == "$XRAY_SNI" || "$HY2_DOMAIN" == "$TELEMT_TLS_DOMAIN" ]]; then
  print_error "Домен Hysteria2 должен быть отдельным, не совпадать с Xray/Telemt SNI"
  exit 1
fi

# ─── Предпросмотр ────────────────────────────────────────────────────────────
echo ""
print_info "Конфигурация:"
echo "  HAProxy:     0.0.0.0:${HAPROXY_PORT}"
echo "  Xray:        127.0.0.1:${XRAY_PORT}"
echo "  Telemt:      127.0.0.1:${TELEMT_PORT}"
echo "  Xray SNI:    ${XRAY_SNI}"
echo "  Telemt SNI:  ${TELEMT_TLS_DOMAIN}"
echo "  Hysteria2:   ${HY2_DOMAIN}:443/udp"
echo "  Public host: ${PUBLIC_HOST}"
echo "  First user:   ${FIRST_USER}"
echo ""

read -rp "Продолжить установку? (y/n): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  print_warning "Установка отменена"
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# УСТАНОВКА СИСТЕМНЫХ ПАКЕТОВ
# ─────────────────────────────────────────────────────────────────────────────
print_info "Обновление и пакеты..."
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y qrencode curl jq haproxy wget openssl tar certbot ufw ca-certificates kmod python3
print_status "Пакеты установлены"

# ─────────────────────────────────────────────────────────────────────────────
# ВКЛЮЧЕНИЕ BBR
# ─────────────────────────────────────────────────────────────────────────────
print_info "BBR..."
if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
  print_status "BBR уже включен"
else
  modprobe tcp_bbr 2>/dev/null || true
  grep -q '^net.core.default_qdisc=fq$' /etc/sysctl.conf || echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
  grep -q '^net.ipv4.tcp_congestion_control=bbr$' /etc/sysctl.conf || echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true
  print_status "BBR включен"
fi

# ─────────────────────────────────────────────────────────────────────────────
# ДИРЕКТОРИИ И БЭКАПЫ
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p /usr/local/etc/xray /usr/local/etc/proxy /etc/telemt /etc/hysteria /etc/hysteria/certs /opt/telemt /var/www/masq /usr/local/lib
chmod 755 /usr/local /usr/local/etc 2>/dev/null || true
chmod 755 /usr/local/etc/xray /usr/local/etc/proxy /etc/telemt /etc/hysteria /etc/hysteria/certs

KEYS="/usr/local/etc/xray/.keys"
USERS_DB="/usr/local/etc/proxy/users.json"

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    cp "$f" "$f.bak.$(date +%F_%H%M%S)" || true
  fi
}
backup_file "$KEYS"
backup_file "$USERS_DB"

# ─────────────────────────────────────────────────────────────────────────────
# ОБЩАЯ БИБЛИОТЕКА /usr/local/lib/proxy-common.sh
#
# Единственный источник переиспользуемых функций. Записываем её ДО установки
# Xray, чтобы можно было сразу `source` и пользоваться gen_alnum_pass / etc
# в основном скрипте — без дублирования кода.
# ─────────────────────────────────────────────────────────────────────────────
cat > /usr/local/lib/proxy-common.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# ─── Пути ────────────────────────────────────────────────────────────────────
KEYS="/usr/local/etc/xray/.keys"
USERS_DB="/usr/local/etc/proxy/users.json"
XRAY_CFG="/usr/local/etc/xray/config.json"
TEL_CFG="/etc/telemt/telemt.toml"
HY2_CFG="/etc/hysteria/config.yaml"

# ─── kv <key> ─────────────────────────────────────────────────────────────────
# Читает значение по ключу из файла .keys (формат "key: value").
kv() {
  awk -F': ' -v k="$1" '$1==k {print $2; exit}' "$KEYS" 2>/dev/null
}

# ─── Генераторы ──────────────────────────────────────────────────────────────
# gen_alnum_pass: 16 символов A-Za-z0-9 (для Hysteria2-паролей).
gen_alnum_pass() {
  local p=""
  while :; do
    p="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)"
    if [[ ${#p} -eq 16 ]]; then
      printf '%s' "$p"
      return 0
    fi
  done
}

# gen_hex_secret: 32 hex (16 байт) для MTProto-секрета Telemt.
gen_hex_secret() {
  openssl rand -hex 16
}

# ─── Сетевые параметры ───────────────────────────────────────────────────────
server_ip() {
  local ip=""
  ip="$(curl -4 -fsS https://icanhazip.com 2>/dev/null || true)"
  ip="${ip//$'\n'/}"
  if [[ -z "$ip" ]]; then
    ip="$(curl -4 -fsS https://ifconfig.me 2>/dev/null || true)"
    ip="${ip//$'\n'/}"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  printf '%s' "$ip"
}

public_host() {
  local h
  h="$(kv public_host)"
  [[ -z "$h" ]] && h="$(server_ip)"
  printf '%s' "$h"
}

public_port() {
  local p
  p="$(kv haproxy_port)"
  [[ -z "$p" ]] && p=443
  printf '%s' "$p"
}

hy2_domain() {
  kv hy2_domain
}

# ─── База пользователей ──────────────────────────────────────────────────────
db_user_count() {
  jq '.users | length' "$USERS_DB" 2>/dev/null || echo 0
}

db_first_user() {
  jq -r '.users[0].name // empty' "$USERS_DB" 2>/dev/null
}

db_user_names() {
  jq -r '.users[].name' "$USERS_DB" 2>/dev/null
}

db_has_user() {
  local name="$1"
  jq -e --arg n "$name" '.users[]? | select(.name==$n)' "$USERS_DB" >/dev/null 2>&1
}

db_get_user_field() {
  local name="$1"
  local field="$2"
  jq -r --arg n "$name" --arg f "$field" '.users[] | select(.name==$n) | .[$f] // empty' "$USERS_DB" 2>/dev/null | head -n1
}

# Атомарная запись через mktemp+mv.
db_add_user() {
  local name="$1" uuid="$2" hy2pass="$3" telsecret="$4"
  local tmp
  tmp="$(mktemp)"
  jq --arg name "$name" --arg uuid "$uuid" \
     --arg hy2pass "$hy2pass" --arg telsecret "$telsecret" \
     '.users += [{"name":$name,"uuid":$uuid,"hy2pass":$hy2pass,"telsecret":$telsecret}]' \
     "$USERS_DB" > "$tmp"
  mv "$tmp" "$USERS_DB"
  chmod 600 "$USERS_DB"
}

db_remove_user() {
  local name="$1"
  local tmp
  tmp="$(mktemp)"
  jq --arg name "$name" '.users |= map(select(.name != $name))' "$USERS_DB" > "$tmp"
  mv "$tmp" "$USERS_DB"
  chmod 600 "$USERS_DB"
}

# ─── Высокоуровневые хелперы для команд /usr/local/bin/* ─────────────────────

# require_first_user: печатает имя первого пользователя, иначе exit 1.
require_first_user() {
  local u
  u="$(db_first_user)"
  if [[ -z "$u" ]]; then
    echo "Нет пользователей" >&2
    exit 1
  fi
  printf '%s' "$u"
}

# db_print_users_indexed: загружает пользователей в массив USERS_ARR
# и печатает пронумерованный список. Если список пуст — exit 1.
# Использует глобальный массив USERS_ARR, чтобы вызывающий мог его потом читать.
db_print_users_indexed() {
  mapfile -t USERS_ARR < <(db_user_names)
  if [[ ${#USERS_ARR[@]} -eq 0 ]]; then
    echo "${1:-Список пользователей пуст}" >&2
    exit 1
  fi
  echo "Пользователи:"
  local i
  for i in "${!USERS_ARR[@]}"; do
    echo "$((i+1)). ${USERS_ARR[$i]}"
  done
}

# db_pick_user <prompt>: интерактивный выбор пользователя из USERS_ARR.
# Перед вызовом обычно идёт db_print_users_indexed.
# Печатает выбранное имя или exit 1 при ошибочном вводе.
db_pick_user() {
  local prompt="${1:-Выберите пользователя}"
  local choice
  read -rp "${prompt}: " choice
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#USERS_ARR[@]} )); then
    echo "Ошибка: номер от 1 до ${#USERS_ARR[@]}" >&2
    exit 1
  fi
  printf '%s' "${USERS_ARR[$((choice-1))]}"
}

# ─── Формирование ссылок ─────────────────────────────────────────────────────

# Полный MTProto TLS-секрет: ee + <hex секрет> + <hex домен>.
tg_full_secret_for() {
  local user="$1"
  local raw domain_hex
  raw="$(db_get_user_field "$user" telsecret)"
  domain_hex="$(printf '%s' "$(kv telemt_tls_domain)" | od -An -tx1 | tr -d ' \n')"
  printf 'ee%s%s' "$raw" "$domain_hex"
}

# VLESS xHTTP + Reality URI.
xray_link_for() {
  local user="$1"
  local uuid pbk sid sni port
  uuid="$(db_get_user_field "$user" uuid)"
  pbk="$(kv xray_public_key)"
  sid="$(kv xray_short_id)"
  sni="$(kv xray_sni)"
  port="$(public_port)"
  printf 'vless://%s@%s:%s?type=xhttp&security=reality&encryption=none&host=%s&path=%%2F&mode=auto&sni=%s&fp=firefox&pbk=%s&sid=%s&spx=%%2F#%s\n' \
    "$uuid" "$(public_host)" "$port" "$sni" "$sni" "$pbk" "$sid" "$user"
}

# Hysteria2 URI.
hy2_link_for() {
  local user="$1"
  local pass domain
  pass="$(db_get_user_field "$user" hy2pass)"
  domain="$(hy2_domain)"
  printf 'hy2://%s:%s@%s:443?sni=%s&alpn=h3&insecure=0&allowInsecure=0#%s\n' \
    "$user" "$pass" "$domain" "$domain" "$user"
}

# Telegram MTProto ссылки в двух форматах.
tg_https_link_for() {
  local user="$1"
  local full
  full="$(tg_full_secret_for "$user")"
  printf 'https://t.me/proxy?server=%s&port=%s&secret=%s\n' "$(public_host)" "$(public_port)" "$full"
}

tg_scheme_link_for() {
  local user="$1"
  local full
  full="$(tg_full_secret_for "$user")"
  printf 'tg://proxy?server=%s&port=%s&secret=%s\n' "$(public_host)" "$(public_port)" "$full"
}

# QR в терминал.
show_qr() {
  printf '%s\n' "$1" | qrencode -t ansiutf8
}

# ─────────────────────────────────────────────────────────────────────────────
# РЕНДЕРИНГ КОНФИГОВ
# Все три функции перегенерируют конфиг "с нуля" из текущего состояния БД.
# Это гарантирует консистентность: после изменений в БД вызываем
# render_all_configs → все сервисы синхронизируются.
# ─────────────────────────────────────────────────────────────────────────────

render_xray_config() {
  local clients_json port sni pkey sid
  clients_json="$(jq -c '[.users[] | {email:.name,id:.uuid,flow:""}]' "$USERS_DB")"
  port="$(kv xray_port)"
  sni="$(kv xray_sni)"
  pkey="$(kv xray_private_key)"
  sid="$(kv xray_short_id)"
  cat > "$XRAY_CFG" <<EOF2
{
  "log": {
    "loglevel": "warning"
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "domain": ["geosite:category-ads-all"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "ip": ["geoip:cn"],
        "outboundTag": "block"
      }
    ]
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": ${port},
      "protocol": "vless",
      "settings": {
        "clients": ${clients_json},
        "decryption": "none"
      },
      "streamSettings": {
        "network": "xhttp",
        "xhttpSettings": {
          "path": "/"
        },
        "security": "reality",
        "realitySettings": {
          "show": false,
          "target": "${sni}:443",
          "serverNames": ["${sni}", "www.${sni}"],
          "privateKey": "${pkey}",
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": ["${sid}"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ],
  "policy": {
    "levels": {
      "0": {
        "handshake": 3,
        "connIdle": 180
      }
    }
  }
}
EOF2
  chmod 644 "$XRAY_CFG"
  chown root:root "$XRAY_CFG"
}

render_telemt_config() {
  local pub_host hap_port tel_port tls_domain
  pub_host="$(kv public_host)"
  hap_port="$(kv haproxy_port)"
  tel_port="$(kv telemt_port)"
  tls_domain="$(kv telemt_tls_domain)"
  {
    echo "[general]"
    echo "use_middle_proxy = false"
    echo "log_level = \"normal\""
    echo
    echo "[general.modes]"
    echo "classic = false"
    echo "secure = false"
    echo "tls = true"
    echo
    echo "[general.links]"
    echo "show = \"*\""
    echo "public_host = \"${pub_host}\""
    echo "public_port = ${hap_port}"
    echo
    echo "[server]"
    echo "port = ${tel_port}"
    echo "listen_addr_ipv4 = \"127.0.0.1\""
    echo "max_connections = 10000"
    echo
    echo "[server.api]"
    echo "enabled = true"
    echo "listen = \"127.0.0.1:7443\""
    echo "whitelist = [\"127.0.0.1/32\", \"::1/128\"]"
    echo
    echo "[censorship]"
    echo "tls_domain = \"${tls_domain}\""
    echo
    echo "[access.users]"
    jq -r '.users[] | "\"" + .name + "\" = \"" + .telsecret + "\""' "$USERS_DB"
  } > "$TEL_CFG"
  chown telemt:telemt "$TEL_CFG"
  chmod 600 "$TEL_CFG"
}

render_hy2_config() {
  local certname
  certname="$(kv hy2_cert_name)"
  [[ -z "$certname" ]] && certname="$(kv hy2_domain)"
  {
    echo "listen: :443"
    echo
    echo "tls:"
    echo "  cert: /etc/letsencrypt/live/${certname}/fullchain.pem"
    echo "  key: /etc/letsencrypt/live/${certname}/privkey.pem"
    echo
    echo "auth:"
    echo "  type: userpass"
    echo "  userpass:"
    jq -r '.users[] | "    \"" + .name + "\": \"" + .hy2pass + "\""' "$USERS_DB"
    echo
    echo "masquerade:"
    echo "  type: file"
    echo "  listenHTTPS: :8444"
    echo "  forceHTTPS: true"
    echo "  file:"
    echo "    dir: /var/www/masq"
  } > "$HY2_CFG"
  chown root:root "$HY2_CFG"
  chmod 600 "$HY2_CFG"
}

render_all_configs() {
  render_xray_config
  render_telemt_config
  render_hy2_config
}

# Перезапуск всех динамических сервисов после изменений в БД пользователей.
restart_dynamic_services() {
  systemctl restart xray
  systemctl restart telemt
  systemctl restart hysteria-server.service
}

# ─── print_bundle <user> ──────────────────────────────────────────────────────
# Все ссылки + QR-коды для одного пользователя.
print_bundle() {
  local user="$1"
  local xlink hlink tlink tglink

  xlink="$(xray_link_for "$user")"
  hlink="$(hy2_link_for "$user")"
  tlink="$(tg_https_link_for "$user")"
  tglink="$(tg_scheme_link_for "$user")"

  echo "=== VLESS xhttp + Reality ==="
  echo "$xlink"
  echo
  echo "QR:"
  show_qr "$xlink"
  echo

  echo "=== Hysteria2 ==="
  echo "$hlink"
  echo
  echo "QR:"
  show_qr "$hlink"
  echo

  echo "=== Telegram MTProto Proxy ==="
  echo "HTTPS:"
  echo "$tlink"
  echo
  echo "TG:"
  echo "$tglink"
  echo
  echo "QR:"
  show_qr "$tlink"
}
EOF
chmod +x /usr/local/lib/proxy-common.sh

# Подключаем библиотеку — дальше пользуемся её хелперами без дублирования.
# shellcheck source=/usr/local/lib/proxy-common.sh
source /usr/local/lib/proxy-common.sh

# ─────────────────────────────────────────────────────────────────────────────
# УСТАНОВКА XRAY И ГЕНЕРАЦИЯ КЛЮЧЕЙ
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка Xray..."
bash -c "$(curl -4 -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/var/log/xray-install.log 2>&1

UUID="$(xray uuid)"

# Парсим вывод xray x25519 — формат заголовков может варьироваться между версиями.
X25519_OUT="$(xray x25519 2>&1 | tr -d '\r')"
PRIVATE_KEY="$(
  awk -F': ' '
    /^Private[[:space:]]*Key:/ {print $2; exit}
    /^PrivateKey:/ {print $2; exit}
  ' <<< "$X25519_OUT"
)"
PUBLIC_KEY="$(
  awk -F': ' '
    /^Public[[:space:]]*Key:/ {print $2; exit}
    /^PublicKey:/ {print $2; exit}
    /^Password \(PublicKey\):/ {print $2; exit}
  ' <<< "$X25519_OUT"
)"

if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
  echo "Не удалось получить ключи x25519"
  echo "Сырой вывод:"
  echo "$X25519_OUT"
  exit 1
fi

SHORT_ID="$(openssl rand -hex 8)"

# Учётные данные первого пользователя.
MAIN_HY2_PASS="$(gen_alnum_pass)"
MAIN_TEL_SECRET="$(gen_hex_secret)"

# ─── Сохраняем параметры установки в .keys ────────────────────────────────────
cat > "$KEYS" <<EOF
public_host: $PUBLIC_HOST
server_ip: $SERVER_IP
haproxy_port: $HAPROXY_PORT
xray_port: $XRAY_PORT
telemt_port: $TELEMT_PORT
xray_sni: $XRAY_SNI
telemt_tls_domain: $TELEMT_TLS_DOMAIN
hy2_domain: $HY2_DOMAIN
hy2_email: $HY2_EMAIL
hy2_cert_name: $HY2_DOMAIN
hysteria_service: hysteria-server.service
xray_uuid: $UUID
xray_private_key: $PRIVATE_KEY
xray_public_key: $PUBLIC_KEY
xray_short_id: $SHORT_ID
EOF
chmod 600 "$KEYS"

# ─── Инициализация базы пользователей ─────────────────────────────────────────
# Через jq -n — корректное JSON-экранирование на любых именах.
jq -n --arg name "$FIRST_USER" --arg uuid "$UUID" \
      --arg hy2pass "$MAIN_HY2_PASS" --arg telsecret "$MAIN_TEL_SECRET" \
      '{users: [{name:$name, uuid:$uuid, hy2pass:$hy2pass, telsecret:$telsecret}]}' \
      > "$USERS_DB"
chmod 600 "$USERS_DB"

# Генерируем Xray-конфиг и стартуем сервис.
render_xray_config
systemctl enable --now xray
systemctl restart xray
print_status "Xray установлен"

# ─────────────────────────────────────────────────────────────────────────────
# УСТАНОВКА TELEMT (MTProto прокси для Telegram)
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка Telemt..."

ARCH="$(uname -m)"

# musl — Alpine и др. минималистичные дистрибутивы; gnu — стандартная glibc.
if ldd --version 2>&1 | grep -iq musl; then
  LIBC="musl"
else
  LIBC="gnu"
fi

TELEMT_URL="https://github.com/telemt/telemt/releases/latest/download/telemt-${ARCH}-linux-${LIBC}.tar.gz"
TMPDIR="$(mktemp -d)"

print_info "Скачивание: telemt-${ARCH}-linux-${LIBC}.tar.gz"
curl -fsSL -o "$TMPDIR/telemt.tar.gz" "$TELEMT_URL"
tar -xzf "$TMPDIR/telemt.tar.gz" -C "$TMPDIR"
install -m 755 "$TMPDIR/telemt" /bin/telemt
rm -rf "$TMPDIR"

# Системный пользователь telemt: nologin shell, домашняя директория /opt/telemt.
if ! id telemt &>/dev/null; then
  useradd -r -s /usr/sbin/nologin -d /opt/telemt telemt
  print_status "Пользователь telemt создан"
fi

mkdir -p /etc/telemt /opt/telemt
chown -R telemt:telemt /opt/telemt /etc/telemt

# ─── systemd unit для Telemt ─────────────────────────────────────────────────
cat > /etc/systemd/system/telemt.service <<'EOF'
[Unit]
Description=Telemt MTProto Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=/opt/telemt
ExecStart=/bin/telemt /etc/telemt/telemt.toml
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

render_telemt_config
systemctl daemon-reload
systemctl enable --now telemt
systemctl restart telemt
print_status "Telemt настроен"

# ─────────────────────────────────────────────────────────────────────────────
# УСТАНОВКА HYSTERIA2
# Hysteria2 работает поверх QUIC (UDP), не конкурирует с HAProxy на TCP.
# Занимает UDP :443. Для TCP с HY2_DOMAIN HAProxy роутит к masquerade :8444.
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка Hysteria2"

mkdir -p /var/www/masq /etc/hysteria/certs

# ─── Страница-заглушка для маскировки ─────────────────────────────────────────
cat > /var/www/masq/index.html <<'HTML'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Please wait</title>
  <style>
    body{background:#080808;height:100vh;margin:0;display:flex;flex-direction:column;align-items:center;justify-content:center;font-family:sans-serif}
    .dots{display:flex;gap:15px;margin-bottom:30px}
    .d{width:20px;height:20px;background:#fff;border-radius:50%;animation:b 1.4s infinite ease-in-out both}
    .d:nth-child(1){animation-delay:-0.32s}
    .d:nth-child(2){animation-delay:-0.16s}
    @keyframes b{0%,80%,100%{transform:scale(0);opacity:0.2}40%{transform:scale(1);opacity:1}}
    .t{color:#555;font-size:14px;letter-spacing:2px;font-weight:600}
  </style>
</head>
<body>
  <div class="dots">
    <div class="d"></div>
    <div class="d"></div>
    <div class="d"></div>
  </div>
  <div class="t">RETRYING CONNECTION</div>
</body>
</html>
HTML

# ─── Получение TLS-сертификата Let's Encrypt ─────────────────────────────────
# Три пути:
#   1. Уже есть валидный сертификат точно для $HY2_DOMAIN
#   2. Есть сертификат под другим именем, покрывающий этот домен
#   3. Нет сертификата → выпускаем через certbot standalone (требует свободный 80/tcp)
if [[ -s "/etc/letsencrypt/live/$HY2_DOMAIN/fullchain.pem" && -s "/etc/letsencrypt/live/$HY2_DOMAIN/privkey.pem" ]]; then
  CERT_NAME="$HY2_DOMAIN"
  print_status "Найден существующий сертификат: $HY2_DOMAIN"
else
  CERT_NAME="$(find_cert_name_for_domain "$HY2_DOMAIN" || true)"
  if [[ -n "$CERT_NAME" && -s "/etc/letsencrypt/live/$CERT_NAME/fullchain.pem" && -s "/etc/letsencrypt/live/$CERT_NAME/privkey.pem" ]]; then
    print_status "Найден существующий сертификат: $CERT_NAME"
  else
    # Проверяем, не занят ли порт 80 (нужен для ACME challenge).
    if ss -ltn 2>/dev/null | awk '$4 ~ /:80$/ {found=1} END {exit !found}'; then
      print_error "Порт 80 занят. Освободи 80/tcp для первого выпуска сертификата."
      exit 1
    fi

    print_info "Получение сертификата Let's Encrypt для Hysteria2..."
    # Все флаги одной командой, без inline-комментариев между \ —
    # иначе перенос строк ломается.
    certbot certonly --standalone \
      --cert-name "$HY2_DOMAIN" \
      --keep-until-expiring \
      -d "$HY2_DOMAIN" \
      -m "$HY2_EMAIL" \
      --agree-tos \
      --non-interactive

    CERT_NAME="$HY2_DOMAIN"
  fi
fi

# Атомарное обновление поля hy2_cert_name в .keys (надёжнее `sed -i`).
update_keys_field() {
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$val" '
    BEGIN { done = 0 }
    $1 == k ":" || index($0, k ":") == 1 { print k ": " v; done = 1; next }
    { print }
    END { if (!done) print k ": " v }
  ' "$KEYS" > "$tmp"
  mv "$tmp" "$KEYS"
  chmod 600 "$KEYS"
}
update_keys_field "hy2_cert_name" "$CERT_NAME"

# Системный пользователь для Hysteria2.
if ! id hysteria &>/dev/null; then
  useradd -r -U -d /etc/hysteria -s /usr/sbin/nologin hysteria
fi

# Официальный установщик Hysteria2.
print_info "Установка Hysteria2..."
bash <(curl -fsSL https://get.hy2.sh/) >/var/log/hy2-install.log 2>&1

# Ищем бинарник hysteria.
HYST_BIN="$(command -v hysteria || true)"
if [[ -z "$HYST_BIN" ]]; then
  HYST_BIN="/usr/local/bin/hysteria"
fi
if [[ ! -x "$HYST_BIN" ]]; then
  print_error "Не найден бинарник hysteria после установки"
  exit 1
fi

render_hy2_config

# ─── systemd unit для Hysteria2 ──────────────────────────────────────────────
cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/hysteria
ExecStart=$HYST_BIN server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Хук для автоматического перезапуска Hysteria2 после обновления сертификата.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/99-hysteria-restart.sh <<'EOF'
#!/bin/sh
systemctl restart hysteria-server.service 2>/dev/null || true
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/99-hysteria-restart.sh

systemctl daemon-reload
systemctl enable --now hysteria-server.service
systemctl restart hysteria-server.service
systemctl enable --now certbot.timer >/dev/null 2>&1 || true
print_status "Hysteria2 установлена"

# ─────────────────────────────────────────────────────────────────────────────
# НАСТРОЙКА HAPROXY — SNI-МАРШРУТИЗАТОР (TCP, layer 4)
# ─────────────────────────────────────────────────────────────────────────────
print_info "Настройка HAProxy..."

backup_file /etc/haproxy/haproxy.cfg

cat > /etc/haproxy/haproxy.cfg <<EOF
global
    log /dev/log local0    # логирование в syslog
    maxconn 8192           # максимум одновременных соединений
    user haproxy
    group haproxy

defaults
    log     global
    mode    tcp            # Layer 4 TCP режим (не HTTP!)
    option  tcplog
    option  dontlognull    # не логировать пустые соединения (health checks)
    timeout connect 10s    # таймаут установки соединения к бэкенду
    timeout client  300s   # таймаут простоя клиента (300с для долгих соединений)
    timeout server  300s   # таймаут ответа бэкенда
    retries 3

frontend front_main
    bind *:${HAPROXY_PORT}
    mode tcp

    # HAProxy должен прочитать часть потока для определения SNI.
    # inspect-delay 5s — ждём до 5 секунд данных от клиента.
    tcp-request inspect-delay 5s
    # Принимаем соединение только когда увидели TLS ClientHello (тип 1).
    # Это отсекает non-TLS соединения на входе.
    tcp-request content accept if { req_ssl_hello_type 1 }

    # ACL-правила маршрутизации по SNI (case-insensitive).
    acl is_hy2site req.ssl_sni -i ${HY2_DOMAIN}
    acl is_telemt  req.ssl_sni -i ${TELEMT_TLS_DOMAIN}
    acl is_xray    req.ssl_sni -i ${XRAY_SNI} www.${XRAY_SNI}  # Xray принимает и www.

    use_backend bk_hy2site if is_hy2site
    use_backend bk_telemt  if is_telemt
    use_backend bk_xray    if is_xray

    # По умолчанию (неизвестный SNI) → страница-заглушка Hysteria2.
    # Это важно: сканеры увидят нейтральный HTTPS-сайт.
    default_backend bk_hy2site

backend bk_hy2site
    mode tcp
    server hy2site 127.0.0.1:8444 check inter 30s   # masquerade HTTPS Hysteria2

backend bk_telemt
    mode tcp
    server telemt 127.0.0.1:${TELEMT_PORT} check inter 30s

backend bk_xray
    mode tcp
    server xray 127.0.0.1:${XRAY_PORT} check inter 30s
EOF

if haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
  print_status "HAProxy конфиг валиден"
else
  print_error "Ошибка конфигурации HAProxy"
  exit 1
fi

systemctl enable --now haproxy
systemctl restart haproxy
print_status "HAProxy настроен"

# ─────────────────────────────────────────────────────────────────────────────
# НАСТРОЙКА UFW
# ─────────────────────────────────────────────────────────────────────────────
print_info "Настройка UFW..."
ufw allow 22/tcp comment "SSH"
ufw allow 80/tcp comment "ACME"
ufw allow ${HAPROXY_PORT}/tcp comment "HAProxy"
ufw allow 443/udp comment "Hysteria2"
ufw --force enable
print_status "UFW настроен"

# ─────────────────────────────────────────────────────────────────────────────
# УПРАВЛЯЮЩИЕ КОМАНДЫ /usr/local/bin/*
# Все они source-ят /usr/local/lib/proxy-common.sh.
# ─────────────────────────────────────────────────────────────────────────────

# ─── mainuser ─────────────────────────────────────────────────────────────────
cat > /usr/local/bin/mainuser <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

user="$(require_first_user)"
print_bundle "$user"
EOF
chmod +x /usr/local/bin/mainuser

# ─── userlist ─────────────────────────────────────────────────────────────────
cat > /usr/local/bin/userlist <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

db_print_users_indexed
EOF
chmod +x /usr/local/bin/userlist

# ─── newuser ──────────────────────────────────────────────────────────────────
# Интерактивно создаёт нового пользователя, обновляет конфиги и перезапускает сервисы.
cat > /usr/local/bin/newuser <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

read -rp "Введите имя пользователя: " NAME
if [[ -z "$NAME" || "$NAME" == *" "* ]]; then
  echo "Имя не может быть пустым или содержать пробелы."
  exit 1
fi
if ! [[ "$NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Разрешены только A-Za-z0-9._-"
  exit 1
fi
if db_has_user "$NAME"; then
  echo "Пользователь '$NAME' уже существует."
  exit 1
fi

UUID="$(xray uuid)"
HY2PASS="$(gen_alnum_pass)"
TELSECRET="$(gen_hex_secret)"

db_add_user "$NAME" "$UUID" "$HY2PASS" "$TELSECRET"
render_all_configs
restart_dynamic_services

print_bundle "$NAME"
EOF
chmod +x /usr/local/bin/newuser

# ─── rmuser ───────────────────────────────────────────────────────────────────
# Удаляет пользователя; защита от удаления последнего.
cat > /usr/local/bin/rmuser <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

db_print_users_indexed "Нет пользователей для удаления."

if [[ ${#USERS_ARR[@]} -le 1 ]]; then
  echo "Нельзя удалить последнего пользователя."
  exit 1
fi

SEL="$(db_pick_user "Номер для удаления")"

db_remove_user "$SEL"
render_all_configs
restart_dynamic_services

echo "Пользователь '$SEL' удалён."
EOF
chmod +x /usr/local/bin/rmuser

# ─── sharelink ────────────────────────────────────────────────────────────────
cat > /usr/local/bin/sharelink <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

db_print_users_indexed "Нет пользователей."
SEL="$(db_pick_user "Выберите пользователя")"
print_bundle "$SEL"
EOF
chmod +x /usr/local/bin/sharelink

# ─── hy2info ──────────────────────────────────────────────────────────────────
cat > /usr/local/bin/hy2info <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

user="$(require_first_user)"
LINK="$(hy2_link_for "$user")"
echo ""
echo "=== Hysteria2 ==="
echo "$LINK"
echo ""
echo "QR:"
show_qr "$LINK"
EOF
chmod +x /usr/local/bin/hy2info

# ─── hy2list ──────────────────────────────────────────────────────────────────
cat > /usr/local/bin/hy2list <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)
if [[ ${#users[@]} -eq 0 ]]; then
  echo "Пользователей нет"
  exit 1
fi

echo "Пользователи Hysteria2:"
for i in "${!users[@]}"; do
  echo "$((i+1)). ${users[$i]}"
done
EOF
chmod +x /usr/local/bin/hy2list

# ─── hy2links ─────────────────────────────────────────────────────────────────
cat > /usr/local/bin/hy2links <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)
if [[ ${#users[@]} -eq 0 ]]; then
  echo "Пользователей нет"
  exit 1
fi

echo "Ссылки Hysteria2:"
for u in "${users[@]}"; do
  echo "$u -> $(hy2_link_for "$u")"
done
EOF
chmod +x /usr/local/bin/hy2links

# ─── tglink ───────────────────────────────────────────────────────────────────
cat > /usr/local/bin/tglink <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

user="$(require_first_user)"
HTTPS_LINK="$(tg_https_link_for "$user")"
TG_LINK="$(tg_scheme_link_for "$user")"

echo ""
echo "=== Telegram MTProto Proxy ==="
echo ""
echo "HTTPS:"
echo "$HTTPS_LINK"
echo ""
echo "TG:"
echo "$TG_LINK"
echo ""
echo "QR:"
show_qr "$HTTPS_LINK"
EOF
chmod +x /usr/local/bin/tglink

# ─── telegramlinks ────────────────────────────────────────────────────────────
cat > /usr/local/bin/telegramlinks <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)
if [[ ${#users[@]} -eq 0 ]]; then
  echo "Пользователей нет"
  exit 1
fi

echo "=== Telemt MTProto Proxy ==="
for u in "${users[@]}"; do
  echo "$u -> $(tg_https_link_for "$u")"
done
EOF
chmod +x /usr/local/bin/telegramlinks

# ─── proxystatus ──────────────────────────────────────────────────────────────
cat > /usr/local/bin/proxystatus <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

HAPROXY_PORT="$(kv haproxy_port)"
XRAY_PORT="$(kv xray_port)"
TELEMT_PORT="$(kv telemt_port)"
[[ -z "$HAPROXY_PORT" ]] && HAPROXY_PORT=443
[[ -z "$XRAY_PORT" ]] && XRAY_PORT=8443
[[ -z "$TELEMT_PORT" ]] && TELEMT_PORT=9443

echo ""
echo "=== Статус сервисов ==="
for svc in haproxy xray telemt hysteria-server.service; do
  printf "%-24s : " "$svc"
  if systemctl is-active --quiet "$svc"; then
    echo "работает"
  else
    echo "не работает"
  fi
done

echo ""
echo "=== Порты ==="
ss -tlnup 2>/dev/null | grep -E "(:${HAPROXY_PORT}|:${XRAY_PORT}|:${TELEMT_PORT}|:80|:443|:8444)" || true
echo ""
EOF
chmod +x /usr/local/bin/proxystatus

# ─────────────────────────────────────────────────────────────────────────────
# СПРАВОЧНЫЙ ФАЙЛ /root/help
# ─────────────────────────────────────────────────────────────────────────────
cat > /root/help <<'EOF'
============================================
  Команды управления
============================================

Общий users flow:
  newuser     — создать пользователя во всех сервисах сразу
  rmuser      — удалить пользователя из всех сервисов
  userlist    — список пользователей
  sharelink   — показать все ссылки выбранного пользователя
  mainuser    — ссылки первого пользователя

Hysteria2:
  hy2info     — Hysteria2 первого пользователя
  hy2list     — список пользователей
  hy2links    — все Hysteria2 ссылки

Telegram / Telemt:
  tglink         — ссылка первого пользователя
  telegramlinks  — все Telegram proxy ссылки

Статус:
  proxystatus   — проверка сервисов

============================================
  Конфиги
============================================

  /usr/local/etc/xray/config.json
  /usr/local/etc/xray/.keys
  /usr/local/etc/proxy/users.json
  /etc/hysteria/config.yaml
  /etc/telemt/telemt.toml
  /etc/haproxy/haproxy.cfg

============================================
  Перезапуск
============================================

  systemctl restart haproxy
  systemctl restart xray
  systemctl restart telemt
  systemctl restart hysteria-server.service
EOF

# ─────────────────────────────────────────────────────────────────────────────
# ФИНАЛЬНЫЙ ПЕРЕЗАПУСК
# ─────────────────────────────────────────────────────────────────────────────
systemctl daemon-reload
restart_dynamic_services
systemctl restart haproxy

echo ""
echo "============================================"
print_status "Установка завершена"
echo "  TCP ${HAPROXY_PORT} -> HAProxy -> Xray + Telemt + Hysteria2 site"
echo "  UDP 443 -> Hysteria2"
echo "  Первый пользователь: ${FIRST_USER}"
echo "============================================"
echo ""

mainuser
echo ""
print_info "Справка: cat /root/help"
print_info "Проверка: proxystatus"
