#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# VLESS (xHTTP + Reality) + Hysteria2 + Telemt (MTProto) + HAProxy (SNI router)
#
# Production-ready инсталлер.
#   • HAProxy на :443/TCP — SNI-роутер на три бэкенда
#   • Xray — VLESS xHTTP + Reality на 127.0.0.1:8443
#   • Telemt — MTProto fake-TLS на 127.0.0.1:9443
#   • Hysteria2 — QUIC на :443/UDP (TLS от Let's Encrypt)
#
# Идемпотентность: повторный запуск БЕЗ --reinstall сохраняет ключи Reality
# и базу пользователей. С --reinstall — пересоздаёт всё с нуля.
#
# Автор оригинала: Alexdev.
# ─────────────────────────────────────────────────────────────────────────────

set -Eeuo pipefail
umask 077

# ─── Локаль ──────────────────────────────────────────────────────────────────
# Парсинг вывода certbot/xray и т.п. зависит от языка → форсим C.
export LC_ALL=C
export LANG=C
export DEBIAN_FRONTEND=noninteractive

# ─── Логирование установки в файл + stdout ───────────────────────────────────
INSTALL_LOG="/var/log/proxy-install.log"
mkdir -p "$(dirname "$INSTALL_LOG")"
# tee'им весь вывод с момента старта (stderr тоже).
exec > >(tee -a "$INSTALL_LOG") 2>&1
echo "=== install started: $(date -u +%FT%TZ) ==="

# ─── Trap с кодом возврата ───────────────────────────────────────────────────
on_err() {
  local rc=$?
  echo "[ERR] exit=$rc on line $LINENO of $0" >&2
  exit "$rc"
}
trap on_err ERR

# ─── Цвета (только для TTY) ──────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi
print_status()  { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1" >&2; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info()    { echo -e "${BLUE}[i]${NC} $1"; }

# ─── Хелперы общего назначения ───────────────────────────────────────────────

# retry <attempts> <delay_sec> <cmd...>
retry() {
  local n=$1 d=$2; shift 2
  local i=0
  until "$@"; do
    i=$((i+1))
    if (( i >= n )); then
      return 1
    fi
    print_warning "повтор ($i/$n) после ошибки: $*"
    sleep "$d"
  done
}

# Ждать, пока systemd unit не станет active. Таймаут в секундах.
wait_for_active() {
  local svc=$1 timeout=${2:-15} i=0
  while (( i < timeout )); do
    if systemctl is-active --quiet "$svc"; then
      return 0
    fi
    sleep 1
    i=$((i+1))
  done
  return 1
}

# normalize_host: убирает пробелы/префиксы/завершающий слэш, нижний регистр.
normalize_host() {
  local h="${1:-}"
  h="${h//[[:space:]]/}"
  h="${h#http://}"
  h="${h#https://}"
  h="${h%/}"
  printf '%s' "$h" | tr '[:upper:]' '[:lower:]'
}

valid_port() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] && (( 1 <= 10#$1 && 10#$1 <= 65535 ))
}

valid_email() {
  [[ "${1:-}" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

valid_domain() {
  [[ "${1:-}" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]
}

# Поиск имени уже выпущенного certbot-сертификата для домена.
find_cert_name_for_domain() {
  local domain="$1"
  certbot certificates 2>/dev/null | awk -v target="$domain" '
    /^Certificate Name:/ {name=$3}
    /^[[:space:]]+Domains:/ {
      for (i=2; i<=NF; i++) {
        if ($i == target) {
          print name; exit
        }
      }
    }
  '
}

# detect_server_ip: внешний IP сервера (fallback-цепочка).
detect_server_ip() {
  local ip=""
  for u in https://icanhazip.com https://ifconfig.me https://api.ipify.org; do
    ip="$(curl -4 -fsS --connect-timeout 5 --max-time 10 "$u" 2>/dev/null || true)"
    ip="${ip//$'\n'/}"; ip="${ip//[[:space:]]/}"
    [[ -n "$ip" ]] && { printf '%s' "$ip"; return 0; }
  done
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '%s' "${ip:-}"
}

# update_keys_field: безопасная замена поля key в .keys.
# Удаляет ВСЕ существующие строки с этим ключом и добавляет одну.
update_keys_field() {
  local file="$1" key="$2" val="$3" tmp
  tmp="$(mktemp)"
  awk -v k="$key" '
    {
      line = $0
      # ищем "key:" в начале строки (с пробелами или нет — ключ слева до ":")
      keypart = line
      sub(/:.*$/, "", keypart)
      # тримим пробелы у keypart
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", keypart)
      if (keypart == k) next   # выкинуть старые
      print line
    }
  ' "$file" > "$tmp"
  printf '%s: %s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$file"
  chmod 600 "$file"
}

# Бэкап + ротация (хранить N последних).
backup_file() {
  local f="$1" keep="${2:-5}"
  if [[ -f "$f" ]]; then
    cp -p "$f" "$f.bak.$(date -u +%Y%m%dT%H%M%SZ)" || true
    # удаляем старые бэкапы за пределами keep последних
    # shellcheck disable=SC2012
    ls -1t "$f".bak.* 2>/dev/null | tail -n +$((keep+1)) | xargs -r rm -f --
  fi
}

# ─── Проверка прав ───────────────────────────────────────────────────────────
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  print_error "Скрипт должен запускаться от root"
  exit 1
fi

# ─── Парсинг флагов ──────────────────────────────────────────────────────────
REINSTALL=false
NONINTERACTIVE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reinstall)      REINSTALL=true; shift ;;
    --noninteractive) NONINTERACTIVE=true; shift ;;
    -h|--help)
      cat <<H
Usage: $0 [--reinstall] [--noninteractive]

  --reinstall       Пересоздать ключи Reality и базу пользователей с нуля.
                    БЕЗ этого флага существующие .keys и users.json не трогаем.
  --noninteractive  Не задавать вопросов; использовать переменные окружения.

ENV (для --noninteractive):
  HAPROXY_PORT, XRAY_PORT, TELEMT_PORT,
  XRAY_SNI, TELEMT_TLS_DOMAIN, HY2_DOMAIN, HY2_EMAIL,
  PUBLIC_HOST, FIRST_USER
H
      exit 0
      ;;
    *) print_error "Неизвестный аргумент: $1"; exit 1 ;;
  esac
done

# ─── Состояние существующей установки ───────────────────────────────────────
KEYS="/usr/local/etc/xray/.keys"
USERS_DB="/usr/local/etc/proxy/users.json"
LOCK_FILE="/var/lock/proxy-users.lock"

EXISTING_INSTALL=false
if [[ -s "$KEYS" && -s "$USERS_DB" ]]; then
  EXISTING_INSTALL=true
fi

if $EXISTING_INSTALL && ! $REINSTALL; then
  print_info "Найдена существующая установка — переиспользую ключи и базу пользователей."
  print_info "Для полного пересоздания запусти: $0 --reinstall"
fi

echo ""
echo "============================================"
echo "   VLESS + Hysteria2 + Telemt (prod)        "
echo "============================================"
echo ""

# ─── Чтение существующих значений (если есть) ────────────────────────────────
read_kv_file() {
  local f="$1" k="$2"
  [[ -f "$f" ]] || { echo ""; return 0; }
  awk -F': ' -v k="$k" '$1==k {print $2; exit}' "$f"
}

EXIST_HAPROXY_PORT="$(read_kv_file "$KEYS" haproxy_port || true)"
EXIST_XRAY_PORT="$(read_kv_file "$KEYS" xray_port || true)"
EXIST_TELEMT_PORT="$(read_kv_file "$KEYS" telemt_port || true)"
EXIST_XRAY_SNI="$(read_kv_file "$KEYS" xray_sni || true)"
EXIST_TELEMT_TLS_DOMAIN="$(read_kv_file "$KEYS" telemt_tls_domain || true)"
EXIST_HY2_DOMAIN="$(read_kv_file "$KEYS" hy2_domain || true)"
EXIST_HY2_EMAIL="$(read_kv_file "$KEYS" hy2_email || true)"
EXIST_PUBLIC_HOST="$(read_kv_file "$KEYS" public_host || true)"

# ─── Интерактивный или env-driven ввод параметров ────────────────────────────
ask() {
  local prompt="$1" default="${2:-}" var
  if $NONINTERACTIVE; then
    printf '%s' "$default"
    return 0
  fi
  if [[ -n "$default" ]]; then
    read -rp "$prompt [$default]: " var
  else
    read -rp "$prompt: " var
  fi
  printf '%s' "${var:-$default}"
}

print_info "Параметры (Enter = значение по умолчанию)"
echo ""

HAPROXY_PORT="${HAPROXY_PORT:-$(ask "Порт HAProxy" "${EXIST_HAPROXY_PORT:-443}")}"
valid_port "$HAPROXY_PORT" || { print_error "Неверный HAProxy порт"; exit 1; }

XRAY_PORT="${XRAY_PORT:-$(ask "Порт Xray/VLESS (loopback)" "${EXIST_XRAY_PORT:-8443}")}"
valid_port "$XRAY_PORT" || { print_error "Неверный Xray порт"; exit 1; }

TELEMT_PORT="${TELEMT_PORT:-$(ask "Порт Telemt (loopback)" "${EXIST_TELEMT_PORT:-9443}")}"
valid_port "$TELEMT_PORT" || { print_error "Неверный Telemt порт"; exit 1; }

XRAY_SNI="${XRAY_SNI:-$(ask "SNI для VLESS Reality" "${EXIST_XRAY_SNI:-github.com}")}"
XRAY_SNI="$(normalize_host "$XRAY_SNI")"
XRAY_SNI="${XRAY_SNI#www.}"
valid_domain "$XRAY_SNI" || { print_error "Неверный XRAY_SNI: $XRAY_SNI"; exit 1; }

TELEMT_TLS_DOMAIN="${TELEMT_TLS_DOMAIN:-$(ask "TLS-домен для Telemt" "${EXIST_TELEMT_TLS_DOMAIN:-www.google.com}")}"
TELEMT_TLS_DOMAIN="$(normalize_host "$TELEMT_TLS_DOMAIN")"
valid_domain "$TELEMT_TLS_DOMAIN" || { print_error "Неверный TELEMT_TLS_DOMAIN"; exit 1; }

HY2_DOMAIN="${HY2_DOMAIN:-$(ask "Домен Hysteria2 (TLS + masquerade)" "${EXIST_HY2_DOMAIN:-}")}"
HY2_DOMAIN="$(normalize_host "$HY2_DOMAIN")"
[[ -z "$HY2_DOMAIN" ]] && { print_error "Домен Hysteria2 обязателен"; exit 1; }
valid_domain "$HY2_DOMAIN" || { print_error "Неверный HY2_DOMAIN"; exit 1; }

HY2_EMAIL="${HY2_EMAIL:-$(ask "Email для Let's Encrypt" "${EXIST_HY2_EMAIL:-}")}"
[[ -z "$HY2_EMAIL" ]] && { print_error "Email обязателен"; exit 1; }
valid_email "$HY2_EMAIL" || { print_error "Неверный email: $HY2_EMAIL"; exit 1; }

# Имя первого пользователя — только при свежей установке/реинсталле.
if $EXISTING_INSTALL && ! $REINSTALL; then
  FIRST_USER="$(jq -r '.users[0].name // empty' "$USERS_DB" 2>/dev/null)"
  if [[ -z "$FIRST_USER" ]]; then
    FIRST_USER="${FIRST_USER:-$(ask "Имя первого пользователя" "main")}"
  fi
else
  FIRST_USER="${FIRST_USER:-$(ask "Имя первого пользователя" "main")}"
fi
if ! [[ "$FIRST_USER" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
  print_error "Имя пользователя: A-Za-z0-9._- (1..32 символа)"
  exit 1
fi

# Внешний IP.
SERVER_IP="$(detect_server_ip)"
if [[ -z "$SERVER_IP" ]]; then
  print_error "Не удалось определить внешний IP сервера"
  exit 1
fi

PUBLIC_HOST="${PUBLIC_HOST:-$(ask "Публичный хост для ссылок" "${EXIST_PUBLIC_HOST:-$SERVER_IP}")}"
PUBLIC_HOST="$(normalize_host "$PUBLIC_HOST")"
[[ -z "$PUBLIC_HOST" ]] && PUBLIC_HOST="$SERVER_IP"

# ─── Проверки целостности ввода ──────────────────────────────────────────────
if [[ "$XRAY_SNI" == "$TELEMT_TLS_DOMAIN" ]]; then
  print_error "SNI Xray и Telemt должны быть разными"; exit 1
fi
if [[ "$HY2_DOMAIN" == "$XRAY_SNI" || "$HY2_DOMAIN" == "$TELEMT_TLS_DOMAIN" ]]; then
  print_error "Домен Hysteria2 не должен совпадать с Xray/Telemt SNI"; exit 1
fi

# ─── Предпросмотр + подтверждение ────────────────────────────────────────────
echo ""
print_info "Конфигурация:"
echo "  HAProxy:     0.0.0.0:${HAPROXY_PORT}/tcp"
echo "  Xray:        127.0.0.1:${XRAY_PORT}/tcp (loopback)"
echo "  Telemt:      127.0.0.1:${TELEMT_PORT}/tcp (loopback)"
echo "  Xray SNI:    ${XRAY_SNI} (+ www.${XRAY_SNI})"
echo "  Telemt SNI:  ${TELEMT_TLS_DOMAIN}"
echo "  Hysteria2:   ${HY2_DOMAIN}:443/udp + masquerade :8444/tcp"
echo "  Public host: ${PUBLIC_HOST}"
echo "  First user:  ${FIRST_USER}"
echo "  Mode:        $($EXISTING_INSTALL && ! $REINSTALL && echo upgrade || echo fresh-install)"
echo ""

if ! $NONINTERACTIVE; then
  read -rp "Продолжить установку? (y/n): " CONFIRM
  if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    print_warning "Установка отменена"
    exit 0
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# СИСТЕМНЫЕ ПАКЕТЫ
# ─────────────────────────────────────────────────────────────────────────────
print_info "Обновление apt и установка зависимостей..."
retry 3 5 apt-get update -y
retry 3 5 apt-get install -y --no-install-recommends \
  curl wget jq tar openssl ca-certificates \
  qrencode haproxy certbot ufw util-linux iproute2 dnsutils
print_status "Пакеты установлены"

# ─────────────────────────────────────────────────────────────────────────────
# SYSCTL: BBR + UDP/QUIC буферы + TCP-тюнинг
# ─────────────────────────────────────────────────────────────────────────────
print_info "Настройка sysctl (BBR, буферы, somaxconn, file-max)..."
modprobe tcp_bbr 2>/dev/null || true
cat > /etc/sysctl.d/99-proxy-stack.conf <<'EOF'
# proxy-stack tuning
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.rmem_default=262144
net.core.wmem_default=262144
net.core.netdev_max_backlog=4096
net.core.somaxconn=4096
net.ipv4.udp_rmem_min=8192
net.ipv4.udp_wmem_min=8192
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_notsent_lowat=131072
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.tcp_tw_reuse=1
fs.file-max=1048576
EOF
sysctl --system >/dev/null
# Sanity-check BBR
if ! sysctl -n net.ipv4.tcp_congestion_control | grep -q bbr; then
  print_warning "BBR не активен после применения sysctl — продолжаем, но сетевая производительность может быть ниже."
else
  print_status "BBR активен"
fi

# ─────────────────────────────────────────────────────────────────────────────
# ДИРЕКТОРИИ
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p /usr/local/etc/xray /usr/local/etc/proxy /etc/telemt /etc/hysteria \
         /etc/hysteria/certs /opt/telemt /var/www/masq /usr/local/lib /var/lock
chmod 755 /usr/local /usr/local/etc 2>/dev/null || true

# Xray и Hysteria должны быть доступны своим сервисным пользователям
chmod 750 /usr/local/etc/xray /etc/hysteria
chmod 700 /usr/local/etc/proxy /etc/telemt
chmod 755 /etc/hysteria/certs

backup_file "$KEYS" 5
backup_file "$USERS_DB" 5

# ─────────────────────────────────────────────────────────────────────────────
# ОБЩАЯ БИБЛИОТЕКА /usr/local/lib/proxy-common.sh
#
# Используется и инсталлером, и CLI-командами (newuser, rmuser и т.п.).
# ─────────────────────────────────────────────────────────────────────────────
cat > /usr/local/lib/proxy-common.sh <<'COMMON_EOF'
#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C LANG=C

KEYS="/usr/local/etc/xray/.keys"
USERS_DB="/usr/local/etc/proxy/users.json"
LOCK_FILE="/var/lock/proxy-users.lock"
XRAY_CFG="/usr/local/etc/xray/config.json"
TEL_CFG="/etc/telemt/telemt.toml"
HY2_CFG="/etc/hysteria/config.yaml"

# ─── Цвета (TTY) ─────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi
print_status()  { echo -e "${GREEN}[✓]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1" >&2; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info()    { echo -e "${BLUE}[i]${NC} $1"; }

# ─── kv: чтение значения из .keys ────────────────────────────────────────────
kv() {
  awk -F': ' -v k="$1" '$1==k {print $2; exit}' "$KEYS" 2>/dev/null
}

# ─── Генераторы ──────────────────────────────────────────────────────────────
gen_alnum_pass() {
  local p
  while :; do
    p="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)"
    if [[ ${#p} -eq 16 ]]; then
      printf '%s' "$p"; return 0
    fi
  done
}
gen_hex_secret() { openssl rand -hex 16; }

# ─── Сетевые параметры ──────────────────────────────────────────────────────
server_ip() {
  local ip=""
  for u in https://icanhazip.com https://ifconfig.me https://api.ipify.org; do
    ip="$(curl -4 -fsS --connect-timeout 5 --max-time 10 "$u" 2>/dev/null || true)"
    ip="${ip//$'\n'/}"; ip="${ip//[[:space:]]/}"
    [[ -n "$ip" ]] && { printf '%s' "$ip"; return 0; }
  done
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  printf '%s' "${ip:-}"
}
public_host() { local h; h="$(kv public_host)"; [[ -z "$h" ]] && h="$(server_ip)"; printf '%s' "$h"; }
public_port() { local p; p="$(kv haproxy_port)"; [[ -z "$p" ]] && p=443; printf '%s' "$p"; }
hy2_domain()  { kv hy2_domain; }

# ─── База пользователей под flock ────────────────────────────────────────────
db_user_count()  { jq '.users | length' "$USERS_DB" 2>/dev/null || echo 0; }
db_first_user()  { jq -r '.users[0].name // empty' "$USERS_DB" 2>/dev/null; }
db_user_names()  { jq -r '.users[].name' "$USERS_DB" 2>/dev/null; }
db_has_user()    { jq -e --arg n "$1" '.users[]? | select(.name==$n)' "$USERS_DB" >/dev/null 2>&1; }
db_get_user_field() {
  jq -r --arg n "$1" --arg f "$2" '.users[] | select(.name==$n) | .[$f] // empty' "$USERS_DB" 2>/dev/null | head -n1
}
_with_users_lock() {
  local fd
  exec {fd}>"$LOCK_FILE"
  flock -x "$fd"
  "$@"
  local rc=$?
  exec {fd}>&-
  return $rc
}
db_add_user() {
  local name="$1" uuid="$2" hy2pass="$3" telsecret="$4"
  _with_users_lock _db_add_user_locked "$name" "$uuid" "$hy2pass" "$telsecret"
}
_db_add_user_locked() {
  local name="$1" uuid="$2" hy2pass="$3" telsecret="$4" tmp
  tmp="$(mktemp)"
  jq --arg name "$name" --arg uuid "$uuid" \
     --arg hy2pass "$hy2pass" --arg telsecret "$telsecret" \
     '.users += [{"name":$name,"uuid":$uuid,"hy2pass":$hy2pass,"telsecret":$telsecret}]' \
     "$USERS_DB" > "$tmp"
  mv "$tmp" "$USERS_DB"
  chmod 600 "$USERS_DB"
}
db_remove_user() {
  _with_users_lock _db_remove_user_locked "$@"
}
_db_remove_user_locked() {
  local name="$1" tmp
  tmp="$(mktemp)"
  jq --arg name "$name" '.users |= map(select(.name != $name))' "$USERS_DB" > "$tmp"
  mv "$tmp" "$USERS_DB"
  chmod 600 "$USERS_DB"
}

require_first_user() {
  local u; u="$(db_first_user)"
  [[ -z "$u" ]] && { print_error "Нет пользователей"; exit 1; }
  printf '%s' "$u"
}
db_print_users_indexed() {
  mapfile -t USERS_ARR < <(db_user_names)
  if [[ ${#USERS_ARR[@]} -eq 0 ]]; then
    print_error "${1:-Список пользователей пуст}"
    exit 1
  fi
  echo "Пользователи:"
  local i
  for i in "${!USERS_ARR[@]}"; do
    echo "$((i+1)). ${USERS_ARR[$i]}"
  done
}
db_pick_user() {
  local prompt="${1:-Выберите пользователя}" choice
  read -rp "${prompt}: " choice
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#USERS_ARR[@]} )); then
    print_error "Номер от 1 до ${#USERS_ARR[@]}"; exit 1
  fi
  printf '%s' "${USERS_ARR[$((choice-1))]}"
}

# ─── Формирование ссылок ─────────────────────────────────────────────────────
tg_full_secret_for() {
  local user="$1" raw domain_hex
  raw="$(db_get_user_field "$user" telsecret)"
  domain_hex="$(printf '%s' "$(kv telemt_tls_domain)" | od -An -tx1 | tr -d ' \n')"
  printf 'ee%s%s' "$raw" "$domain_hex"
}
xray_link_for() {
  local user="$1" uuid pbk sid sni port
  uuid="$(db_get_user_field "$user" uuid)"
  pbk="$(kv xray_public_key)"; sid="$(kv xray_short_id)"; sni="$(kv xray_sni)"
  port="$(public_port)"
  printf 'vless://%s@%s:%s?type=xhttp&security=reality&encryption=none&host=%s&path=%%2F&mode=auto&sni=%s&fp=firefox&pbk=%s&sid=%s&spx=%%2F#%s\n' \
    "$uuid" "$(public_host)" "$port" "$sni" "$sni" "$pbk" "$sid" "$user"
}
hy2_link_for() {
  local user="$1" pass domain
  pass="$(db_get_user_field "$user" hy2pass)"; domain="$(hy2_domain)"
  printf 'hy2://%s:%s@%s:443?sni=%s&alpn=h3&insecure=0&allowInsecure=0#%s\n' \
    "$user" "$pass" "$domain" "$domain" "$user"
}
tg_https_link_for() {
  local user="$1" full; full="$(tg_full_secret_for "$user")"
  printf 'https://t.me/proxy?server=%s&port=%s&secret=%s\n' "$(public_host)" "$(public_port)" "$full"
}
tg_scheme_link_for() {
  local user="$1" full; full="$(tg_full_secret_for "$user")"
  printf 'tg://proxy?server=%s&port=%s&secret=%s\n' "$(public_host)" "$(public_port)" "$full"
}
show_qr() {
  if [[ -t 1 ]]; then
    printf '%s\n' "$1" | qrencode -t ansiutf8
  fi
}

# ─── Рендер конфигов ────────────────────────────────────────────────────────
render_xray_config() {
  local clients_json port sni pkey sid
  clients_json="$(jq -c '[.users[] | {email:.name,id:.uuid,flow:""}]' "$USERS_DB")"
  port="$(kv xray_port)"; sni="$(kv xray_sni)"
  pkey="$(kv xray_private_key)"; sid="$(kv xray_short_id)"
  cat > "$XRAY_CFG" <<EOF2
{
  "log": {"loglevel": "warning"},
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
      {"type": "field", "ip": ["geoip:cn"], "outboundTag": "block"}
    ]
  },
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": ${port},
    "protocol": "vless",
    "settings": {
      "clients": ${clients_json},
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "xhttpSettings": {"path": "/"},
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
    "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
  }],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {"protocol": "blackhole", "tag": "block"}
  ],
  "policy": {
    "levels": {
      "0": {"handshake": 3, "connIdle": 180, "uplinkOnly": 2, "downlinkOnly": 5, "bufferSize": 4}
    }
  }
}
EOF2
  chown xray:xray "$XRAY_CFG"
  chmod 640 "$XRAY_CFG"
}

render_telemt_config() {
  local pub_host hap_port tel_port tls_domain
  pub_host="$(kv public_host)"; hap_port="$(kv haproxy_port)"
  tel_port="$(kv telemt_port)"; tls_domain="$(kv telemt_tls_domain)"
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
    echo "max_connections = 65536"
    echo
    echo "[[server.listeners]]"
    echo "ip = \"127.0.0.1\""
    echo
    echo "[server.api]"
    echo "enabled = true"
    echo "listen = \"127.0.0.1:7443\""
    echo "whitelist = [\"127.0.0.1/32\", \"::1/128\"]"
    echo
    echo "[censorship]"
    echo "tls_domain = \"${tls_domain}\""
    echo "mask = true"
    echo "tls_emulation = true"
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
    echo "congestion:"
    echo "  type: bbr"
    echo "  bbrProfile: standard"
    echo
    echo "quic:"
    echo "  initStreamReceiveWindow: 8388608"
    echo "  maxStreamReceiveWindow: 8388608"
    echo "  initConnReceiveWindow: 20971520"
    echo "  maxConnReceiveWindow: 20971520"
    echo "  maxIdleTimeout: 30s"
    echo "  maxIncomingStreams: 1024"
    echo "  disablePathMTUDiscovery: false"
    echo
    echo "udpIdleTimeout: 60s"
    echo "ignoreClientBandwidth: false"
    echo "disableUDP: false"
    echo
    echo "sniff:"
    echo "  enable: true"
    echo "  timeout: 2s"
    echo "  rewriteDomain: false"
    echo "  tcpPorts: 80,443"
    echo "  udpPorts: all"
    echo
    echo "masquerade:"
    echo "  type: file"
    echo "  listenHTTPS: :8444"
    echo "  forceHTTPS: true"
    echo "  file:"
    echo "    dir: /var/www/masq"
  } > "$HY2_CFG"
  chown root:hysteria "$HY2_CFG" 2>/dev/null || chown root:root "$HY2_CFG"
  chmod 640 "$HY2_CFG"
}

render_all_configs() {
  render_xray_config
  render_telemt_config
  render_hy2_config
}

restart_dynamic_services() {
  systemctl restart xray
  systemctl restart telemt
  systemctl restart hysteria-server.service
}

print_bundle() {
  local user="$1" xlink hlink tlink tglink
  xlink="$(xray_link_for "$user")"
  hlink="$(hy2_link_for "$user")"
  tlink="$(tg_https_link_for "$user")"
  tglink="$(tg_scheme_link_for "$user")"

  echo "=== VLESS xhttp + Reality ==="
  echo "$xlink"; echo
  show_qr "$xlink"; echo

  echo "=== Hysteria2 ==="
  echo "$hlink"; echo
  show_qr "$hlink"; echo

  echo "=== Telegram MTProto Proxy ==="
  echo "HTTPS: $tlink"
  echo "TG:    $tglink"; echo
  show_qr "$tlink"
}
COMMON_EOF
chmod 755 /usr/local/lib/proxy-common.sh

# Подключаем библиотеку для использования в текущем процессе.
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

# ─────────────────────────────────────────────────────────────────────────────
# XRAY (с переиспользованием ключей при upgrade)
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка/обновление Xray..."
if ! command -v xray >/dev/null 2>&1; then
  retry 3 5 bash -c "$(curl -4 -fsSL --connect-timeout 10 --max-time 120 https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" \
    @ install >/var/log/xray-install.log 2>&1
fi

# Пользователь для Xray
if ! id xray &>/dev/null; then
  useradd -r -U -d /usr/local/etc/xray -s /usr/sbin/nologin xray
fi
chown -R xray:xray /usr/local/etc/xray
chmod 750 /usr/local/etc/xray

# Ключи Reality.
if $EXISTING_INSTALL && ! $REINSTALL && [[ -n "$(kv xray_private_key)" && -n "$(kv xray_public_key)" && -n "$(kv xray_short_id)" ]]; then
  PRIVATE_KEY="$(kv xray_private_key)"
  PUBLIC_KEY="$(kv xray_public_key)"
  SHORT_ID="$(kv xray_short_id)"
  print_status "Reality keys: переиспользую существующие"
else
  X25519_OUT="$(xray x25519 2>&1 | tr -d '\r')"
  PRIVATE_KEY="$(awk -F': ' '
    /^Private[[:space:]]*Key:/ {print $2; exit}
    /^PrivateKey:/             {print $2; exit}' <<< "$X25519_OUT")"
  PUBLIC_KEY="$(awk -F': ' '
    /^Public[[:space:]]*Key:/         {print $2; exit}
    /^PublicKey:/                     {print $2; exit}
    /^Password \(PublicKey\):/        {print $2; exit}' <<< "$X25519_OUT")"
  if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
    print_error "Не удалось получить ключи x25519 из xray. Сырой вывод:"
    echo "$X25519_OUT"
    exit 1
  fi
  SHORT_ID="$(openssl rand -hex 8)"
  print_status "Reality keys: сгенерированы новые"
fi

# UUID + учётка первого пользователя — только если БД пуста или --reinstall.
if $REINSTALL || [[ ! -s "$USERS_DB" ]] || [[ "$(jq -r '.users | length' "$USERS_DB" 2>/dev/null || echo 0)" -eq 0 ]]; then
  UUID="$(xray uuid)"
  MAIN_HY2_PASS="$(gen_alnum_pass)"
  MAIN_TEL_SECRET="$(gen_hex_secret)"
  jq -n --arg name "$FIRST_USER" --arg uuid "$UUID" \
        --arg hy2pass "$MAIN_HY2_PASS" --arg telsecret "$MAIN_TEL_SECRET" \
        '{users: [{name:$name, uuid:$uuid, hy2pass:$hy2pass, telsecret:$telsecret}]}' \
        > "$USERS_DB"
  chmod 600 "$USERS_DB"
  print_status "users.json инициализирован первым пользователем '$FIRST_USER'"
else
  UUID="$(jq -r --arg n "$FIRST_USER" '.users[] | select(.name==$n) | .uuid' "$USERS_DB")"
  if [[ -z "$UUID" ]]; then
    UUID="$(jq -r '.users[0].uuid' "$USERS_DB")"
  fi
  print_status "users.json: переиспользую существующую базу ($(jq '.users | length' "$USERS_DB") польз.)"
fi

# Сохраняем все параметры в .keys атомарно (один файл целиком).
{
  echo "public_host: $PUBLIC_HOST"
  echo "server_ip: $SERVER_IP"
  echo "haproxy_port: $HAPROXY_PORT"
  echo "xray_port: $XRAY_PORT"
  echo "telemt_port: $TELEMT_PORT"
  echo "xray_sni: $XRAY_SNI"
  echo "telemt_tls_domain: $TELEMT_TLS_DOMAIN"
  echo "hy2_domain: $HY2_DOMAIN"
  echo "hy2_email: $HY2_EMAIL"
  echo "hy2_cert_name: ${HY2_DOMAIN}"
  echo "hysteria_service: hysteria-server.service"
  echo "xray_uuid: $UUID"
  echo "xray_private_key: $PRIVATE_KEY"
  echo "xray_public_key: $PUBLIC_KEY"
  echo "xray_short_id: $SHORT_ID"
} > "$KEYS"
chmod 600 "$KEYS"

render_xray_config

# ─── Hardening unit-файла Xray (мягкое) ─────────────────────────────────────
mkdir -p /etc/systemd/system/xray.service.d
cat > /etc/systemd/system/xray.service.d/override.conf <<'EOF'
[Service]
User=xray
Group=xray
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ReadWritePaths=/usr/local/etc/xray /var/log/xray
EOF
mkdir -p /var/log/xray
systemctl daemon-reload
systemctl enable --now xray
systemctl restart xray
wait_for_active xray 15 || { print_error "xray не стартанул"; journalctl -u xray -n 50 --no-pager >&2 || true; exit 1; }
print_status "Xray работает"

# ─────────────────────────────────────────────────────────────────────────────
# TELEMT (MTProto proxy)
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка/обновление Telemt..."

ARCH="$(uname -m)"
if ldd --version 2>&1 | grep -iq musl; then LIBC="musl"; else LIBC="gnu"; fi
TELEMT_URL="https://github.com/telemt/telemt/releases/latest/download/telemt-${ARCH}-linux-${LIBC}.tar.gz"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

print_info "Скачивание: telemt-${ARCH}-linux-${LIBC}.tar.gz"
retry 3 5 curl -fsSL --connect-timeout 10 --max-time 180 -o "$TMPDIR/telemt.tar.gz" "$TELEMT_URL"
tar -xzf "$TMPDIR/telemt.tar.gz" -C "$TMPDIR"
install -m 755 "$TMPDIR/telemt" /bin/telemt

if ! id telemt &>/dev/null; then
  useradd -r -U -s /usr/sbin/nologin -d /opt/telemt telemt
  print_status "Пользователь telemt создан"
fi
mkdir -p /etc/telemt /opt/telemt
chown -R telemt:telemt /opt/telemt /etc/telemt

cat > /etc/systemd/system/telemt.service <<'EOF'
[Unit]
Description=Telemt MTProto Proxy
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=5

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
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ReadWritePaths=/etc/telemt /opt/telemt /var/log

[Install]
WantedBy=multi-user.target
EOF

render_telemt_config
systemctl daemon-reload
systemctl enable --now telemt
systemctl restart telemt
wait_for_active telemt 15 || { print_error "telemt не стартанул"; journalctl -u telemt -n 50 --no-pager >&2 || true; exit 1; }
print_status "Telemt работает"

# ─────────────────────────────────────────────────────────────────────────────
# HYSTERIA2
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка/обновление Hysteria2..."
mkdir -p /var/www/masq /etc/hysteria/certs

# Страница-заглушка (только если нет).
if [[ ! -s /var/www/masq/index.html ]]; then
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
  <div class="dots"><div class="d"></div><div class="d"></div><div class="d"></div></div>
  <div class="t">RETRYING CONNECTION</div>
</body>
</html>
HTML
fi
chmod 644 /var/www/masq/index.html

# Hysteria2 user (используем!)
if ! id hysteria &>/dev/null; then
  useradd -r -U -d /etc/hysteria -s /usr/sbin/nologin hysteria
  print_status "Пользователь hysteria создан"
fi

chown root:hysteria /etc/hysteria
chmod 750 /etc/hysteria

# DNS-проверка — мягкое предупреждение, не блокируем.
RESOLVED_IP="$(getent hosts "$HY2_DOMAIN" 2>/dev/null | awk '{print $1; exit}' || true)"
if [[ -n "$RESOLVED_IP" && "$RESOLVED_IP" != "$SERVER_IP" ]]; then
  print_warning "DNS '$HY2_DOMAIN' указывает на $RESOLVED_IP, а не на $SERVER_IP. certbot скорее всего упадёт."
  if ! $NONINTERACTIVE; then
    read -rp "Продолжить всё равно? (y/n): " ans
    [[ "$ans" =~ ^[yY]$ ]] || exit 1
  fi
fi

# Получение/использование сертификата.
CERT_NAME="$HY2_DOMAIN"
if [[ -s "/etc/letsencrypt/live/$HY2_DOMAIN/fullchain.pem" && -s "/etc/letsencrypt/live/$HY2_DOMAIN/privkey.pem" ]]; then
  print_status "Сертификат: используется существующий $HY2_DOMAIN"
else
  EXISTING_NAME="$(find_cert_name_for_domain "$HY2_DOMAIN" || true)"
  if [[ -n "$EXISTING_NAME" && -s "/etc/letsencrypt/live/$EXISTING_NAME/fullchain.pem" ]]; then
    CERT_NAME="$EXISTING_NAME"
    print_status "Сертификат: используется существующий $CERT_NAME"
  else
    if ss -ltn 2>/dev/null | awk '$4 ~ /:80$/ {found=1} END {exit !found}'; then
      print_error "Порт 80 занят. Освободи 80/tcp для первого выпуска сертификата."
      exit 1
    fi
    print_info "Запрос сертификата Let's Encrypt..."
    retry 3 10 certbot certonly --standalone \
      --cert-name "$HY2_DOMAIN" \
      --keep-until-expiring \
      -d "$HY2_DOMAIN" \
      -m "$HY2_EMAIL" \
      --agree-tos --non-interactive
    CERT_NAME="$HY2_DOMAIN"
  fi
fi
update_keys_field "$KEYS" hy2_cert_name "$CERT_NAME"

# Дать группе hysteria доступ к live/archive.
chgrp -R hysteria /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
chmod g+rx /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
find /etc/letsencrypt/live /etc/letsencrypt/archive -type d -exec chmod g+rx {} + 2>/dev/null || true
find /etc/letsencrypt/archive -type f -name 'privkey*.pem' -exec chmod g+r {} + 2>/dev/null || true

# Установка hysteria.
if ! command -v hysteria >/dev/null 2>&1; then
  retry 3 5 bash -c "$(curl -fsSL --connect-timeout 10 --max-time 120 https://get.hy2.sh/)" >/var/log/hy2-install.log 2>&1
fi
HYST_BIN="$(command -v hysteria || echo /usr/local/bin/hysteria)"
[[ -x "$HYST_BIN" ]] || { print_error "hysteria бинарь не найден"; exit 1; }

render_hy2_config

# systemd unit для Hysteria2 (запускаем от hysteria, не root).
cat > /etc/systemd/system/hysteria-server.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=5

[Service]
Type=simple
User=hysteria
Group=hysteria
WorkingDirectory=/
ExecStart=${HYST_BIN} server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
ReadWritePaths=/etc/hysteria /var/www/masq

[Install]
WantedBy=multi-user.target
EOF

# Renewal-хук: рестартуем hysteria + чиним группу-доступ к новым ключам.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/99-hysteria-restart.sh <<'EOF'
#!/bin/sh
chgrp -R hysteria /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
chmod g+rx /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
find /etc/letsencrypt/live /etc/letsencrypt/archive -type d -exec chmod g+rx {} + 2>/dev/null || true
find /etc/letsencrypt/archive -type f -name 'privkey*.pem' -exec chmod g+r {} + 2>/dev/null || true
systemctl restart hysteria-server.service 2>/dev/null || true
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/99-hysteria-restart.sh

systemctl daemon-reload
systemctl enable --now hysteria-server.service
systemctl restart hysteria-server.service
wait_for_active hysteria-server.service 15 || {
  print_error "hysteria не стартанул";
  journalctl -u hysteria-server.service -n 80 --no-pager >&2 || true
  exit 1
}
systemctl enable --now certbot.timer >/dev/null 2>&1 || true
print_status "Hysteria2 работает"

# ─────────────────────────────────────────────────────────────────────────────
# HAPROXY (SNI router, TCP)
# ─────────────────────────────────────────────────────────────────────────────
print_info "Настройка HAProxy..."
backup_file /etc/haproxy/haproxy.cfg 5

CPU_COUNT="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

cat > /etc/haproxy/haproxy.cfg <<EOF
global
    log /dev/log local0
    maxconn 65536
    user haproxy
    group haproxy
    nbthread ${CPU_COUNT}
    tune.bufsize 32768
    tune.maxrewrite 8192
    daemon

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    option  tcp-smart-accept
    option  tcp-smart-connect
    option  splice-auto
    timeout connect  10s
    timeout client   1h
    timeout server   1h
    timeout tunnel   1h
    retries 3

frontend front_main
    bind *:${HAPROXY_PORT}
    mode tcp

    # Ждём ClientHello и принимаем только TLS-трафик.
    tcp-request inspect-delay 5s
    tcp-request content reject if !{ req_ssl_hello_type 1 }
    tcp-request content accept if { req_ssl_hello_type 1 }

    # SNI-роутинг (case-insensitive).
    acl is_hy2site req.ssl_sni -i ${HY2_DOMAIN}
    acl is_telemt  req.ssl_sni -i ${TELEMT_TLS_DOMAIN}
    acl is_xray    req.ssl_sni -i ${XRAY_SNI} www.${XRAY_SNI}

    use_backend bk_hy2site if is_hy2site
    use_backend bk_telemt  if is_telemt
    use_backend bk_xray    if is_xray

    # Неизвестный SNI → нейтральная HTTPS-заглушка.
    default_backend bk_hy2site

backend bk_hy2site
    mode tcp
    option splice-auto
    server hy2site 127.0.0.1:8444 check inter 30s

backend bk_telemt
    mode tcp
    option splice-auto
    server telemt 127.0.0.1:${TELEMT_PORT} check inter 30s

backend bk_xray
    mode tcp
    option splice-auto
    server xray 127.0.0.1:${XRAY_PORT} check inter 30s
EOF

if ! haproxy -c -f /etc/haproxy/haproxy.cfg >/dev/null 2>&1; then
  print_error "haproxy.cfg синтаксически невалиден — откатываю"
  LAST_BAK="$(ls -1t /etc/haproxy/haproxy.cfg.bak.* 2>/dev/null | head -n1 || true)"
  if [[ -n "$LAST_BAK" ]]; then
    cp -p "$LAST_BAK" /etc/haproxy/haproxy.cfg
    print_warning "Откат к $LAST_BAK"
  fi
  exit 1
fi

systemctl enable --now haproxy
systemctl restart haproxy
if ! wait_for_active haproxy 10; then
  print_error "haproxy не стартанул — откатываю на бэкап"
  LAST_BAK="$(ls -1t /etc/haproxy/haproxy.cfg.bak.* 2>/dev/null | head -n1 || true)"
  if [[ -n "$LAST_BAK" ]]; then
    cp -p "$LAST_BAK" /etc/haproxy/haproxy.cfg
    systemctl restart haproxy || true
  fi
  journalctl -u haproxy -n 80 --no-pager >&2 || true
  exit 1
fi
print_status "HAProxy работает (nbthread=${CPU_COUNT})"

# ─────────────────────────────────────────────────────────────────────────────
# UFW
# ─────────────────────────────────────────────────────────────────────────────
print_info "Настройка UFW..."
ufw allow 22/tcp comment "SSH"
ufw allow 80/tcp comment "ACME (certbot renew)"
ufw allow "${HAPROXY_PORT}/tcp" comment "HAProxy SNI router"
ufw allow 443/udp comment "Hysteria2 QUIC"
ufw --force enable >/dev/null
print_status "UFW настроен"

# ─────────────────────────────────────────────────────────────────────────────
# CLI-команды
# ─────────────────────────────────────────────────────────────────────────────

# mainuser
cat > /usr/local/bin/mainuser <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh
print_bundle "$(require_first_user)"
EOF
chmod 755 /usr/local/bin/mainuser

# userlist
cat > /usr/local/bin/userlist <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh
db_print_users_indexed
EOF
chmod 755 /usr/local/bin/userlist

# newuser
cat > /usr/local/bin/newuser <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

read -rp "Введите имя пользователя: " NAME
if ! [[ "$NAME" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
  print_error "Имя должно соответствовать ^[A-Za-z0-9._-]{1,32}\$"
  exit 1
fi
if db_has_user "$NAME"; then
  print_error "Пользователь '$NAME' уже существует"
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
chmod 755 /usr/local/bin/newuser

# rmuser (с подтверждением)
cat > /usr/local/bin/rmuser <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

db_print_users_indexed "Нет пользователей для удаления."

if [[ ${#USERS_ARR[@]} -le 1 ]]; then
  print_error "Нельзя удалить последнего пользователя."
  exit 1
fi

SEL="$(db_pick_user "Номер для удаления")"
read -rp "Удалить '$SEL'? (y/N): " conf
[[ "$conf" =~ ^[yY]$ ]] || { echo "Отменено."; exit 0; }

db_remove_user "$SEL"
render_all_configs
restart_dynamic_services

echo "Пользователь '$SEL' удалён."
EOF
chmod 755 /usr/local/bin/rmuser

# sharelink
cat > /usr/local/bin/sharelink <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

db_print_users_indexed "Нет пользователей."
SEL="$(db_pick_user "Выберите пользователя")"
print_bundle "$SEL"
EOF
chmod 755 /usr/local/bin/sharelink

# hy2info
cat > /usr/local/bin/hy2info <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

user="$(require_first_user)"
LINK="$(hy2_link_for "$user")"
echo
echo "=== Hysteria2 ==="
echo "$LINK"
echo
show_qr "$LINK"
EOF
chmod 755 /usr/local/bin/hy2info

# hy2list
cat > /usr/local/bin/hy2list <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)
[[ ${#users[@]} -eq 0 ]] && { echo "Пользователей нет"; exit 1; }
echo "Пользователи Hysteria2:"
for i in "${!users[@]}"; do
  echo "$((i+1)). ${users[$i]}"
done
EOF
chmod 755 /usr/local/bin/hy2list

# hy2links
cat > /usr/local/bin/hy2links <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)
[[ ${#users[@]} -eq 0 ]] && { echo "Пользователей нет"; exit 1; }
echo "Ссылки Hysteria2:"
for u in "${users[@]}"; do
  echo "$u -> $(hy2_link_for "$u")"
done
EOF
chmod 755 /usr/local/bin/hy2links

# tglink
cat > /usr/local/bin/tglink <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

user="$(require_first_user)"
HTTPS_LINK="$(tg_https_link_for "$user")"
TG_LINK="$(tg_scheme_link_for "$user")"
echo
echo "=== Telegram MTProto Proxy ==="
echo "HTTPS: $HTTPS_LINK"
echo "TG:    $TG_LINK"
echo
show_qr "$HTTPS_LINK"
EOF
chmod 755 /usr/local/bin/tglink

# telegramlinks
cat > /usr/local/bin/telegramlinks <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)
[[ ${#users[@]} -eq 0 ]] && { echo "Пользователей нет"; exit 1; }
echo "=== Telemt MTProto Proxy ==="
for u in "${users[@]}"; do
  echo "$u -> $(tg_https_link_for "$u")"
done
EOF
chmod 755 /usr/local/bin/telegramlinks

# proxystatus
cat > /usr/local/bin/proxystatus <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

HAPROXY_PORT="$(kv haproxy_port)"; XRAY_PORT="$(kv xray_port)"; TELEMT_PORT="$(kv telemt_port)"
[[ -z "$HAPROXY_PORT" ]] && HAPROXY_PORT=443
[[ -z "$XRAY_PORT" ]]    && XRAY_PORT=8443
[[ -z "$TELEMT_PORT" ]]  && TELEMT_PORT=9443

echo
echo "=== Сервисы ==="
for svc in haproxy xray telemt hysteria-server.service; do
  printf "%-26s : " "$svc"
  if systemctl is-active --quiet "$svc"; then
    printf "${GREEN}работает${NC}\n"
  else
    printf "${RED}не работает${NC}\n"
  fi
done

echo
echo "=== TCP-порты ==="
ss -tlnp 2>/dev/null | grep -E "(:${HAPROXY_PORT}|:${XRAY_PORT}|:${TELEMT_PORT}|:80|:443|:8444|:7443)" || true
echo
echo "=== UDP-порты ==="
ss -ulnp 2>/dev/null | grep -E "(:443)" || true
echo
echo "=== Версии ==="
xray version 2>/dev/null | head -n1 || true
telemt --version 2>/dev/null || true
hysteria version 2>/dev/null | head -n1 || true
haproxy -v 2>/dev/null | head -n1 || true
echo
echo "=== Конгест-контроль / qdisc ==="
sysctl -n net.ipv4.tcp_congestion_control net.core.default_qdisc 2>/dev/null
echo
EOF
chmod 755 /usr/local/bin/proxystatus

# proxydiag — расширенная диагностика
cat > /usr/local/bin/proxydiag <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

echo "=== /usr/local/etc/xray/.keys (обезличенный) ==="
sed -E 's/(private_key|public_key|secret|uuid):.*/\1: ***hidden***/' "$KEYS"
echo
echo "=== Чексумы конфигов ==="
for f in "$XRAY_CFG" "$TEL_CFG" "$HY2_CFG" /etc/haproxy/haproxy.cfg; do
  if [[ -f "$f" ]]; then
    sha256sum "$f"
  fi
done
echo
echo "=== Последние логи (по 20 строк) ==="
for svc in haproxy xray telemt hysteria-server.service; do
  echo "--- $svc ---"
  journalctl -u "$svc" -n 20 --no-pager 2>/dev/null || true
  echo
done
echo "=== sysctl (ключевое) ==="
sysctl net.core.rmem_max net.core.wmem_max net.core.somaxconn \
       net.core.default_qdisc net.ipv4.tcp_congestion_control \
       fs.file-max 2>/dev/null
echo
echo "=== UFW ==="
ufw status verbose 2>/dev/null || true
EOF
chmod 755 /usr/local/bin/proxydiag

# proxyrenew — принудительный certbot renew
cat > /usr/local/bin/proxyrenew <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=/usr/local/lib/proxy-common.sh disable=SC1091
source /usr/local/lib/proxy-common.sh

certbot renew --force-renewal
# deploy-hook сам рестартанёт hysteria, но на всякий случай:
systemctl restart hysteria-server.service
print_status "Сертификаты обновлены"
EOF
chmod 755 /usr/local/bin/proxyrenew

# Справка
cat > /root/help <<'EOF'
============================================
  Команды управления (proxy-stack)
============================================

Пользователи:
  newuser     — создать пользователя во всех сервисах
  rmuser      — удалить пользователя (с подтверждением)
  userlist    — список пользователей
  sharelink   — все ссылки выбранного пользователя
  mainuser    — ссылки первого пользователя

Hysteria2:
  hy2info     — Hysteria2 первого пользователя
  hy2list     — список пользователей
  hy2links    — все Hysteria2 ссылки

Telegram / Telemt:
  tglink         — ссылка первого пользователя
  telegramlinks  — все Telegram-ссылки

Эксплуатация:
  proxystatus   — компактный статус сервисов и портов
  proxydiag     — расширенная диагностика (логи, чексумы, sysctl)
  proxyrenew    — принудительное обновление LE-сертификата

============================================
  Конфиги
============================================
  /usr/local/etc/xray/config.json
  /usr/local/etc/xray/.keys
  /usr/local/etc/proxy/users.json
  /etc/hysteria/config.yaml
  /etc/telemt/telemt.toml
  /etc/haproxy/haproxy.cfg
  /etc/sysctl.d/99-proxy-stack.conf

============================================
  Перезапуск
============================================
  systemctl restart haproxy xray telemt hysteria-server.service

============================================
  Установка
============================================
  /path/to/install.sh                # upgrade — сохраняет ключи и пользователей
  /path/to/install.sh --reinstall    # полное пересоздание
  /path/to/install.sh --noninteractive  # из переменных окружения
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
echo "  TCP ${HAPROXY_PORT} -> HAProxy -> {Xray | Telemt | Hysteria2 site}"
echo "  UDP 443 -> Hysteria2"
echo "  Первый пользователь: $(jq -r '.users[0].name' "$USERS_DB")"
echo "============================================"
echo ""

mainuser
echo
print_info "Справка: cat /root/help"
print_info "Проверка: proxystatus"
print_info "Лог установки: $INSTALL_LOG"

trap - EXIT
echo "=== install finished: $(date -u +%FT%TZ) ==="
