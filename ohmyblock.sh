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
# Помогает быстро найти место сбоя без трейса всего стека.
trap 'echo "Ошибка на строке $LINENO" >&2' ERR

# ─── Цветовые коды ANSI для вывода в терминал ────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'   # NC = No Color — сброс цвета

# ─── Вспомогательные функции вывода ──────────────────────────────────────────
print_status()  { echo -e "${GREEN}[✓]${NC} $1"; }   # Успех
print_error()   { echo -e "${RED}[✗]${NC} $1"; }     # Ошибка
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }  # Предупреждение
print_info()    { echo -e "${BLUE}[i]${NC} $1"; }    # Информация

# ─── normalize_host ───────────────────────────────────────────────────────────
# Приводит введённый пользователем хост к единому виду:
#   1. Убирает пробелы (на случай случайного ввода)
#   2. Срезает префиксы http:// и https://
#   3. Срезает завершающий слэш
#   4. Приводит к нижнему регистру
# Пример: "  HTTPS://GitHub.Com/  " → "github.com"
normalize_host() {
  local h="${1:-}"
  h="${h//[[:space:]]/}"          # удалить все пробелы
  h="${h#http://}"                # убрать http://
  h="${h#https://}"               # убрать https://
  h="${h%/}"                      # убрать trailing слэш
  printf '%s' "$h" | tr '[:upper:]' '[:lower:]'   # → нижний регистр
}

# ─── valid_port ───────────────────────────────────────────────────────────────
# Проверяет, что переданная строка — корректный номер порта (1–65535).
# Используется для валидации пользовательского ввода портов.
# Возвращает 0 (true) если порт валиден, иначе 1 (false).
valid_port() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] && (( 1 <= 10#$1 && 10#$1 <= 65535 ))
  # 10#$1 — принудительный перевод в десятичную систему,
  # защита от интерпретации "08" как восьмеричного числа в bash.
}

# ─── get_server_ip ────────────────────────────────────────────────────────────
# Определяет внешний IPv4-адрес сервера тремя способами (fallback-цепочка):
#   1. icanhazip.com   — быстрый, возвращает чистый IP
#   2. ifconfig.me     — резервный внешний сервис
#   3. hostname -I     — локальный способ (работает без интернета,
#                        но может вернуть приватный адрес в NAT-окружении)
# IP нужен для формирования ссылок подключения, если пользователь
# не задал публичный хост вручную.
get_server_ip() {
  local ip=""
  ip="$(curl -4 -fsS https://icanhazip.com 2>/dev/null || true)"
  ip="${ip//$'\n'/}"               # убираем переводы строк из ответа
  if [[ -z "$ip" ]]; then
    ip="$(curl -4 -fsS https://ifconfig.me 2>/dev/null || true)"
    ip="${ip//$'\n'/}"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  printf '%s' "$ip"
}

# ─── gen_alnum_pass ───────────────────────────────────────────────────────────
# Генерирует случайный 16-символьный пароль из алфавитно-цифровых символов
# (A-Za-z0-9). Цикл гарантирует ровно 16 символов: openssl base64 иногда
# выдаёт меньше после tr -dc, поэтому пробуем до успеха.
# Используется для паролей Hysteria2-пользователей.
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

# ─── gen_hex_secret ───────────────────────────────────────────────────────────
# Генерирует 32-символьный hex-секрет (128 бит случайных данных).
# Используется для MTProto-секретов Telemt-пользователей.
gen_hex_secret() {
  openssl rand -hex 16
}

# ─── find_cert_name_for_domain ────────────────────────────────────────────────
# Ищет в базе certbot имя сертификата, который покрывает указанный домен.
# Certbot хранит сертификаты под именами, которые могут отличаться от домена
# (например, если сертификат на несколько доменов).
# Вывод: имя сертификата (Certificate Name) или пустая строка.
# Используется, чтобы переиспользовать уже выпущенный сертификат
# вместо повторного запроса.
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
# EUID — эффективный UID текущего процесса; fallback через id -u
# если EUID по каким-то причинам не задана.
# ─────────────────────────────────────────────────────────────────────────────
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  print_error "Скрипт должен запускаться от root"
  exit 1
fi

# ─── Шапка ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================"
echo "   VLESS + Hysteria2 + Telemt  by.Alexdev   " 
echo "============================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# БЛОК ИНТЕРАКТИВНОГО ВВОДА ПАРАМЕТРОВ
# Все переменные имеют дефолтные значения — пользователь может просто
# нажимать Enter для каждого поля.
# ─────────────────────────────────────────────────────────────────────────────
print_info "Параметры"
echo ""

# Порт HAProxy — точка входа для всего TCP-трафика (TLS SNI роутинг).
# Стандартный 443 позволяет работать без нестандартных портов на клиенте.
read -rp "Порт HAProxy [443]: " HAPROXY_PORT
HAPROXY_PORT=${HAPROXY_PORT:-443}
valid_port "$HAPROXY_PORT" || { print_error "Неверный HAProxy порт"; exit 1; }

# Порт Xray — принимает VLESS xHTTP + Reality от HAProxy.
# Слушает только на localhost, снаружи недоступен.
read -rp "Порт Xray/VLESS [8443]: " XRAY_PORT
XRAY_PORT=${XRAY_PORT:-8443}
valid_port "$XRAY_PORT" || { print_error "Неверный Xray порт"; exit 1; }

# Порт Telemt — принимает MTProto от HAProxy.
# Тоже только localhost.
read -rp "Порт Telemt [9443]: " TELEMT_PORT
TELEMT_PORT=${TELEMT_PORT:-9443}
valid_port "$TELEMT_PORT" || { print_error "Неверный Telemt порт"; exit 1; }

# SNI для VLESS Reality — домен, под который маскируется Xray.
# HAProxy роутит на Xray, когда TLS ClientHello содержит этот SNI.
# Reality имитирует handshake с этим доменом, поэтому трафик
# визуально неотличим от реального TLS-соединения с github.com.
read -rp "SNI для VLESS Reality [github.com]: " XRAY_SNI
XRAY_SNI=${XRAY_SNI:-github.com}
XRAY_SNI="$(normalize_host "$XRAY_SNI")"

# TLS домен для Telemt — MTProto TLS использует этот домен для FakeTLS.
# Должен отличаться от XRAY_SNI, иначе HAProxy не сможет разделить трафик.
read -rp "TLS домен для Telemt [www.google.com]: " TELEMT_TLS_DOMAIN
TELEMT_TLS_DOMAIN=${TELEMT_TLS_DOMAIN:-www.google.com}
TELEMT_TLS_DOMAIN="$(normalize_host "$TELEMT_TLS_DOMAIN")"

# Домен для Hysteria2 — реальный домен, на который выпускается сертификат
# Let's Encrypt. Hysteria2 слушает UDP 443, отдельно от HAProxy (TCP 443).
# Для выпуска сертификата сервер должен быть доступен по этому домену на порту 80.
read -rp "Домен для Hysteria2 (для заглушки и TLS): " HY2_DOMAIN
HY2_DOMAIN="$(normalize_host "$HY2_DOMAIN")"

# Email для Let's Encrypt — используется для уведомлений об истечении сертификата.
read -rp "Email для Let's Encrypt: " HY2_EMAIL

# Имя первого пользователя — создаётся автоматически с UUID, паролем Hy2
# и MTProto-секретом. После установки можно добавлять других через newuser.
read -rp "Первый пользователь [main]: " FIRST_USER
FIRST_USER=${FIRST_USER:-main}

# ─── Определение внешнего IP сервера ─────────────────────────────────────────
SERVER_IP="$(get_server_ip)"
if [[ -z "$SERVER_IP" ]]; then
  print_error "Не удалось определить внешний IP сервера"
  exit 1
fi

# Публичный хост — IP или домен, который будет вставлен в ссылки подключения.
# По умолчанию — определённый выше внешний IP.
# Если сервер за реверс-прокси или CDN — можно указать домен вручную.
read -rp "Публичный хост для ссылок [${SERVER_IP}]: " PUBLIC_HOST
PUBLIC_HOST=${PUBLIC_HOST:-$SERVER_IP}
PUBLIC_HOST="$(normalize_host "$PUBLIC_HOST")"
if [[ -z "$PUBLIC_HOST" ]]; then
  PUBLIC_HOST="$SERVER_IP"
fi

# ─── Финальная валидация входных данных ──────────────────────────────────────

# Все обязательные поля должны быть заполнены.
if [[ -z "$XRAY_SNI" || -z "$TELEMT_TLS_DOMAIN" || -z "$HY2_DOMAIN" || -z "$HY2_EMAIL" ]]; then
  print_error "Не все параметры заданы"
  exit 1
fi

# Имя пользователя: только безопасные символы (буквы, цифры, точка, тире, подчёркивание).
# Запрет спецсимволов защищает от инъекций в конфиги TOML/JSON/YAML.
if ! [[ "$FIRST_USER" =~ ^[A-Za-z0-9._-]+$ ]]; then
  print_error "Имя пользователя должно содержать только A-Za-z0-9._-"
  exit 1
fi

# HAProxy роутит трафик по SNI, поэтому все три SNI/домена должны быть уникальны.
if [[ "$XRAY_SNI" == "$TELEMT_TLS_DOMAIN" ]]; then
  print_error "SNI для Xray и Telemt должны быть разными"
  exit 1
fi

# Hysteria2-домен — реальный домен с DNS-записью; он не может совпадать
# с маскировочными SNI Xray/Telemt, которые просто имитируются.
if [[ "$HY2_DOMAIN" == "$XRAY_SNI" || "$HY2_DOMAIN" == "$TELEMT_TLS_DOMAIN" ]]; then
  print_error "Домен Hysteria2 должен быть отдельным, не совпадать с Xray/Telemt SNI"
  exit 1
fi

# ─── Предпросмотр конфигурации перед установкой ───────────────────────────────
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

# Финальное подтверждение — даём пользователю шанс прервать перед
# деструктивными операциями (перезапись конфигов, установка пакетов).
read -rp "Продолжить установку? (y/n): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  print_warning "Установка отменена"
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# УСТАНОВКА СИСТЕМНЫХ ПАКЕТОВ
# ─────────────────────────────────────────────────────────────────────────────
print_info "Обновление и пакеты..."
apt update
apt install -y qrencode curl jq haproxy wget openssl tar certbot ufw ca-certificates kmod python3
# qrencode    — генерация QR-кодов прямо в терминале (ANSI art)
# jq          — парсинг и редактирование JSON (база данных пользователей)
# haproxy     — входной TCP-балансировщик с SNI-роутингом
# certbot     — выпуск TLS-сертификатов Let's Encrypt для Hysteria2
# ufw         — управление firewall (iptables frontend)
# kmod        — утилиты для загрузки модулей ядра (нужно для BBR)
# python3     — требуется некоторыми вспомогательными скриптами certbot
print_status "Пакеты установлены"

# ─────────────────────────────────────────────────────────────────────────────
# ВКЛЮЧЕНИЕ BBR (TCP Bottleneck Bandwidth and RTT)
# BBR — алгоритм управления перегрузкой от Google, значительно улучшает
# пропускную способность и снижает задержки, особенно полезен для прокси.
# fq (Fair Queueing) — планировщик очереди, который BBR требует в паре.
# ─────────────────────────────────────────────────────────────────────────────
print_info "BBR..."
if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
  print_status "BBR уже включен"
else
  modprobe tcp_bbr 2>/dev/null || true   # загружаем модуль ядра BBR
  grep -q '^net.core.default_qdisc=fq$' /etc/sysctl.conf || echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
  grep -q '^net.ipv4.tcp_congestion_control=bbr$' /etc/sysctl.conf || echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
  sysctl -p >/dev/null 2>&1 || true      # применяем параметры ядра
  print_status "BBR включен"
fi

# ─────────────────────────────────────────────────────────────────────────────
# СОЗДАНИЕ ДИРЕКТОРИЙ И РЕЗЕРВНЫХ КОПИЙ
# Все рабочие директории создаются заранее с нужными правами.
# Перед перезаписью ключевых файлов делаем timestamped-бэкапы.
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p /usr/local/etc/xray /usr/local/etc/proxy /etc/telemt /etc/hysteria /etc/hysteria/certs /opt/telemt /var/www/masq /usr/local/lib
chmod 755 /usr/local /usr/local/etc /usr/local/etc/xray /usr/local/etc/proxy 2>/dev/null || true
chmod 755 /usr/local/etc/xray /usr/local/etc/proxy /etc/telemt /etc/hysteria /etc/hysteria/certs

# Пути к основным хранилищам данных.
KEYS="/usr/local/etc/xray/.keys"         # ключи и параметры установки (flat key:value)
USERS_DB="/usr/local/etc/proxy/users.json"  # база пользователей (JSON)

# Резервные копии с меткой времени — на случай повторного запуска скрипта.
[ -f "$KEYS" ] && cp "$KEYS" "$KEYS.bak.$(date +%F_%H%M%S)" || true
[ -f "$USERS_DB" ] && cp "$USERS_DB" "$USERS_DB.bak.$(date +%F_%H%M%S)" || true

# ─────────────────────────────────────────────────────────────────────────────
# УСТАНОВКА XRAY И ГЕНЕРАЦИЯ КРИПТОГРАФИЧЕСКИХ КЛЮЧЕЙ
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка Xray..."

# Официальный установщик от XTLS — скачивает и устанавливает последнюю версию.
bash -c "$(curl -4 -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1

# UUID — уникальный идентификатор клиента в VLESS-протоколе.
# Каждый пользователь получает свой UUID.
UUID="$(xray uuid)"

# Ключевая пара X25519 для Reality:
# - приватный ключ хранится на сервере (никому не передаётся)
# - публичный ключ вставляется в ссылку подключения для клиента
# Reality использует эту пару для создания маскировочного TLS-рукопожатия.
X25519_OUT="$(xray x25519 2>&1 | tr -d '\r')"

# Парсим вывод xray x25519 — формат может варьироваться между версиями,
# поэтому обрабатываем несколько возможных вариантов заголовков.
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

# Если ключи не распарсились — аварийный выход с диагностикой.
if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
  echo "Не удалось получить ключи x25519"
  echo "Сырой вывод:"
  echo "$X25519_OUT"
  exit 1
fi

# Short ID — дополнительный 8-байтный идентификатор Reality-сессии.
# Используется для дополнительной аутентификации и фингерпринтинга.
SHORT_ID="$(openssl rand -hex 8)"

# Генерируем учётные данные первого пользователя:
# - пароль Hysteria2 (буквенно-цифровой, 16 символов)
# - MTProto-секрет для Telemt (hex, 32 символа)
MAIN_HY2_PASS="$(gen_alnum_pass)"
MAIN_TEL_SECRET="$(gen_hex_secret)"

# ─── Сохраняем параметры установки в .keys ────────────────────────────────────
# Плоский формат key: value удобен для парсинга через awk (функция kv()).
# Файл хранится с правами 600 — только root.
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

# ─── Инициализация базы данных пользователей ─────────────────────────────────
# JSON-файл со списком пользователей. Каждый пользователь содержит:
#   name      — уникальное имя
#   uuid      — VLESS-идентификатор для Xray
#   hy2pass   — пароль Hysteria2
#   telsecret — MTProto-секрет для Telemt (raw hex, без префикса ee)
cat > "$USERS_DB" <<EOF
{
  "users": [
    {
      "name": "$FIRST_USER",
      "uuid": "$UUID",
      "hy2pass": "$MAIN_HY2_PASS",
      "telsecret": "$MAIN_TEL_SECRET"
    }
  ]
}
EOF
chmod 600 "$USERS_DB"

# ─────────────────────────────────────────────────────────────────────────────
# ОБЩАЯ БИБЛИОТЕКА /usr/local/lib/proxy-common.sh
#
# Выносим весь переиспользуемый код в отдельный файл-библиотеку.
# Все управляющие команды (newuser, rmuser, sharelink и др.) подключают её
# через `source`. Это исключает дублирование кода и упрощает поддержку.
# ─────────────────────────────────────────────────────────────────────────────
cat > /usr/local/lib/proxy-common.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# ─── Пути к хранилищам данных ────────────────────────────────────────────────
KEYS="/usr/local/etc/xray/.keys"
USERS_DB="/usr/local/etc/proxy/users.json"
XRAY_CFG="/usr/local/etc/xray/config.json"
TEL_CFG="/etc/telemt/telemt.toml"
HY2_CFG="/etc/hysteria/config.yaml"

# ─── kv <key> ─────────────────────────────────────────────────────────────────
# Читает значение по ключу из файла .keys (формат "key: value").
# Аналог ini-парсера для плоского key:value файла.
# Пример: kv xray_port → "8443"
kv() {
  awk -F': ' -v k="$1" '$1==k {print $2; exit}' "$KEYS" 2>/dev/null
}

# ─── Генераторы паролей (дублируются из основного скрипта) ───────────────────
# Необходимы в библиотеке, так как newuser создаёт учётные данные
# без вызова основного скрипта установки.

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

gen_hex_secret() {
  openssl rand -hex 16
}

# ─── Функции работы с базой пользователей (users.json) ───────────────────────

# Количество пользователей в БД.
db_user_count() {
  jq '.users | length' "$USERS_DB" 2>/dev/null || echo 0
}

# Имя первого пользователя (для команд mainuser, tglink, hy2info).
db_first_user() {
  jq -r '.users[0].name // empty' "$USERS_DB" 2>/dev/null
}

# Список всех имён пользователей (по одному на строку).
db_user_names() {
  jq -r '.users[].name' "$USERS_DB" 2>/dev/null
}

# Проверка существования пользователя по имени.
# Возвращает 0 если существует, 1 если нет.
db_has_user() {
  local name="$1"
  jq -e --arg n "$name" '.users[]? | select(.name==$n)' "$USERS_DB" >/dev/null 2>&1
}

# Получение значения конкретного поля пользователя.
# Пример: db_get_user_field "alice" "hy2pass" → "Xk9pQr2mNv7aLb4w"
db_get_user_field() {
  local name="$1"
  local field="$2"
  jq -r --arg n "$name" --arg f "$field" '.users[] | select(.name==$n) | .[$f] // empty' "$USERS_DB" 2>/dev/null | head -n1
}

# Добавление нового пользователя в БД.
# Использует mktemp для атомарной записи — исключает повреждение файла
# при прерывании записи (write-then-move идиома).
db_add_user() {
  local name="$1"
  local uuid="$2"
  local hy2pass="$3"
  local telsecret="$4"
  local tmp
  tmp="$(mktemp)"
  jq --arg name "$name" \
     --arg uuid "$uuid" \
     --arg hy2pass "$hy2pass" \
     --arg telsecret "$telsecret" \
     '.users += [{"name":$name,"uuid":$uuid,"hy2pass":$hy2pass,"telsecret":$telsecret}]' \
     "$USERS_DB" > "$tmp"
  mv "$tmp" "$USERS_DB"
  chmod 600 "$USERS_DB"
}

# Удаление пользователя из БД по имени.
# Тоже через mktemp для атомарности.
db_remove_user() {
  local name="$1"
  local tmp
  tmp="$(mktemp)"
  jq --arg name "$name" '.users |= map(select(.name != $name))' "$USERS_DB" > "$tmp"
  mv "$tmp" "$USERS_DB"
  chmod 600 "$USERS_DB"
}

# ─── Вспомогательные функции для получения сетевых параметров ────────────────

# Внешний IP сервера (fallback-цепочка из трёх методов).
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

# Публичный хост из .keys, или внешний IP как fallback.
public_host() {
  local h
  h="$(kv public_host)"
  [[ -z "$h" ]] && h="$(server_ip)"
  printf '%s' "$h"
}

# Порт HAProxy из .keys, или 443 как fallback.
public_port() {
  local p
  p="$(kv haproxy_port)"
  [[ -z "$p" ]] && p=443
  printf '%s' "$p"
}

# Домен Hysteria2 из .keys.
hy2_domain() {
  kv hy2_domain
}

# ─── tg_full_secret_for <user> ────────────────────────────────────────────────
# Формирует полный MTProto TLS-секрет для Telegram-ссылки.
#
# Формат секрета MTProto TLS:
#   ee + <hex-секрет пользователя> + <hex-кодированный TLS домен>
#
# Префикс "ee" — маркер TLS-режима MTProto (FakeTLS).
# Домен кодируется как hex с помощью od (octal dump с -tx1 флагом).
# Результат вставляется в ссылку t.me/proxy?secret=...
tg_full_secret_for() {
  local user="$1"
  local raw domain_hex
  raw="$(db_get_user_field "$user" telsecret)"
  domain_hex="$(printf '%s' "$(kv telemt_tls_domain)" | od -An -tx1 | tr -d ' \n')"
  printf 'ee%s%s' "$raw" "$domain_hex"
}

# ─── xray_link_for <user> ─────────────────────────────────────────────────────
# Формирует VLESS URI для подключения через Xray (Reality + xHTTP).
#
# Формат: vless://<uuid>@<host>:<port>?<параметры>#<имя>
# Параметры:
#   type=xhttp        — транспорт HTTP/2 или HTTP/3 (xhttp — расширенный HTTP)
#   security=reality  — маскировочный TLS (не настоящий, но неотличимый снаружи)
#   fp=firefox        — fingerprint TLS — имитируем Firefox
#   pbk               — публичный ключ Reality (для клиентской проверки)
#   sid               — short ID Reality-сессии
#   sni               — домен маскировки (например, github.com)
#   spx=/%2F          — URL-путь (закодированный слэш)
xray_link_for() {
  local user="$1"
  local uuid pbk sid sni host port
  uuid="$(db_get_user_field "$user" uuid)"
  pbk="$(kv xray_public_key)"
  sid="$(kv xray_short_id)"
  sni="$(kv xray_sni)"
  host="$sni"
  port="$(public_port)"
  printf 'vless://%s@%s:%s?type=xhttp&security=reality&encryption=none&host=%s&path=%%2F&mode=auto&sni=%s&fp=firefox&pbk=%s&sid=%s&spx=%%2F#%s\n' \
    "$uuid" "$(public_host)" "$port" "$host" "$sni" "$pbk" "$sid" "$user"
}

# ─── hy2_link_for <user> ──────────────────────────────────────────────────────
# Формирует URI для подключения к Hysteria2.
#
# Формат: hy2://<user>:<pass>@<domain>:443?<параметры>#<имя>
# Параметры:
#   sni=<domain>       — SNI совпадает с реальным доменом сертификата LE
#   alpn=h3            — QUIC/HTTP3 ALPN
#   insecure=0         — проверяем сертификат (он настоящий, от LE!)
#   allowInsecure=0    — дублирующий параметр для совместимости клиентов
hy2_link_for() {
  local user="$1"
  local pass domain
  pass="$(db_get_user_field "$user" hy2pass)"
  domain="$(hy2_domain)"
  printf 'hy2://%s:%s@%s:443?sni=%s&alpn=h3&insecure=0&allowInsecure=0#%s\n' \
    "$user" "$pass" "$domain" "$domain" "$user"
}

# ─── Ссылки для Telegram MTProto ─────────────────────────────────────────────

# HTTPS-ссылка для открытия в браузере (откроет Telegram через web).
tg_https_link_for() {
  local user="$1"
  local full
  full="$(tg_full_secret_for "$user")"
  printf 'https://t.me/proxy?server=%s&port=%s&secret=%s\n' "$(public_host)" "$(public_port)" "$full"
}

# tg://-схема для прямого открытия в приложении Telegram.
tg_scheme_link_for() {
  local user="$1"
  local full
  full="$(tg_full_secret_for "$user")"
  printf 'tg://proxy?server=%s&port=%s&secret=%s\n' "$(public_host)" "$(public_port)" "$full"
}

# ─── show_qr <string> ─────────────────────────────────────────────────────────
# Генерирует QR-код прямо в терминале (ANSI Unicode art).
# Полезно для сканирования мобильным клиентом без копирования строки.
show_qr() {
  printf '%s\n' "$1" | qrencode -t ansiutf8
}

# ─────────────────────────────────────────────────────────────────────────────
# РЕНДЕРИНГ КОНФИГОВ
# Все три функции перегенерируют конфиг "с нуля" из текущего состояния БД.
# Это обеспечивает консистентность: после добавления/удаления пользователя
# вызываем render_all_configs → все сервисы синхронизируются с БД.
# ─────────────────────────────────────────────────────────────────────────────

# ─── render_xray_config ───────────────────────────────────────────────────────
# Генерирует /usr/local/etc/xray/config.json из шаблона.
#
# Ключевые особенности конфига Xray:
#   - routing: блокируем рекламные домены и китайские IP (геолокация)
#   - inbound: VLESS с xHTTP-транспортом + Reality-безопасностью
#   - clients: список из всех пользователей в БД (uuid + email=name)
#   - flow: пустая строка — XTLS-flow не используется с xhttp-транспортом
#   - realitySettings: target — реальный сервер для маскировки,
#     serverNames — допустимые SNI, privateKey — приватный ключ Reality
#   - sniffing: определяем тип трафика для корректного routing
render_xray_config() {
  local clients_json
  # Формируем JSON-массив клиентов из БД: [{email, id, flow}, ...]
  clients_json="$(jq -c '[.users[] | {email:.name,id:.uuid,flow:""}]' "$USERS_DB")"
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
      "port": $(kv xray_port),
      "protocol": "vless",
      "settings": {
        "clients": $clients_json,
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
          "target": "$(kv xray_sni):443",
          "serverNames": ["$(kv xray_sni)", "www.$(kv xray_sni)"],
          "privateKey": "$(kv xray_private_key)",
          "minClientVer": "",
          "maxClientVer": "",
          "maxTimeDiff": 0,
          "shortIds": ["$(kv xray_short_id)"]
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

# ─── render_telemt_config ─────────────────────────────────────────────────────
# Генерирует /etc/telemt/telemt.toml из параметров .keys и БД пользователей.
#
# Ключевые секции конфига Telemt:
#   [general.modes]    — включаем только tls (FakeTLS), classic/secure off
#   [general.links]    — публичный хост и порт для генерации ссылок
#   [server]           — локальный порт и лимит соединений
#   [server.api]       — REST API для управления (только localhost)
#   [censorship]       — домен для TLS-маскировки
#   [access.users]     — таблица "имя = hex-секрет" для аутентификации
render_telemt_config() {
  {
    echo "[general]"
    echo "use_middle_proxy = false"   # не используем промежуточный прокси MTProto
    echo "log_level = \"normal\""
    echo
    echo "[general.modes]"
    echo "classic = false"    # классический MTProto без маскировки — off
    echo "secure = false"     # DD MTProto секретный режим — off
    echo "tls = true"         # FakeTLS режим — on (маскируется под TLS)
    echo
    echo "[general.links]"
    echo "show = \"*\""
    echo "public_host = \"$(kv public_host)\""
    echo "public_port = $(kv haproxy_port)"
    echo
    echo "[server]"
    echo "port = $(kv telemt_port)"
    echo "listen_addr_ipv4 = \"127.0.0.1\""   # только localhost — снаружи через HAProxy
    echo "max_connections = 10000"
    echo
    echo "[server.api]"
    echo "enabled = true"
    echo "listen = \"127.0.0.1:7443\""
    echo "whitelist = [\"127.0.0.1/32\", \"::1/128\"]"   # API только с localhost
    echo
    echo "[censorship]"
    echo "tls_domain = \"$(kv telemt_tls_domain)\""   # домен FakeTLS маскировки
    echo
    echo "[access.users]"
    # Каждый пользователь: "имя" = "hex-секрет" (сырой, без ee-префикса)
    jq -r '.users[] | "\"" + .name + "\" = \"" + .telsecret + "\""' "$USERS_DB"
  } > "$TEL_CFG"
  chown telemt:telemt "$TEL_CFG"
  chmod 600 "$TEL_CFG"
}

# ─── render_hy2_config ────────────────────────────────────────────────────────
# Генерирует /etc/hysteria/config.yaml для Hysteria2.
#
# Hysteria2 слушает UDP :443, использует сертификат от Let's Encrypt.
# Аутентификация: userpass — словарь "имя: пароль".
# Маскировочный HTTPS-сервер (masquerade) запускается на TCP :8444
# и отдаёт статическую страницу-заглушку из /var/www/masq.
# HAProxy роутит к нему TLS-трафик с HY2_DOMAIN через bk_hy2site.
render_hy2_config() {
  local certname
  certname="$(kv hy2_cert_name)"
  [[ -z "$certname" ]] && certname="$(kv hy2_domain)"   # fallback на hy2_domain
  {
    echo "listen: :443"
    echo
    echo "tls:"
    # Пути к сертификатам Let's Encrypt. certname — имя сертификата в certbot,
    # может отличаться от имени домена при wildcard или мультидоменных сертах.
    echo "  cert: /etc/letsencrypt/live/${certname}/fullchain.pem"
    echo "  key: /etc/letsencrypt/live/${certname}/privkey.pem"
    echo
    echo "auth:"
    echo "  type: userpass"
    echo "  userpass:"
    # Генерируем словарь пользователей для Hysteria2
    jq -r '.users[] | "    \"" + .name + "\": \"" + .hy2pass + "\""' "$USERS_DB"
    echo
    echo "masquerade:"
    echo "  type: file"
    echo "  listenHTTPS: :8444"   # HAProxy шлёт сюда TCP с SNI=hy2_domain
    echo "  forceHTTPS: true"     # редиректим HTTP→HTTPS
    echo "  file:"
    echo "    dir: /var/www/masq" # статическая заглушка-страница
  } > "$HY2_CFG"
  chown root:root "$HY2_CFG"
  chmod 600 "$HY2_CFG"
}

# Обёртка для перегенерации всех трёх конфигов за один вызов.
render_all_configs() {
  render_xray_config
  render_telemt_config
  render_hy2_config
}

# Перезапуск всех динамических сервисов после изменений в БД пользователей.
# Вызывается после newuser/rmuser.
restart_dynamic_services() {
  systemctl restart xray
  systemctl restart telemt
  systemctl restart hysteria-server.service
}

# ─── print_bundle <user> ──────────────────────────────────────────────────────
# Выводит все ссылки подключения для указанного пользователя:
#   1. VLESS xHTTP + Reality ссылка + QR
#   2. Hysteria2 ссылка + QR
#   3. Telegram MTProto HTTPS и tg:// ссылки + QR
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

# Загружаем библиотеку в текущий процесс установки и сразу генерируем конфиг.
source /usr/local/lib/proxy-common.sh
render_xray_config

# Запускаем Xray и добавляем в автозагрузку.
systemctl enable --now xray
systemctl restart xray
print_status "Xray установлен"

# ─────────────────────────────────────────────────────────────────────────────
# УСТАНОВКА TELEMT (MTProto прокси для Telegram)
# Telemt — форк mtproxy с поддержкой FakeTLS и TOML-конфигом.
# Скачиваем готовый бинарник под текущую архитектуру и libc.
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка Telemt..."

# Определяем архитектуру процессора для выбора правильного бинарника.
ARCH="$(uname -m)"

# Определяем используемую C-библиотеку:
#   musl  — используется в Alpine Linux и других минималистичных дистрибутивах
#   gnu   — стандартная glibc для Ubuntu/Debian/CentOS и большинства VPS
if ldd --version 2>&1 | grep -iq musl; then
  LIBC="musl"
else
  LIBC="gnu"
fi

# Формируем URL для скачивания: telemt-<arch>-linux-<libc>.tar.gz
TELEMT_URL="https://github.com/telemt/telemt/releases/latest/download/telemt-${ARCH}-linux-${LIBC}.tar.gz"
TMPDIR="$(mktemp -d)"  # временная директория, очищается после установки

print_info "Скачивание: telemt-${ARCH}-linux-${LIBC}.tar.gz"
curl -fsSL -o "$TMPDIR/telemt.tar.gz" "$TELEMT_URL"
tar -xzf "$TMPDIR/telemt.tar.gz" -C "$TMPDIR"
# install -m 755 — копируем бинарник с установкой прав выполнения
install -m 755 "$TMPDIR/telemt" /bin/telemt
rm -rf "$TMPDIR"  # убираем временные файлы

# Создаём системного пользователя telemt (без shell, без домашней директории).
# Сервис запускается от непривилегированного пользователя для безопасности,
# но с capability CAP_NET_BIND_SERVICE (не нужен здесь — слушает на >1024).
if ! id telemt &>/dev/null; then
  useradd -r -s /bin/false -d /opt/telemt -m telemt
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
LimitNOFILE=65536                              # увеличенный лимит файловых дескрипторов
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true                           # запрет получения новых привилегий

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
# Hysteria2 работает поверх QUIC (UDP), поэтому не конкурирует с HAProxy
# на TCP. Занимает UDP :443. Для TCP-трафика с HY2_DOMAIN HAProxy
# роутит к masquerade-серверу Hysteria2 (TCP :8444).
# ─────────────────────────────────────────────────────────────────────────────
print_info "Установка Hysteria2"

mkdir -p /var/www/masq /etc/hysteria/certs

# ─── Страница-заглушка для маскировки ─────────────────────────────────────────
# При обращении через браузер по HTTP/HTTPS пользователь увидит эту страницу
# вместо ошибки соединения. Имитирует "что-то грузится" без явных признаков прокси.
# Тёмный фон, три анимированные точки — стандартный loading screen.
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

# ─── Получение TLS-сертификата Let's Encrypt для Hysteria2 ───────────────────
# Логика с тремя путями:
#   1. Уже есть валидный сертификат точно для этого домена
#   2. Есть сертификат под другим именем, покрывающий этот домен (мультидоменный)
#   3. Нет сертификата → выпускаем через certbot standalone (временный HTTP-сервер)
#
# Для certbot standalone требуется свободный порт 80/tcp на время выпуска.
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
    certbot certonly --standalone \
      --cert-name "$HY2_DOMAIN" \
      --keep-until-expiring \     # не перевыпускать, если ещё действует
      -d "$HY2_DOMAIN" \
      -m "$HY2_EMAIL" \
      --agree-tos \
      --non-interactive            # без интерактивных вопросов

    CERT_NAME="$HY2_DOMAIN"
  fi
fi

# Сохраняем итоговое имя сертификата в .keys для последующего использования.
sed -i "s#^hy2_cert_name:.*#hy2_cert_name: $CERT_NAME#" "$KEYS" 2>/dev/null || echo "hy2_cert_name: $CERT_NAME" >> "$KEYS"

# Создаём системного пользователя для Hysteria2.
if ! id hysteria &>/dev/null; then
  useradd -r -U -d /etc/hysteria -s /usr/sbin/nologin hysteria
fi

# Официальный установщик Hysteria2 от авторов.
print_info "Установка Hysteria2..."
bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1

# Ищем бинарник hysteria в стандартных местах.
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
LimitNOFILE=1048576   # максимальный лимит для высоконагруженного UDP-сервера
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# ─── Хук для автоматического перезапуска Hysteria2 после обновления сертификата ──
# certbot при обновлении (renew) запускает скрипты из renewal-hooks/deploy/.
# Hysteria2 нужно перезапустить, чтобы подхватить новый сертификат.
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/99-hysteria-restart.sh <<'EOF'
#!/bin/sh
systemctl restart hysteria-server.service 2>/dev/null || true
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/99-hysteria-restart.sh

systemctl daemon-reload
systemctl enable --now hysteria-server.service
systemctl restart hysteria-server.service
# Включаем таймер автообновления сертификатов certbot (если поддерживается).
systemctl enable --now certbot.timer >/dev/null 2>&1 || true
print_status "Hysteria2 установлена"

# ─────────────────────────────────────────────────────────────────────────────
# НАСТРОЙКА HAPROXY — SNI-МАРШРУТИЗАТОР
#
# Архитектура трафика:
#   Клиент → 0.0.0.0:443 (TCP) → HAProxy
#   HAProxy инспектирует TLS ClientHello (SNI) и роутит:
#     SNI = HY2_DOMAIN       → 127.0.0.1:8444  (Hysteria2 masquerade, HTTPS)
#     SNI = TELEMT_TLS_DOMAIN → 127.0.0.1:TELEMT_PORT (Telemt MTProto)
#     SNI = XRAY_SNI          → 127.0.0.1:XRAY_PORT  (Xray VLESS Reality)
#     default                 → Hysteria2 masquerade (выглядит как обычный сайт)
#
# HAProxy работает в режиме tcp (Layer 4), не терминирует TLS —
# просто перенаправляет байты по SNI.
# ─────────────────────────────────────────────────────────────────────────────
print_info "Настройка HAProxy..."

[ -f /etc/haproxy/haproxy.cfg ] && cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak.$(date +%F_%H%M%S) || true

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

# Проверяем синтаксис конфига перед применением.
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
# НАСТРОЙКА UFW (Uncomplicated Firewall)
#
# Открываем только необходимые порты:
#   22/tcp  — SSH (обязательно, иначе потеряем доступ)
#   80/tcp  — ACME HTTP challenge для certbot
#   <HAProxy>/tcp — основной вход (обычно 443)
#   443/udp — Hysteria2 (QUIC работает только на UDP!)
# ─────────────────────────────────────────────────────────────────────────────
print_info "Настройка UFW..."
ufw allow 22/tcp comment "SSH"
ufw allow 80/tcp comment "ACME"
ufw allow ${HAPROXY_PORT}/tcp comment "HAProxy"
ufw allow 443/udp comment "Hysteria2"
ufw --force enable   # --force не спрашивает подтверждения
print_status "UFW настроен"

# ─────────────────────────────────────────────────────────────────────────────
# УПРАВЛЯЮЩИЕ КОМАНДЫ
# Каждая команда — отдельный исполняемый файл в /usr/local/bin/.
# Все они source-ят /usr/local/lib/proxy-common.sh для доступа к функциям.
# ─────────────────────────────────────────────────────────────────────────────

# ─── mainuser ─────────────────────────────────────────────────────────────────
# Быстрый просмотр ссылок первого (главного) пользователя.
# Удобно после установки или при быстрой проверке конфигурации.
cat > /usr/local/bin/mainuser <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

USER="$(db_first_user)"
if [[ -z "$USER" ]]; then
  echo "Нет пользователей"
  exit 1
fi

print_bundle "$USER"
EOF
chmod +x /usr/local/bin/mainuser

# ─── userlist ─────────────────────────────────────────────────────────────────
# Выводит пронумерованный список всех пользователей из БД.
cat > /usr/local/bin/userlist <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)

if [[ ${#users[@]} -eq 0 ]]; then
  echo "Список пользователей пуст"
  exit 1
fi

echo "Пользователи:"
for i in "${!users[@]}"; do
  echo "$((i+1)). ${users[$i]}"
done
EOF
chmod +x /usr/local/bin/userlist

# ─── newuser ──────────────────────────────────────────────────────────────────
# Интерактивное создание нового пользователя:
#   1. Запрашивает имя, валидирует
#   2. Генерирует UUID, пароль Hy2, MTProto-секрет
#   3. Добавляет в БД
#   4. Перегенерирует все конфиги
#   5. Перезапускает сервисы
#   6. Выводит ссылки нового пользователя
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
# Удаление пользователя с защитой от удаления последнего.
# Минимум один пользователь должен оставаться для работы сервисов.
cat > /usr/local/bin/rmuser <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)

if [[ ${#users[@]} -eq 0 ]]; then
  echo "Нет пользователей для удаления."
  exit 1
fi

if [[ ${#users[@]} -le 1 ]]; then
  echo "Нельзя удалить последнего пользователя."
  exit 1
fi

echo "Пользователи:"
for i in "${!users[@]}"; do
  echo "$((i+1)). ${users[$i]}"
done

read -rp "Номер для удаления: " CHOICE
if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || (( CHOICE < 1 || CHOICE > ${#users[@]} )); then
  echo "Ошибка: номер от 1 до ${#users[@]}"
  exit 1
fi

IDX=$((CHOICE - 1))
SEL="${users[$IDX]}"

db_remove_user "$SEL"
render_all_configs
restart_dynamic_services

echo "Пользователь '$SEL' удалён."
EOF
chmod +x /usr/local/bin/rmuser

# ─── sharelink ────────────────────────────────────────────────────────────────
# Интерактивный выбор пользователя из списка и вывод всех его ссылок.
# Используется для шаринга конфигурации с конкретным клиентом.
cat > /usr/local/bin/sharelink <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

mapfile -t users < <(db_user_names)

if [[ ${#users[@]} -eq 0 ]]; then
  echo "Нет пользователей."
  exit 1
fi

echo "Пользователи:"
for i in "${!users[@]}"; do
  echo "$((i+1)). ${users[$i]}"
done

read -rp "Выберите пользователя: " CHOICE
if ! [[ "$CHOICE" =~ ^[0-9]+$ ]] || (( CHOICE < 1 || CHOICE > ${#users[@]} )); then
  echo "Ошибка: номер от 1 до ${#users[@]}"
  exit 1
fi

SEL="${users[$((CHOICE - 1))]}"
print_bundle "$SEL"
EOF
chmod +x /usr/local/bin/sharelink

# ─── hy2info ──────────────────────────────────────────────────────────────────
# Быстрый вывод Hysteria2-ссылки и QR для первого пользователя.
cat > /usr/local/bin/hy2info <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

USER="$(db_first_user)"
if [[ -z "$USER" ]]; then
  echo "Нет пользователей"
  exit 1
fi

LINK="$(hy2_link_for "$USER")"
echo ""
echo "=== Hysteria2 ==="
echo "$LINK"
echo ""
echo "QR:"
show_qr "$LINK"
EOF
chmod +x /usr/local/bin/hy2info

# ─── hy2list ──────────────────────────────────────────────────────────────────
# Список пользователей с доступом к Hysteria2 (все пользователи из БД).
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
# Вывод всех Hysteria2-ссылок для всех пользователей сразу.
# Удобно для массовой рассылки или аудита.
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
# MTProto-ссылки первого пользователя в двух форматах:
#   https://t.me/proxy?... — открывается в браузере, редиректит в Telegram
#   tg://proxy?...         — открывается напрямую в Telegram-приложении
cat > /usr/local/bin/tglink <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /usr/local/lib/proxy-common.sh

USER="$(db_first_user)"
if [[ -z "$USER" ]]; then
  echo "Нет пользователей"
  exit 1
fi

HTTPS_LINK="$(tg_https_link_for "$USER")"
TG_LINK="$(tg_scheme_link_for "$USER")"

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
# Все MTProto HTTPS-ссылки для всех пользователей одной командой.
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
# Быстрая диагностика: статус всех четырёх сервисов + открытые порты.
# Первое место для проверки после установки или при проблемах.
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
# Показываем только интересующие нас порты: входные и внутренние
ss -tlnup 2>/dev/null | grep -E "(:${HAPROXY_PORT}|:${XRAY_PORT}|:${TELEMT_PORT}|:80|:443|:8444)" || true
echo ""
EOF
chmod +x /usr/local/bin/proxystatus

# ─────────────────────────────────────────────────────────────────────────────
# СПРАВОЧНЫЙ ФАЙЛ /root/help
# Краткая шпаргалка по командам и путям к конфигам.
# Доступна сразу после установки: cat /root/help
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
# ФИНАЛЬНЫЙ ПЕРЕЗАПУСК ВСЕХ СЕРВИСОВ
# После установки делаем чистый reload systemd и рестарт,
# чтобы все сервисы стартовали с актуальными конфигурациями.
# ─────────────────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl restart xray
systemctl restart telemt
systemctl restart hysteria-server.service
systemctl restart haproxy

# ─── Итоговый вывод ──────────────────────────────────────────────────────────
echo ""
echo "============================================"
print_status "Установка завершена"
echo "  TCP ${HAPROXY_PORT} -> HAProxy -> Xray + Telemt + Hysteria2 site"
echo "  UDP 443 -> Hysteria2"
echo "  Первый пользователь: ${FIRST_USER}"
echo "============================================"
echo ""

# Сразу показываем ссылки первого пользователя.
mainuser
echo ""
print_info "Справка: cat /root/help"
print_info "Проверка: proxystatus"
echo ""