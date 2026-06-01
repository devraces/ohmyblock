# Ohmyblock
![OhMyBlock](https://ik.imagekit.io/gh4fm25seyo/ohmyblock_UoY6Io1VN.webp)
Инсталлер прокси-стека на одном VPS:

- **VLESS xHTTP + Reality** (Xray) — TLS-маскировка под популярный домен.
- **Hysteria2** — высокоскоростной QUIC-прокси поверх UDP с TLS Let's Encrypt.
- **Telemt (MTProto)** — прокси для Telegram с fake-TLS маскировкой.
- **HAProxy** — единая точка входа на TCP/443, SNI-маршрутизатор.
- **Cloudflare WARP** — outbound-туннель: исходящий трафик VLESS и Telemt идёт через Cloudflare, меняя IP сервера в глазах целевых сайтов.

Один публичный TCP-порт (443) обслуживает три разных протокола, отделённых по SNI. Hysteria2 параллельно занимает UDP/443. Все три прокси-движка слушают только loopback. Исходящий трафик от VLESS и Telemt направляется через WARP socks5 на `127.0.0.1:40000`.

---

## Содержание

- [Архитектура](#архитектура)
- [Требования](#требования)
- [Установка](#установка)
- [Параметры установки](#параметры-установки)
- [Управление](#управление)
- [Файлы и пути](#файлы-и-пути)
- [Тюнинг производительности](#тюнинг-производительности)
- [Безопасность](#безопасность)
- [Обновление сертификатов](#обновление-сертификатов)
- [Диагностика и устранение неполадок](#диагностика-и-устранение-неполадок)
- [Идемпотентность и обновление](#идемпотентность-и-обновление)
- [Удаление](#удаление)
- [FAQ](#faq)

---

## Архитектура

```
                              ┌─────────────────────────────────────────────┐
   Клиент (TCP 443)           │                    VPS                      │
   ─────────────────►         │                                             │
                              │   HAProxy :443/tcp                          │
                              │   ├─ SNI=$XRAY_SNI ──────────┼──► Xray   :8443/tcp (loopback)  ─┐
                              │   ├─ SNI=$TELEMT_TLS_DOMAIN ─┼──► Telemt :9443/tcp (loopback)  ─┤
                              │   └─ SNI=$HY2_DOMAIN / def. ─┼──► Hysteria2 masq. :8444/tcp     │
                              │                               │             │                   │
   Клиент (UDP 443) ─────────►│   Hysteria2 :443/udp          │             │                   │
                              │                               │             │                   │
                              │                               │   WARP socks5 :40000  ◄──────────┘
                              │                               │        │                        │
                              └───────────────────────────────┼────────┼────────────────────────┘
                                                              │        ▼
                                                              │  Cloudflare WARP (WireGuard)
                                                              │        │
                                                              │        ▼
                                                              │    Интернет
                                                              │  (с Cloudflare IP)
```

### Как это работает

- **HAProxy** на TCP/443 принимает TLS ClientHello, читает SNI и направляет соединение в один из трёх loopback-бэкендов. Layer-4 passthrough — HAProxy не терминирует TLS.
- **Xray (VLESS xHTTP + Reality)** имитирует чужой популярный TLS-сайт (например, `github.com`). Reality снимает необходимость в собственном сертификате. xHTTP — транспорт поверх HTTP, выглядит как обычный HTTPS-трафик. Весь исходящий трафик идёт через WARP socks5.
- **Telemt (MTProto)** обслуживает Telegram-клиентов через fake-TLS. Внешне трафик выглядит как HTTPS на «честный» домен из параметра `tls_domain`. Исходящие соединения к серверам Telegram проходят через WARP socks5.
- **Hysteria2** работает на UDP/443 (QUIC). Использует реальный TLS-сертификат Let's Encrypt. На TCP/443 отдаёт HTTPS-«заглушку» через masquerade. Hysteria2 выходит в интернет **напрямую** (без WARP) — QUIC и WireGuard плохо сочетаются при вложенном UDP.
- **HAProxy default backend** при незнакомом SNI отправляет клиента на Hysteria2 masquerade, что снижает риск активного зондирования.
- **Cloudflare WARP** поднимает локальный socks5 на `127.0.0.1:40000`. Xray и Telemt используют его как единственный outbound — с точки зрения целевых сайтов запросы приходят с IP Cloudflare, а не с IP вашего VPS.

### Сетевые порты

| Порт | Протокол | Сервис | Слушает на |
| ---- | -------- | ------ | ---------- |
| 22 | TCP | SSH | внешний |
| 80 | TCP | certbot/ACME | внешний (только для renewal) |
| `$HAPROXY_PORT` (default 443) | TCP | HAProxy SNI-router | внешний |
| 443 | UDP | Hysteria2 (QUIC) | внешний |
| 8443 | TCP | Xray VLESS xHTTP | 127.0.0.1 |
| 8444 | TCP | Hysteria2 masq. | 127.0.0.1 |
| 9443 | TCP | Telemt MTProto | 127.0.0.1 |
| 7443 | TCP | Telemt API | 127.0.0.1 |
| 40000 | TCP | WARP socks5 (outbound) | 127.0.0.1 |

UFW разрешает снаружи только: 22/tcp, 80/tcp, `$HAPROXY_PORT`/tcp, 443/udp. Порт 40000 доступен исключительно с loopback.

---

## Требования

### VPS
- **OS:** Debian 11/12 или Ubuntu 22.04/24.04 (или совместимый дистрибутив с `apt` и `systemd`).
- **Архитектура:** `x86_64` или `aarch64` (Telemt релизы публикуются для обеих).
- **Минимум:** 1 vCPU / 512 MB RAM / 5 GB SSD. Для прод-нагрузки рекомендуется 2 vCPU / 2 GB RAM.
- **Сеть:** публичный IPv4 (IPv6 опционально), не за NAT (или с проброшенными портами 22, 80, 443/tcp, 443/udp).
- **Ядро:** Linux ≥ 4.9 (для BBR). На современных Ubuntu/Debian — by default.
- **Привилегии:** установка от `root`.

### Что нужно подготовить заранее
1. **Домен для Hysteria2** (например, `proxy.example.com`):
   - DNS A-запись указывает на IP VPS.
   - Проверка: `dig +short proxy.example.com` должно вернуть IP сервера.
   - Этот домен будет использован для TLS-сертификата Let's Encrypt и для masquerade.
2. **SNI для Xray Reality** — любой популярный TLS-сайт, под который маскируемся (default `github.com`). Не должен пересекаться с пунктами 1 и 3.
3. **TLS-домен для Telemt** — любой популярный сайт для fake-TLS маскировки (default `www.microsoft.com`). Не должен пересекаться с пунктами 1 и 2.
4. **Email** для Let's Encrypt (для уведомлений о просрочке сертификата).
5. **Свободный 80/tcp** на момент первой установки — нужен для HTTP-01 ACME-challenge.

### Чего НЕ должно быть
- На 80/tcp ничего не должно слушать (на момент `certbot certonly --standalone`).
- На `$HAPROXY_PORT`/tcp и 443/udp ничего не должно конфликтовать.
- Если уже установлены `xray`, `hysteria` или `haproxy` — инсталлер их переустановит/реконфигурирует.

---

## Установка

### Быстрый старт
на VPS под root
```bash
wget https://raw.githubusercontent.com/devraces/ohmyblock/refs/heads/main/ohmyblock.sh
```
делаем файл исполняемым
```bash
chmod +x ohmyblock.sh
```
запускаем
```bash
./ohmyblock.sh
```
Инсталлер задаст несколько вопросов и поднимет весь стек за 1–3 минуты.

### Что делает скрипт
1. `apt update && apt install` — ставит системные пакеты (HAProxy, certbot, jq, qrencode, ufw, openssl, gnupg и т.д.).
2. Применяет sysctl-тюнинг (`/etc/sysctl.d/99-proxy-stack.conf`): BBR, fq qdisc, расширенные UDP/TCP буферы, `somaxconn`, `fs.file-max`.
3. Закрепляет `fq` qdisc при перезагрузке через `networkd-dispatcher` (или systemd oneshot как fallback).
4. Устанавливает и настраивает **Cloudflare WARP** в режиме proxy (socks5 на `127.0.0.1:40000`).
5. Создаёт системных пользователей `xray`, `telemt`, `hysteria`.
6. Устанавливает Xray (через официальный install-release.sh), генерирует ключи Reality (x25519) и `short_id`. Xray настраивается с outbound через WARP socks5.
7. Скачивает и устанавливает Telemt бинарь. Telemt настраивается с upstream через WARP socks5.
8. Получает сертификат Let's Encrypt (`certbot certonly --standalone`) для `$HY2_DOMAIN`.
9. Копирует `fullchain.pem`/`privkey.pem` в `/etc/hysteria/certs/` (владелец `hysteria`).
10. Устанавливает Hysteria2 (через `https://get.hy2.sh/`). Hysteria2 выходит напрямую (WARP не используется — UDP-in-UDP).
11. Генерирует конфиги для всех сервисов.
12. Настраивает UFW и запускает все сервисы под systemd.
13. Создаёт CLI-утилиты в `/usr/local/bin/` (`mainuser`, `newuser`, `rmuser` и др.).
14. В конце печатает все ссылки и QR-коды для первого пользователя.

Лог установки: `/var/log/proxy-install.log`.

---

## Параметры установки

### Интерактивный режим (по умолчанию)
Скрипт спросит:

| Параметр | Default | Описание |
| -------- | ------- | -------- |
| Порт HAProxy | `443` | Внешний TCP-порт SNI-роутера |
| Порт Xray/VLESS (loopback) | `8443` | Только 127.0.0.1 |
| Порт Telemt (loopback) | `9443` | Только 127.0.0.1 |
| SNI для VLESS Reality | `github.com` | Под какой домен маскируется Reality |
| TLS-домен для Telemt | `www.microsoft.com` | Под какой домен маскируется fake-TLS |
| Домен Hysteria2 | (обязательно) | Реальный домен с A-записью на VPS |
| Email для Let's Encrypt | (обязательно) | Для уведомлений о сертификате |
| Имя первого пользователя | `main` | A-Z, 0-9, `._-`, до 32 символов |
| Публичный хост для ссылок | внешний IP VPS | Используется в URL-ссылках клиентам |

WARP устанавливается и настраивается автоматически — дополнительных параметров не требует.

### Флаги
```
./ohmyblock.sh                  # стандартная установка / upgrade
./ohmyblock.sh --reinstall      # полное пересоздание ключей и базы пользователей
./ohmyblock.sh --noninteractive # все параметры из переменных окружения
./ohmyblock.sh --help           # справка
```

### Неинтерактивная установка (CI/IaC)
```bash
HAPROXY_PORT=443 \
XRAY_PORT=8443 \
TELEMT_PORT=9443 \
XRAY_SNI=github.com \
TELEMT_TLS_DOMAIN=www.google.com \
HY2_DOMAIN=proxy.example.com \
HY2_EMAIL=admin@example.com \
PUBLIC_HOST=proxy.example.com \
FIRST_USER=main \
./ohmyblock.sh --noninteractive
```

---

## Управление

После установки в `/usr/local/bin/` доступны команды (запускать от root):

### Пользователи
| Команда | Что делает |
| ------- | ---------- |
| `newuser` | Создать нового пользователя сразу во всех сервисах |
| `rmuser` | Удалить пользователя (с подтверждением) |
| `userlist` | Показать список пользователей |
| `mainuser` | Все ссылки + QR-коды первого пользователя |
| `sharelink` | Все ссылки + QR-коды выбранного пользователя |

### Hysteria2
| Команда | Что делает |
| ------- | ---------- |
| `hy2info` | Hysteria2-ссылка + QR первого пользователя |
| `hy2list` | Список пользователей Hysteria2 |
| `hy2links` | Все Hysteria2-ссылки одной таблицей |

### Telegram / Telemt
| Команда | Что делает |
| ------- | ---------- |
| `tglink` | MTProto-ссылка (https + tg://) + QR первого пользователя |
| `telegramlinks` | Все Telegram-ссылки одной таблицей |

### Эксплуатация
| Команда | Что делает |
| ------- | ---------- |
| `proxystatus` | Статус сервисов (включая warp-svc), занятые порты, версии бинарей, статус WARP |
| `proxydiag` | Расширенная диагностика: чексумы конфигов, последние логи, sysctl, UFW |
| `proxyrenew` | Принудительное обновление LE-сертификата + рестарт hysteria |

### systemd-сервисы
```bash
systemctl status haproxy
systemctl status xray
systemctl status telemt
systemctl status hysteria-server.service
systemctl status warp-svc

systemctl restart haproxy xray telemt hysteria-server.service warp-svc

journalctl -u xray -f
journalctl -u hysteria-server.service -f
journalctl -u warp-svc -f
```

---

## Файлы и пути

### Конфиги
```
/etc/haproxy/haproxy.cfg                    # SNI-роутер
/usr/local/etc/xray/config.json             # Xray (VLESS+Reality, outbound→WARP)
/usr/local/etc/xray/.keys                   # параметры установки + ключи Reality
/usr/local/etc/proxy/users.json             # БД пользователей (источник правды)
/etc/telemt/telemt.toml                     # Telemt (upstream→WARP socks5)
/etc/hysteria/config.yaml                   # Hysteria2 (outbound напрямую)
/etc/hysteria/certs/{fullchain,privkey}.pem # копия LE-сертификата для hysteria
/etc/sysctl.d/99-proxy-stack.conf           # сетевой тюнинг
/etc/letsencrypt/live/<domain>/             # оригинальный LE-сертификат
/var/www/masq/index.html                    # страница-заглушка masquerade
/var/log/proxy-install.log                  # лог установки
```

### systemd units
```
/etc/systemd/system/telemt.service
/etc/systemd/system/hysteria-server.service
/etc/systemd/system/xray.service.d/override.conf
/etc/systemd/system/fq-qdisc.service         # (создаётся при отсутствии networkd-dispatcher)
```
`warp-svc.service` создаётся пакетом `cloudflare-warp` автоматически.

### Permissions
| Путь | Mode | Owner |
| ---- | ---- | ----- |
| `/usr/local/etc/xray/` | 750 | root:xray |
| `/usr/local/etc/xray/config.json` | 640 | root:xray |
| `/usr/local/etc/xray/.keys` | 600 | root:root |
| `/usr/local/etc/proxy/` | 700 | root:root |
| `/usr/local/etc/proxy/users.json` | 600 | root:root |
| `/etc/telemt/` | 750 | telemt:telemt |
| `/etc/telemt/telemt.toml` | 600 | telemt:telemt |
| `/etc/hysteria/` | 750 | root:hysteria |
| `/etc/hysteria/config.yaml` | 600 | hysteria:hysteria |
| `/etc/hysteria/certs/` | 750 | root:hysteria |
| `/etc/hysteria/certs/fullchain.pem` | 644 | hysteria:hysteria |
| `/etc/hysteria/certs/privkey.pem` | 600 | hysteria:hysteria |
| `/var/www/masq/` | 755 | hysteria:hysteria |

---

## Тюнинг производительности

Скрипт автоматически применяет `/etc/sysctl.d/99-proxy-stack.conf`:

```ini
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_tw_reuse = 1
fs.file-max = 1048576
```

**Что это даёт:**
- `bbr` + `fq` — современный congestion control для TCP, уменьшает задержки и увеличивает throughput на каналах с потерями. `fq` qdisc применяется немедленно при установке и закрепляется при перезагрузке.
- `rmem_max`/`wmem_max = 16 MB` — большие сокет-буферы, критично для **Hysteria2/QUIC** на каналах с высоким BDP.
- `somaxconn = 4096`, `tcp_max_syn_backlog = 4096`, `fs.file-max = 1M` — выдерживает тысячи одновременных соединений.
- `tcp_fastopen = 3` — TFO для клиентов и серверов (уменьшает RTT при handshake).

**HAProxy:**
- `nbthread` = числу vCPU — использует все ядра автоматически.
- `option splice-auto` per-backend — kernel splice для TCP-relay.
- `maxconn 65536`, `timeout client/server/tunnel = 1h` для long-lived xHTTP-сессий.
- Не-TLS трафик отклоняется на уровне `tcp-request content reject`.

**Hysteria2:**
- `congestion: bbr`, `bbrProfile: standard`.
- QUIC окна: `maxStreamReceiveWindow = 8 MB`, `maxConnReceiveWindow = 20 MB`.
- `sniff: enable` для DPI-обработки IP-only клиентов.

**WARP:**
- WARP работает через WireGuard (UDP), поэтому Hysteria2 (тоже UDP) намеренно не направляется через него — вложенный UDP нестабилен.
- Xray и Telemt используют WARP через TCP CONNECT — это прозрачно и стабильно.
- WARP socks5 поддерживает только команду `CONNECT` (TCP). UDP-команды (`CommandNotSupported`) отклоняются — это нормально, весь нужный трафик TCP.

---

## Безопасность

### Изоляция сервисов
- **Telemt** работает под пользователем `telemt` с `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=true`, ограниченным `RestrictAddressFamilies`. Исходящий трафик к Telegram идёт через WARP — IP сервера скрыт.
- **Hysteria2** работает под пользователем `hysteria` с теми же sandboxing-опциями + `CAP_NET_BIND_SERVICE` для bind на 443/udp.
- **Xray** работает под пользователем `xray` с `LimitNOFILE=1048576`. Жёсткий sandbox намеренно не включён, чтобы не ломать загрузку geoip/geosite датабаз. Исходящий трафик идёт через WARP — IP сервера скрыт.
- **HAProxy** работает под собственным пользователем `haproxy:haproxy`.
- **WARP (warp-svc)** работает от root (требование пакета Cloudflare), слушает только `127.0.0.1:40000`.

### Что даёт WARP с точки зрения безопасности
- Целевые сайты видят IP Cloudflare, а не IP вашего VPS — усложняет корреляцию трафика.
- Трафик между VPS и Cloudflare зашифрован через WireGuard.
- Бесплатный аккаунт WARP не требует регистрации личных данных.

### Доступы и секреты
- `/usr/local/etc/proxy/users.json` (UUID, пароли Hysteria2, MTProto-секреты) — `600 root:root`.
- `/usr/local/etc/xray/.keys` (приватный ключ Reality) — `600 root:root`.
- `/etc/hysteria/certs/privkey.pem` — `600 hysteria:hysteria`.
- Ни один CLI-инструмент не выводит секреты в журнал/stdout без явного запроса.

### Атомарность изменений
- Все модификации `users.json` происходят под `flock` — гонки между параллельными `newuser`/`rmuser` исключены.
- HAProxy конфиг проверяется через `haproxy -c -f` ДО `systemctl restart`. При невалидной конфигурации выполняется автооткат к последнему бэкапу.

### Бэкапы
- При каждом запуске `ohmyblock.sh` бэкапятся `.keys`, `users.json`, `haproxy.cfg` (хранятся последние 5 версий).
- Файлы `*.bak.<timestamp>` лежат рядом с оригиналами.

### Firewall
UFW настроен на whitelist:
```
22/tcp                SSH
80/tcp                ACME (certbot renew)
$HAPROXY_PORT/tcp     HAProxy SNI router
443/udp               Hysteria2 QUIC
```
Всё остальное — DROP. Порт WARP (40000) закрыт снаружи — доступен только с loopback.

---

## Обновление сертификатов

certbot.timer запускается по расписанию (1–2 раза в день). При успешном обновлении:
1. Срабатывает `/etc/letsencrypt/renewal-hooks/deploy/99-hysteria-restart.sh`.
2. Хук копирует свежие `fullchain.pem`/`privkey.pem` из `$RENEWED_LINEAGE` в `/etc/hysteria/certs/` (с владельцем `hysteria:hysteria`, правильные mode).
3. Делает `systemctl restart hysteria-server.service`.

Принудительное обновление:
```bash
proxyrenew    # certbot renew --force-renewal + рестарт hysteria
```

Проверить, что renewal будет работать (без реального обновления):
```bash
certbot renew --dry-run
```

> **Важно:** для обновления сертификата нужен свободный 80/tcp. UFW его уже открывает. Если в момент renewal что-то слушает 80 — обновление упадёт.

---

## Диагностика и устранение неполадок

### Стандартный workflow
```bash
proxystatus        # быстрый чек: все сервисы active? статус WARP?
proxydiag          # подробно: логи, чексумы конфигов, sysctl, UFW
journalctl -u <service> -n 100 --no-pager
```

### Типовые проблемы

**HAProxy не стартует**
```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
journalctl -u haproxy -n 50
```
Если конфиг битый — `ohmyblock.sh` сам откатит на последний бэкап. Если автоматически не откатил, см. `/etc/haproxy/haproxy.cfg.bak.*`.

**Xray не стартует**
```bash
journalctl -u xray -n 100
xray -test -config /usr/local/etc/xray/config.json
```
Самые частые причины: занят 8443/tcp, кривой `xray_private_key` в `.keys` (только при `--reinstall`), не запущен warp-svc (outbound недоступен).

**Hysteria2 не стартует**
```bash
journalctl -u hysteria-server.service -n 100
ls -la /etc/hysteria/certs/
```
Если в логах `permission denied: /etc/hysteria/certs/...`:
```bash
chown -R hysteria:hysteria /etc/hysteria/certs
chmod 600 /etc/hysteria/certs/privkey.pem
chmod 644 /etc/hysteria/certs/fullchain.pem
chmod 750 /etc/hysteria /etc/hysteria/certs
chown root:hysteria /etc/hysteria /etc/hysteria/certs
systemctl restart hysteria-server.service
```

**Telemt не стартует**
```bash
journalctl -u telemt -n 100
/bin/telemt /etc/telemt/telemt.toml --help
```
Часто помогает: `chown -R telemt:telemt /etc/telemt /opt/telemt`.

**WARP не работает / низкая скорость**
```bash
# Статус подключения
warp-cli --accept-tos status

# Проверить что socks5 слушает
ss -tlnp | grep ':40000'

# Проверить IP через WARP (должен отличаться от IP сервера)
curl --proxy socks5://127.0.0.1:40000 -s http://ifconfig.me
curl -s https://ifconfig.me   # прямой IP для сравнения

# Логи
journalctl -u warp-svc -n 50
```

Если WARP не подключён после установки:
```bash
warp-cli --accept-tos mode proxy
warp-cli --accept-tos proxy port 40000
warp-cli --accept-tos connect
```

> **Примечание:** ошибки вида `SOCKS5 Protocol Error: CommandNotSupported` в логах warp-svc — это норма. WARP socks5 поддерживает только `CONNECT` (TCP). Xray и Telemt используют только TCP, поэтому трафик проходит корректно.

> **Примечание:** ошибки `sni guard: x509: cannot validate certificate for 127.0.0.1` в логах hysteria — это HAProxy health-check стучится по IP. Они не влияют на работу клиентов и безвредны.

**certbot падает на первом запуске**
- Проверь, что DNS `$HY2_DOMAIN` указывает на VPS: `dig +short $HY2_DOMAIN`.
- Проверь, что 80/tcp свободен: `ss -ltn | grep ':80'`.
- Проверь rate-limit Let's Encrypt (5 неудач/час, 50 успешных/неделю на домен).

**Клиент не подключается через VLESS Reality**
- Убедись, что `$XRAY_SNI` — популярный сайт с TLS 1.3 + h2 (X25519). Хорошие варианты: `github.com`, `cloudflare.com`, `microsoft.com`.
- В клиенте: `fingerprint=firefox` (или `chrome`), `flow` пустой, `mode=auto`.
- Проверь, что warp-svc запущен: `systemctl is-active warp-svc`.

**Клиент не подключается через Hysteria2**
- Проверь, что 443/udp реально проходит до сервера: `nc -u -z -v $HY2_DOMAIN 443`.
- На некоторых хостингах UDP режется — нужно у саппорта запросить открытие.
- Hysteria2 работает без WARP — это ожидаемо.

**Клиент подключается, но скорость низкая**

Проверь throughput WARP (должен быть сопоставим с прямым каналом):
```bash
# Скорость через WARP (HTTP, TCP)
curl --proxy socks5://127.0.0.1:40000 \
  -o /dev/null -s \
  --write-out "Speed: %{speed_download} bytes/sec\n" \
  http://speed.cloudflare.com/__down?bytes=10000000

# Прямая скорость сервера
speedtest-cli --simple 2>/dev/null || \
  curl -o /dev/null -s \
  --write-out "Direct: %{speed_download} bytes/sec\n" \
  http://speed.cloudflare.com/__down?bytes=10000000
```
Если WARP значительно медленнее прямого канала — попробуй переподключить: `warp-cli --accept-tos disconnect && warp-cli --accept-tos connect`.

---

## Идемпотентность и обновление

Скрипт можно запускать повторно сколько угодно раз.

### Без `--reinstall` (default)
- Существующие `.keys` и `users.json` **сохраняются** — все ранее розданные ссылки клиентам продолжают работать.
- Конфиги пересоздаются из текущего состояния.
- WARP проверяется: если уже зарегистрирован — повторная регистрация не выполняется.
- Параметры можно частично переопределить (новый домен, новый SNI и т.п.).

### С `--reinstall`
- Полностью пересоздаются ключи Reality и `users.json` (со старым бэкапом рядом).
- **Все ранее розданные ссылки клиентам станут невалидны.**
- Используй только для полного сброса.

### Добавление нового пользователя
```bash
newuser
# имя: alice
# вывод: VLESS-ссылка, Hysteria2-ссылка, Telegram-ссылки + QR-коды
```
Все три сервиса (Xray, Telemt, Hysteria2) перезапускаются автоматически (downtime < 1 секунды). warp-svc не перезапускается — он не зависит от списка пользователей.

---

## Удаление

Полная деинсталляция:
```bash
# Сервисы
systemctl disable --now hysteria-server.service telemt xray haproxy warp-svc
rm -f /etc/systemd/system/{telemt.service,hysteria-server.service,fq-qdisc.service}
rm -rf /etc/systemd/system/xray.service.d
rm -f /etc/networkd-dispatcher/routable.d/50-fq-qdisc
systemctl daemon-reload

# Бинари
bash -c "$(curl -fsSL https://get.hy2.sh/)" -- --remove
bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove
rm -f /bin/telemt

# WARP
apt purge -y cloudflare-warp
rm -f /etc/apt/sources.list.d/cloudflare-client.list
rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

# Конфиги, ключи, пользователи
rm -rf /usr/local/etc/xray /usr/local/etc/proxy
rm -rf /etc/telemt /etc/hysteria /var/www/masq
rm -f /etc/sysctl.d/99-proxy-stack.conf
rm -f /etc/letsencrypt/renewal-hooks/deploy/99-hysteria-restart.sh

# CLI-команды
rm -f /usr/local/bin/{mainuser,userlist,newuser,rmuser,sharelink}
rm -f /usr/local/bin/{hy2info,hy2list,hy2links,tglink,telegramlinks}
rm -f /usr/local/bin/{proxystatus,proxydiag,proxyrenew}
rm -f /usr/local/lib/proxy-common.sh
rm -f /root/help

# Системные пользователи
userdel -r telemt 2>/dev/null
userdel -r hysteria 2>/dev/null
userdel -r xray 2>/dev/null

# LE-сертификат (опционально)
certbot delete --cert-name <HY2_DOMAIN>

# Применить sysctl-default обратно (опционально)
sysctl --system

# Вычистить apt-зависимости (опционально)
apt purge -y haproxy certbot
```

---

## FAQ

**Можно ли использовать порт, отличный от 443, для HAProxy?**
Да: `HAPROXY_PORT=8443 ./ohmyblock.sh --noninteractive`. Но Reality + HTTPS-маскировка наиболее правдоподобны именно на 443. Hysteria2 всегда занимает UDP/443.

**Почему Hysteria2 не идёт через WARP?**
Hysteria2 использует QUIC (UDP), а WARP сам работает поверх WireGuard (тоже UDP). Вложенный UDP ненадёжен — потери пакетов умножаются, и скорость деградирует. Поэтому Hysteria2 выходит в интернет напрямую.

**Можно ли использовать WARP+ (платный) вместо бесплатного WARP?**
Да. После установки: `warp-cli --accept-tos registration license <ваш-ключ>` — скорость и приоритет улучшатся.

**Меняет ли WARP IP для всего трафика сервера?**
Нет. WARP в режиме proxy (socks5) меняет IP только для трафика, явно направленного через него — то есть для Xray и Telemt. SSH, Hysteria2, сам VPS остаются на прямом IP.

**Можно ли разместить за CDN (Cloudflare и т.п.)?**
- Hysteria2 (UDP) — нет, CDN-ы не проксируют UDP.
- VLESS xHTTP + Reality — Reality несовместим с проксированием через CDN.
- Telemt — нет.

**Сколько пользователей выдержит одна VPS?**
На 2 vCPU / 2 GB RAM — спокойно 100–500 одновременных клиентов с обычным веб-трафиком. Узкое место обычно в bandwidth канала, а не в CPU.

**Можно ли использовать самоподписанный сертификат для Hysteria2?**
Технически да (если на клиенте `insecure=1`), но это палится при пассивном анализе TLS. Для prod — только LE.

**Где лежит лог установки?**
`/var/log/proxy-install.log` — содержит всё, что выводилось во время `ohmyblock.sh`.

**Что делать после reboot?**
Ничего. Все сервисы под systemd с `WantedBy=multi-user.target` — стартуют автоматически. fq qdisc восстанавливается через networkd-dispatcher или systemd oneshot.

**Как выгрузить ссылки всех пользователей одним списком?**
```bash
userlist
hy2links
telegramlinks
# для VLESS:
for u in $(jq -r '.users[].name' /usr/local/etc/proxy/users.json); do
  source /usr/local/lib/proxy-common.sh
  echo "$u -> $(xray_link_for "$u")"
done
```

**Как мигрировать на другую VPS?**
1. На старой машине: `tar czf backup.tgz /usr/local/etc/xray /usr/local/etc/proxy /etc/letsencrypt /etc/hysteria/certs`.
2. На новой: установи `ohmyblock.sh` с теми же доменами/SNI, ОСТАНОВИ сервисы, разверни архив, запусти `ohmyblock.sh` повторно (без `--reinstall`).
3. WARP на новой машине зарегистрируется автоматически — дополнительных действий не нужно.
Все клиентские ссылки продолжат работать.

---

## Лицензия и атрибуция

Стек собран из open-source проектов:
- [Xray-core](https://github.com/XTLS/Xray-core)
- [Hysteria2](https://github.com/apernet/hysteria)
- [Telemt](https://github.com/telemt/telemt)
- [HAProxy](https://www.haproxy.org/)
- [certbot](https://certbot.eff.org/)
- [Cloudflare WARP](https://developers.cloudflare.com/warp-client/get-started/linux/)

Сам инсталлер можно использовать и модифицировать свободно.
