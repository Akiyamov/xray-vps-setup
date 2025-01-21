<h1 align="center">VLESS + Reality Self Steal в Docker</h2>

### Что потребуется:
- VPS 
- Свой домен

В статье будет рассмотрена установка как чистого Xray, так и Marzban.  

## Настройка сервера

### Настройка SSH

На своем ПК, неважно, GNU/Linux или Windows. __На Windows используйте Powershell__. Открываем терминал и выполняем следующую команду:
```bash
ssh-keygen -t ed25519
```
После выполнения команды вам предложат изменить место хранения ключа и добавить пароль к нему. Менять локацию не надо, пароль же можете добавить ради безопасности.
Создав ключ, вам будет выведена локация публичной и приватной его части, нам нужно перекинуть публичную часть этого ключа на нашу VPS.  
На Linux:
```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub ваш_пользователь@ваша_vps
```
На Windows:
```powershell
ssh-copy-id -i $env:USERPROFILE\.ssh\id_ed25519.pub ваш_пользователь@ваша_vps
```
Если данная команда у вас не сработала на Windows, то нужно выполнить следующую:
```powershell
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh ваш_пользователь@ваша_vps "cat >> .ssh/authorized_keys"
```
__Далее все делается на VPS.__  
Для отключения входа по паролю выполняем следующую команду:
```bash
grep -r PasswordAuthentication /etc/ssh -l | xargs -n 1 sed -i -e "/PasswordAuthentication /c\PasswordAuthentication no"
```
Сделав это можно перезапустить SSH. 
```bash
sudo systemctl restart ssh
```

### Настройки iptables
Нам нужно оставить открытыми порты для SSH, 80(HTTP) и 443(HTTPS).
Для этого нужно выполнить следующие команды:
```bash
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT 
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -P INPUT DROP
iptables-save > /etc/network/iptables.rules
```

### Включение BBR
Достаточно выполнить следующие команды:
```bash
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
```

## Создание прокси

### Установка Docker
Для установки нужно выполнить следующую команду:
```bash
bash <(wget -qO- https://get.docker.com) @ -o get-docker.sh
```
Если вы работаете не от админа, то выполните следующие команды, чтобы не писать `sudo` каждый раз:
```bash
sudo groupadd docker
sudo usermod -aG docker $USER
```

### Получение данных для прокси
В этой части будут описаны необходимые данные, а также способ их получения. Позже эти данные будут использованы в конфигурации.  
- __VLESS_DOMAIN__: Ваш домен. Если используется punycode, то далее используется ТОЛЬКО на латинице.  
- __XRAY_PBK+PIK__: `docker run --rm ghcr.io/xtls/xray-core x25519`
Оба значения для нас важны, Public key = PBK, Private key = PIK.  
- __XRAY_SID__: `openssl rand -hex 8`
Short id, используется для различения разных клиентов  

Следующие данные нужны только если вы будете устанавливать панель Marzban.  
- __MARZBAN_USER__: `tr -dc A-Za-z0-9 </dev/urandom | head -c 8; echo`  
Пользователь панели  
- __MARZBAN_PASS__: `tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo`  
Пароль пользователя панели  
- __MARZBAN_PATH__: `openssl rand -hex 8`  
URL панели  
- __MARZBAN_SUB_PATH__: `openssl rand -hex 8`  
URL подписок  

### Настройка прокси
Создадим папку `/opt/xray-vps-setup` командой `mkdir -p /opt/xray-vpx-setup`.  
После этого переходим в папку и создаем в ней файл `docker-compose.yml`  

<details>
  <summary>Marzban</summary>  

```yaml
services:
  caddy:
    image: caddy:2.9
    restart: always
    network_mode: host
    volumes:
      - ./caddy/data:/data
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile
      - ./marzban_lib:/run/marzban
  marzban:
    image: gozargah/marzban:v0.8.4
    restart: always
    env_file: ./marzban/.env
    network_mode: host
    volumes:
      - ./marzban_lib:/var/lib/marzban
      - ./marzban/xray_config.json:/code/xray_config.json
      - ./marzban/templates:/var/lib/marzban/templates
```  
</details>
<details>
  <summary>Xray</summary>  

```yaml
services:
  caddy:
    image: caddy:2.9
    restart: always
    network_mode: host
    volumes:
      - ./caddy/data:/data
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile
      - ./caddy/templates:/srv
  xray:
    image: ghcr.io/xtls/xray-core:25.1.1
    restart: always
    network_mode: host
    volumes:
      - ./xray:/etc/xray
```  
</details>
Создаем папку `/opt/xray-vpx-setup/caddy` и в ней создаем файл `Caddyfile` и меняем его следующим образом.  
<details><summary>Marzban</summary>

```yaml
{
        https_port 4123
        default_bind 127.0.0.1
        servers {
                listener_wrappers {
                        proxy_protocol {
                                allow 127.0.0.1/32
                        }
                        tls
                }
        }
        auto_https disable_redirects
}
https://$VLESS_DOMAIN { 
        reverse_proxy * unix//run/marzban/marzban.socket
}
http://$VLESS_DOMAIN {
        bind 0.0.0.0
        redir https://$VLESS_DOMAIN{uri} permanent
}
:4123 {
        tls internal
        respond 204
}
:80 {
        bind 0.0.0.0
        respond 204
}
```

</details>
<details><summary>Чистый Xray</summary>

```yaml
{
        https_port 4123
        default_bind 127.0.0.1
        servers {
                listener_wrappers {
                        proxy_protocol {
                                allow 127.0.0.1/32
                        }
                        tls
                }
        }
        auto_https disable_redirects
}
https://$VLESS_DOMAIN {
        root * /srv
        file_server
}
http://$VLESS_DOMAIN {
        bind 0.0.0.0
        redir https://$VLESS_DOMAIN{uri} permanent
}
:4123 {
        tls internal
        respond 204
}
:80 {
        bind 0.0.0.0
        respond 204
}
```

</details>
Настроив caddy требуется добавить страницу для маскировки. Для xray и marzban команды отличаются:  
Xray  

```bash
wget -qO- https://raw.githubusercontent.com/Jolymmiles/confluence-marzban-home/main/index.html  | envsubst > /opt/xray-vps-setup/caddy/templates/index.html
```
Marzban
```bash
wget -qO- https://raw.githubusercontent.com/Jolymmiles/confluence-marzban-home/main/index.html  | envsubst > /opt/xray-vps-setup/marzban/templates/home/index.html
```

После этого надо создать файл конфигурации Xray, если вы ставите marzban, то он будет находится в `/opt/xray-vps-setup/marzban/xray_config.json`, если чистый xray, то `/opt/xray-vps-setup/xray/config.json`  

```json
{
  "log": {
    "loglevel": "debug"
  },
  "inbounds": [
    {
      "tag": "VLESS TCP VISION REALITY",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "XRAY_UUDI", // ПОМЕНЯТЬ НА СВОЕ
            "email": "default",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "xver": 1,
          "dest": "127.0.0.1:4123",
          "serverNames": [
            "VLESS_DOMAIN" // ПОМЕНЯТЬ НА СВОЕ
          ],
          "privateKey": "XRAY_PIK", // ПОМЕНЯТЬ НА СВОЕ
          "shortIds": [
            "XRAY_SID" // ПОМЕНЯТЬ НА СВОЕ
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "routeOnly": true
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct",
      "settings": {
        "domainStrategy": "UseIPv4"
      }
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "routing": {
    "rules": [
      {
        "protocol": "bittorrent",
        "outboundTag": "block"
      }
    ],
    "domainStrategy": "IPIfNonMatch"
  },
  "dns": {
    "servers": [
      "1.1.1.1",
      "8.8.8.8"
    ],
    "queryStrategy": "UseIPv4",
    "disableFallback": false,
    "tag": "dns-aux"
  }
}
```

Для Marzban необходимо также добавить `.env` файл. Создайте файл `/opt/xray-vps-setup/marzban/.env` и вставьте следующее: 
```
SUDO_USERNAME = "xray_admin"
SUDO_PASSWORD = "$MARZBAN_PASS"
UVICORN_UDS = "/var/lib/marzban/marzban.socket"
DASHBOARD_PATH = "/$MARZBAN_PATH/"
XRAY_JSON = "xray_config.json"
XRAY_SUBSCRIPTION_URL_PREFIX = "https://$VLESS_DOMAIN"
XRAY_SUBSCRIPTION_PATH = "$MARZBAN_SUB_PATH"
SQLALCHEMY_DATABASE_URL = "sqlite:////var/lib/marzban/db.sqlite3"
CUSTOM_TEMPLATES_DIRECTORY="/var/lib/marzban/templates/"
SUBSCRIPTION_PAGE_TEMPLATE="subscription/index.html"
HOME_PAGE_TEMPLATE="home/index.html"
```

## Настройка WARP

Для того, чтобы доабвить WARP для того, чтобы в Россию наш юзер ходил черзе него, то надо сделать следующее.  
Устанавливаем WARP:
```bash
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
apt update 
apt install cloudflare-warp -y
```
Настроим WARP:
```bash
warp-cli registration new
warp-cli mode proxy
warp-cli proxy port 40000
warp-cli connect
```
Если на этом этапе ловим ошибку подключения, то не продолжайте, WARP не рабоатет.  
Установка `yq`:
```bash
wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && chmod +x /usr/bin/yq
```
Далее с помощью `yq` мы установим в уже существующий кофниг WARP:
```bash
yq eval '.outbounds[.outbounds | length ] |= . + {"tag": "warp","protocol": "socks","settings": {"servers": [{"address": "127.0.0.1","port": 40000}]}}' -i $XRAY_CONFIG_WARP
yq eval '.routing.rules[.routing.rules | length ] |= . + {"outboundTag": "warp", "domain": ["geosite:category-ru"]}' -i $XRAY_CONFIG_WARP

```
Заменяем $XRAY_CONFIG_WARP на `/opt/xray-vps-setup/marzban/xray_config.json` для marzban и на `/opt/xray-vps-setup/xray/config.json` для чистого xray. После этого перезапускаем все:
```bash
docker compose -f /opt/xray-vps-setup/docker-compose.yml down && docker compose -f /opt/xray-vps-setup/docker-compose.yml up -d
```

#

Если вы хотите помочь что-то исправить, добавить и тд, то делайте PR или пишите в [ТГ](https://t.me/Akiyamov).