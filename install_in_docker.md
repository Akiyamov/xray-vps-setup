<h1 align="center">VLESS + Reality Self Steal в Docker</h2>

### Что потребуется:
- VPS хотя бы на 1 гигабайт
- Свой домен

В статье будет рассмотрена установка как чистого XRay, так и Marzban.  

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
После того, как мы добавили ключ пользователю, можно запретить вход по паролю на систему. Для этого в файле `/etc/ssh/sshd_config` нужно найти строчку `PasswordAuthentication` и поменять ее на `PasswordAuthentication no`. Если стоит `#` перед строкой, то надо убрать.
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
<details><summary>Marzban</summary>
```yaml
services:
  caddy:
    image: caddy:2.9
    restart: always
    network_mode: host
    volumes:
      - ./caddy/data:/data
      - ./caddy/Caddyfile:/etc/caddy/Caddyfile
      - ./marzban/run:/var/lib/marzban
  marzban:
    image: gozargah/marzban:v0.7.0
    restart: always
    env_file: ./marzban/.env
    network_mode: host
    volumes:
      - ./marzban/run:/var/lib/marzban
      - ./marzban/xray_config.json:/code/xray_config.json
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
        reverse_proxy http://127.0.0.1:8000
}
:4123 {
        tls internal {
                on_demand
        }
        respond 204
}
:80 {
        bind 0.0.0.0
        respond 204
}
http://$VLESS_DOMAIN {
        bind 0.0.0.0
        redir https://$VLESS_DOMAIN{uri} permanent
}
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
        basic_auth * {
          xray_user $CADDY_BASIC_AUTH
        }
        file_server browse"
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
После этого надо создать файл конфигурации XRay, если вы ставите marzban, то он будет находится в `/opt/xray-vps-setup/marzban/xray_config.json`, если чистый xray, то `/opt/xray-vps-setup/xray/config.json`
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
            "id": "d2dcb7f6-2c14-4f4a-bae6-ecd9aff7dafd",
            "email": "default",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "xver": 1,
          "dest": "127.0.0.1:4123",
          "serverNames": [
            "xn--80aqgfvid.xn-----6kc7awhbxbfs.xn--p1ai",
            "xn--2-7sbyihzje.xn-----6kc7awhbxbfs.xn--p1ai"
          ],
          "privateKey": "kJJJyalL0SVoM8CW9sPc-u3ZBhxMC8aGHGp6vaCIRCQ",
          "shortIds": [
            "f17ce893777a0d11"
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
        "protocol": "bittorrent"
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