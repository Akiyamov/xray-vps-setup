#/bin/bash

set -e

# For development and testing, getting from env without not change in the code
if [[ -z $GIT_USER ]]; then
    GIT_USER="Akiyamov"
fi

export GIT_BRANCH="main"
export GIT_REPO="$GIT_USER/xray-vps-setup"

# Check if script started as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Fetch IP address from ifconfig.io API
NODE_IP_V4=$(curl -s -4 --fail --max-time 5 ifconfig.io 2>/dev/null || echo "")
NODE_IP_V6=$(curl -s -6 --fail --max-time 5 ifconfig.io 2>/dev/null || echo "")

pasarguard_auto_configuring() {
    CREATED_AT=$(date +"%Y-%m-%d %H:%M:%S.%6N")
    HASHED_PASS=$(docker run --rm epicsoft/bcrypt hash $PASARGUARD_PASS 12 2>/dev/null | tail -n1)
    SOCKET_PATH="/opt/xray-vps-setup/pasarguard_lib/pasarguard.socket"
    DATABASE_PATH="/opt/xray-vps-setup/pasarguard_lib/db.sqlite3"
    TIMEOUT=60
    INTERVAL=1

    apt install -y sqlite3 socat
    i=0
    echo "⏳ Waiting for the PasarGuard socket to be ready..."
    while [ $i -lt $TIMEOUT ]; do
        if timeout 1 socat -v UNIX-CONNECT:"$SOCKET_PATH" /dev/null >/dev/null 2>&1; then
            echo "✅ The PasarGuard socket is ready, the setup continues."
            socket_ready=true
            break
        fi
        sleep $INTERVAL
        i=$((i + INTERVAL))
    done
    if [ $socket_ready == false ]; then
        echo "❌ The PasarGuard socket is not running."
        exit 1
    fi

    xray_cfg=$(cat /opt/xray-vps-setup/pasarguard/xray_config.json)
    SSL_CA=$(cat $SSL_CERT_FILE)
    SAFE_JSON="${xray_cfg//\'/''}"
    sqlite3 "$DATABASE_PATH" <<SQL
    BEGIN;
    UPDATE core_configs SET config = '$SAFE_JSON' WHERE id = 1;
    INSERT INTO admins (username, hashed_password, created_at, is_sudo)
        VALUES ('xray_admin', '$HASHED_PASS', '$CREATED_AT', 1);
    UPDATE inbounds SET tag = 'VLESS TCP VISION REALITY' WHERE id = 1;
    INSERT INTO hosts (remark, address, inbound_tag, security, alpn, is_disabled, priority, status)
        VALUES ('{USERNAME}', '$VLESS_DOMAIN,$SERVER_IP', 'VLESS TCP VISION REALITY', 'inbound_default', 'h2,http/1.1', '0', '0', 'active');
    INSERT INTO groups (name, is_disabled) VALUES ('VLESS', '0');
    INSERT INTO inbounds_groups_association (inbound_id, group_id) VALUES ('1', '1');
    INSERT INTO nodes (name, address, port, status, created_at, uplink, downlink, connection_type, server_ca, core_config_id, api_key)
        VALUES ('Local', '127.0.0.1', '62050', 'connecting', '$CREATED_AT', '0', '0', 'grpc', '$SSL_CA', '1', '$PASARGUARD_NODE_API_KEY');
    UPDATE settings SET general = '{"default_flow": "xtls-rprx-vision", "default_method": "chacha20-ietf-poly1305"}';
    COMMIT;
SQL

    docker rmi epicsoft/bcrypt
    docker compose -f /opt/xray-vps-setup/docker-compose.yml restart
}

gen_self_signed_cert() {
    local san_entries=("DNS:localhost" "IP:127.0.0.1")

    # Add IPv4 if it exists
    if [ -n "$NODE_IP_V4" ]; then
        san_entries+=("IP:$NODE_IP_V4")
    fi

    # Add IPv6 if it exists
    if [ -n "$NODE_IP_V6" ]; then
        san_entries+=("IP:$NODE_IP_V6")
    fi
    extra_san=""
    if [[ -n "$extra_san" ]]; then
        IFS=',' read -ra user_entries <<<"$extra_san"
        san_entries+=("${user_entries[@]}")
    fi

    # Join SAN entries into a comma-separated string and remove duplicates
    local san_string
    san_string=$(printf '%s\n' "${san_entries[@]}" | sort -u | paste -sd, -)

    openssl req -x509 -newkey rsa:4096 -keyout "$SSL_KEY_FILE" \
        -out "$SSL_CERT_FILE" -days 36500 -nodes \
        -subj "/CN=$NODE_IP" \
        -addext "subjectAltName = $san_string" >/dev/null 2>&1

}

# Install idn
apt-get update
apt-get install idn dnsutils sudo -y

# Read domain input
read -ep "Enter your domain:"$'\n' input_domain

export VLESS_DOMAIN=$(echo $input_domain | idn)

SERVER_IPS=($(hostname -I))

RESOLVED_IP=$(dig +short $VLESS_DOMAIN | tail -n1)

if [ -z "$RESOLVED_IP" ]; then
    echo "Warning: Domain has no DNS record"
    read -ep "Are you sure? That domain has no DNS record. If you didn't add that you will have to restart xray and caddy by yourself [y/N]"$'\n' prompt_response
    if [[ "$prompt_response" =~ ^([yY])$ ]]; then
        echo "Ok, proceeding without DNS verification"
    else
        echo "Come back later"
        exit 1
    fi
else
    MATCH_FOUND=false
    for server_ip in "${SERVER_IPS[@]}"; do
        if [ "$RESOLVED_IP" == "$server_ip" ]; then
            MATCH_FOUND=true
            break
        fi
    done

    if [ "$MATCH_FOUND" = true ]; then
        echo "✓ DNS record points to this server ($RESOLVED_IP)"
    else
        echo "Warning: DNS record exists but points to different IP"
        echo "  Domain resolves to: $RESOLVED_IP"
        echo "  This server's IPs: ${SERVER_IPS[*]}"
        read -ep "Continue anyway? [y/N]"$'\n' prompt_response
        if [[ "$prompt_response" =~ ^([yY])$ ]]; then
            echo "Ok, proceeding"
        else
            echo "Come back later"
            exit 1
        fi
    fi
fi

read -ep "Do you want to install web-panel? [y/N] "$'\n' panel_input
if [[ "${panel_input,,}" == "y" ]]; then
    select panel in pasarguard marzban; do
        case $panel in
        "pasarguard")
            panel_input="pasarguard"
            break
            ;;
        "marzban")
            panel_input="marzban"
            break
            ;;
        *)
            echo "Invalid selection. Please choose 1 or 2."
            ;;
        esac
    done
fi

read -ep "Do you want to configure server security? Do this on first run only. [y/N] "$'\n' configure_ssh_input
if [[ ${configure_ssh_input,,} == "y" ]]; then
    # Read SSH port
    read -ep "Enter SSH port. Default 22, can't use ports: 80, 443 and 4123:"$'\n' input_ssh_port

    while [[ "$input_ssh_port" -eq "80" || "$input_ssh_port" -eq "443" || "$input_ssh_port" -eq "4123" ]]; do
        read -ep "No, ssh can't use $input_ssh_port as port, write again:"$'\n' input_ssh_port
    done
    # Read SSH Pubkey
    read -ep "Enter SSH public key:"$'\n' input_ssh_pbk
    echo "$input_ssh_pbk" >./test_pbk
    ssh-keygen -l -f ./test_pbk
    PBK_STATUS=$(echo $?)
    if [ "$PBK_STATUS" -eq 255 ]; then
        echo "Can't verify the public key. Try again and make sure to include 'ssh-rsa' or 'ssh-ed25519' followed by 'user@pcname' at the end of the file."
        exit
    fi
    rm ./test_pbk
fi

read -ep "Do you want to install WARP and use it on russian websites? [y/N] "$'\n' configure_warp_input
if [[ ${configure_warp_input,,} == "y" ]]; then
    if ! curl -I https://api.cloudflareclient.com --connect-timeout 10 >/dev/null 2>&1; then
        echo "Warp can't be used"
        configure_warp_input="n"
    fi
fi

# Check congestion protocol
if sysctl net.ipv4.tcp_congestion_control | grep bbr; then
    echo "BBR is already used"
else
    echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
    sysctl -p >/dev/null
    echo "Enabled BBR"
fi

export ARCH=$(dpkg --print-architecture)

yq_install() {
    wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_$ARCH -O /usr/bin/yq && chmod +x /usr/bin/yq
}

yq_install

docker_install() {
    bash <(wget -qO- https://get.docker.com) @ -o get-docker.sh
}

if ! command -v docker 2>&1 >/dev/null; then
    docker_install
fi

# Generate values for XRay
export SSH_USER=$(
    tr -dc A-Za-z0-9 </dev/urandom | head -c 8
    echo
)
export SSH_USER_PASS=$(
    tr -dc A-Za-z0-9 </dev/urandom | head -c 13
    echo
)
export SSH_PORT=${input_ssh_port:-22}
export ROOT_LOGIN="yes"
export IP_CADDY=$(hostname -I | cut -d' ' -f1)
export CADDY_BASIC_AUTH=$(docker run --rm caddy caddy hash-password --plaintext $SSH_USER_PASS)
export XRAY_PIK=$(docker run --rm ghcr.io/xtls/xray-core x25519 | head -n1 | cut -d' ' -f 2)
export XRAY_PBK=$(docker run --rm ghcr.io/xtls/xray-core x25519 -i $XRAY_PIK | tail -2 | head -1 | cut -d' ' -f 2)
export XRAY_SID=$(openssl rand -hex 8)
export XRAY_UUID=$(docker run --rm ghcr.io/xtls/xray-core uuid)
export XRAY_CFG="/usr/local/etc/xray/config.json"

# Install marzban
xray_setup() {
    mkdir -p /opt/xray-vps-setup
    cd /opt/xray-vps-setup
    if [[ "${panel_input,,}" == "pasarguard" ]]; then
        export PASARGUARD_PASS=$(
            tr -dc A-Za-z0-9 </dev/urandom | head -c 13
            echo
        )
        export PASARGUARD_PATH=$(openssl rand -hex 8)
        export PASARGUARD_SUB_PATH=$(openssl rand -hex 8)
        export PASARGUARD_NODE_API_KEY=$(cat /proc/sys/kernel/random/uuid)
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose | envsubst >./docker-compose.yml
        yq eval \
            '.services.pasarguard.image = "pasarguard/panel:v1.0.1" |
     .services.pasarguard.container_name = "pasarguard_panel" |
     .services.pasarguard.restart = "always" |
     .services.pasarguard.env_file = "./pasarguard/.env" |
     .services.pasarguard.network_mode = "host" | 
     .services.pasarguard.volumes[0] = "./pasarguard_lib:/var/lib/pasarguard" | 
     .services.pasarguard.volumes[1] = "./pasarguard/xray_config.json:/code/xray_config.json" |
     .services.pasarguard.volumes[2] = "./pasarguard/templates:/var/lib/pasarguard/templates" |
     .services.caddy.volumes[2] = "./pasarguard_lib:/run/pasarguard" |
     .services.pasarguard_node.image = "pasarguard/node:v0.1.0" |
     .services.pasarguard_node.container_name = "pasarguard_node" |
     .services.pasarguard_node.restart = "always" |
     .services.pasarguard_node.env_file = "./pasarguard/.env_node" |
     .services.pasarguard_node.network_mode = "host" | 
     .services.pasarguard_node.volumes[0] = "./pasarguard/node:/var/lib/pg-node"' -i /opt/xray-vps-setup/docker-compose.yml
        mkdir -p pasarguard/node/certs caddy
        SSL_CERT_FILE="/opt/xray-vps-setup/pasarguard/node/certs/ssl_cert.pem"
        SSL_KEY_FILE="/opt/xray-vps-setup/pasarguard/node/certs/ssl_key.pem"
        gen_self_signed_cert
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/pasarguard | envsubst >./pasarguard/.env
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/pasarguard_node | envsubst >./pasarguard/.env_node
        mkdir -p /opt/xray-vps-setup/pasarguard/templates/home
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/confluence_page | envsubst >./pasarguard/templates/home/index.html
        export CADDY_REVERSE="reverse_proxy * unix//run/pasarguard/pasarguard.socket {
        header_down -Server
    }
    
    handle_errors {
        respond \"{err.status_code} {err.status_text}\"
    }"
        wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst >./caddy/Caddyfile
        wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst >./pasarguard/xray_config.json
    elif [[ "${panel_input,,}" == "marzban" ]]; then
        export MARZBAN_PASS=$(
            tr -dc A-Za-z0-9 </dev/urandom | head -c 13
            echo
        )
        export MARZBAN_PATH=$(openssl rand -hex 8)
        export MARZBAN_SUB_PATH=$(openssl rand -hex 8)
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose | envsubst >./docker-compose.yml
        yq eval \
            '.services.marzban.image = "gozargah/marzban:v0.8.4" |
     .services.marzban.container_name = "marzban" |
     .services.marzban.restart = "always" |
     .services.marzban.env_file = "./marzban/.env" |
     .services.marzban.network_mode = "host" | 
     .services.marzban.volumes[0] = "./marzban_lib:/var/lib/marzban" | 
     .services.marzban.volumes[1] = "./marzban/xray_config.json:/code/xray_config.json" |
     .services.marzban.volumes[2] = "./marzban/templates:/var/lib/marzban/templates" |
     .services.caddy.volumes[2] = "./marzban_lib:/run/marzban"' -i /opt/xray-vps-setup/docker-compose.yml
        mkdir -p marzban caddy
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/marzban | envsubst >./marzban/.env
        mkdir -p /opt/xray-vps-setup/marzban/templates/home
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/confluence_page | envsubst >./marzban/templates/home/index.html
        export CADDY_REVERSE="reverse_proxy * unix//run/marzban/marzban.socket {
        header_down -Server
    }

    handle_errors {
        respond \"{err.status_code} {err.status_text}\"
    }"
        wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst >./caddy/Caddyfile
        wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst >./marzban/xray_config.json
    else
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose | envsubst >./docker-compose.yml
        mkdir -p /opt/xray-vps-setup/caddy/templates
        yq eval \
            '.services.xray.image = "ghcr.io/xtls/xray-core:25.6.8" | 
    .services.xray.container_name = "xray" |
    .services.xray.user = "root" |
    .services.xray.command = "run -c /etc/xray/config.json" |
    .services.xray.restart = "always" | 
    .services.xray.network_mode = "host" | 
    .services.caddy.volumes[2] = "./caddy/templates:/srv" |
    .services.xray.volumes[0] = "./xray:/etc/xray"' -i /opt/xray-vps-setup/docker-compose.yml
        wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/confluence_page | envsubst >./caddy/templates/index.html
        export CADDY_REVERSE="root * /srv
    file_server"
        mkdir -p xray caddy
        wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst >./xray/config.json
        wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst >./caddy/Caddyfile
    fi
}

xray_setup

sshd_edit() {
    grep -r Port /etc/ssh -l | xargs -n 1 sed -i -e "/Port /c\Port $SSH_PORT"
    grep -r PasswordAuthentication /etc/ssh -l | xargs -n 1 sed -i -e "/PasswordAuthentication /c\PasswordAuthentication no"
    grep -r PermitRootLogin /etc/ssh -l | xargs -n 1 sed -i -e "/PermitRootLogin /c\PermitRootLogin no"
    systemctl daemon-reload
    systemctl restart ssh
}

add_user() {
    useradd $SSH_USER -s /bin/bash
    usermod -aG sudo $SSH_USER
    echo $SSH_USER:$SSH_USER_PASS | chpasswd
    mkdir -p /home/$SSH_USER/.ssh
    touch /home/$SSH_USER/.ssh/authorized_keys
    echo $input_ssh_pbk >>/home/$SSH_USER/.ssh/authorized_keys
    chmod 700 /home/$SSH_USER/.ssh/
    chmod 600 /home/$SSH_USER/.ssh/authorized_keys
    chown $SSH_USER:$SSH_USER -R /home/$SSH_USER
    usermod -aG docker $SSH_USER
}

debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF

# Configure iptables
edit_iptables() {
    apt-get install iptables-persistent netfilter-persistent -y
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $SSH_PORT -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -P INPUT DROP
    netfilter-persistent save
}

if [[ ${configure_ssh_input,,} == "y" ]]; then
    sshd_edit
    add_user
    edit_iptables
fi

# WARP Install function
warp_install() {
    apt install gpg -y
    echo "If this fails then warp won't be added to routing and everything will work without it"
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    apt update
    apt install cloudflare-warp -y

    echo "y" | warp-cli registration new
    export TRY_WARP=$(echo $?)
    if [[ $TRY_WARP != 0 ]]; then
        echo "Couldn't connect to WARP"
        exit 0
    else
        warp-cli mode proxy
        warp-cli proxy port 40000
        warp-cli connect
        if [[ "${panel_input,,}" == "pasarguard" ]]; then
            export XRAY_CONFIG_WARP="/opt/xray-vps-setup/pasarguard/xray_config.json"
        elif [[ "${panel_input,,}" == "marzban" ]]; then
            export XRAY_CONFIG_WARP="/opt/xray-vps-setup/marzban/xray_config.json"
        else
            export XRAY_CONFIG_WARP="/opt/xray-vps-setup/xray/config.json"
        fi
        yq eval \
            '.outbounds += {"tag": "warp","protocol": "socks","settings": {"servers": [{"address": "127.0.0.1","port": 40000}]}}' \
            -i $XRAY_CONFIG_WARP
        yq eval \
            '.routing.rules += {"outboundTag": "warp", "domain": ["geosite:category-ru", "regexp:.*\\.xn--$", "regexp:.*\\.ru$", "regexp:.*\\.su$"]}' \
            -i $XRAY_CONFIG_WARP
        docker compose -f /opt/xray-vps-setup/docker-compose.yml down && docker compose -f /opt/xray-vps-setup/docker-compose.yml up -d
    fi
}

end_script() {
    if [[ ${configure_warp_input,,} == "y" ]]; then
        warp_install
    fi

    if [[ "${panel_input,,}" == "pasarguard" ]]; then
        docker run -v /opt/xray-vps-setup/caddy/Caddyfile:/opt/xray-vps-setup/Caddyfile --rm caddy caddy fmt --overwrite /opt/xray-vps-setup/Caddyfile
        docker compose -f /opt/xray-vps-setup/docker-compose.yml up -d
        pasarguard_auto_configuring
        final_msg="PasarGuard panel location: https://$VLESS_DOMAIN/$PASARGUARD_PATH
User: xray_admin
Password: $PASARGUARD_PASS
    "
    elif [[ "${panel_input,,}" == "marzban" ]]; then
        docker run -v /opt/xray-vps-setup/caddy/Caddyfile:/opt/xray-vps-setup/Caddyfile --rm caddy caddy fmt --overwrite /opt/xray-vps-setup/Caddyfile
        docker compose -f /opt/xray-vps-setup/docker-compose.yml up -d
        final_msg="Marzban panel location: https://$VLESS_DOMAIN/$MARZBAN_PATH
User: xray_admin
Password: $MARZBAN_PASS
    "
    else
        apt install -y qrencode
        docker run -v /opt/xray-vps-setup/caddy/Caddyfile:/opt/xray-vps-setup/Caddyfile --rm caddy caddy fmt --overwrite /opt/xray-vps-setup/Caddyfile
        docker compose -f /opt/xray-vps-setup/docker-compose.yml up -d

        vless_qr=$(qrencode -t UTF8 -o - "vless://$XRAY_UUID@$VLESS_DOMAIN:443?type=tcp&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&spx=%2F&flow=xtls-rprx-vision")
        xray_config=$(wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray_outbound" | envsubst)
        singbox_config=$(wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/sing_box_outbound" | envsubst)

        final_msg="Clipboard string format:
vless://$XRAY_UUID@$VLESS_DOMAIN:443?type=tcp&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&spx=%2F&flow=xtls-rprx-vision

XRay outbound config:
$xray_config

Sing-box outbound config:
$singbox_config

Plain data:
PBK: $XRAY_PBK, SID: $XRAY_SID, UUID: $XRAY_UUID

VLESS QR Code:

$vless_qr

    "
    fi

    docker rmi ghcr.io/xtls/xray-core:latest caddy:latest
    clear
    if [[ ${configure_ssh_input,,} == "y" ]]; then
        echo "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT."
    fi
    echo "$final_msg"
}

end_script
set +e
