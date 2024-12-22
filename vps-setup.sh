#/bin/bash

set -e

export GIT_BRANCH="marzban"
export GIT_REPO="Akiyamov/xray-vps-setup"

# Check if script started as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Install idn and yq
apt-get update
apt-get install idn yq -y

# Read domain input
read -ep "Enter your domain:"$'\n' input_domain

export VLESS_DOMAIN=$(echo $input_domain | idn)
export TEST_DOMAIN=$(nslookup $VLESS_DOMAIN | awk -F': ' 'NR==6 { print $2 } ')
if [ $TEST_DOMAIN -eq "" ]; then
  read -ep "Are you sure? That domain has no DNS record. If you didn't add that you will have to restart xray and caddy by yourself [y/N]" prompt_response
  if [[ "$prompt_response" =~ ^([yY]) ]]; then
    echo "Ok"
  else 
    echo "Come back later"
    exit 1
  fi
fi

read -ep "Do you want to install marzban? [y/N] " marzban_input

read -ep "Do you want to configure SSH? [y/N] " configure_ssh_input

if [[ ${configure_ssh_input,,} == "y" ]]; then
  # Read SSH port
  read -ep "Enter SSH port. Default 22, can't use ports: 80, 443 and 4123:"$'\n' input_ssh_port

  while [ "$input_ssh_port" -eq "80"] || [ "$input_ssh_port" -eq "443" ] || [ "$input_ssh_port" -eq "4123" ]; do
    read -ep "No, ssh can't use $input_ssh_port as port, write again:"$'\n' input_ssh_port
  done
  # Read SSH Pubkey
  read -ep "Enter SSH public key:"$'\n' input_ssh_pbk

  echo "$input_ssh_pbk" > ./test_pbk
  ssh-keygen -l -f ./test_pbk
  PBK_STATUS=$(echo $?)
  if [ "$PBK_STATUS" -eq 255 ]; then
    echo "Can't verify publick key. Try again and be sure to include 'ssh-rsa' or 'ssh-ed25519' and 'user@pcname' at the end of file"
    exit
  fi
  rm ./test_pbk
fi

read -ep "Do you want to create special user to login and forbid root login? [y/N] " create_new_user

# Check congestion protocol
if sysctl net.ipv4.tcp_congestion_control | grep bbr; then
    echo "BBR is already used"
else
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    echo "Enabled BBR"
fi

# Generate values for XRay
export SSH_USER=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8; echo)
export SSH_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
export ROOT_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
export SSH_PORT=${input_ssh_port:-22}
if [[ "${create_new_user,,}" -eq "y" ]]; then
  export ROOT_LOGIN="no"
else 
  export ROOT_LOGIN="yes"
fi
export IP_CADDY=$(hostname -I | cut -d' ' -f1)
export CADDY_BASIC_AUTH=$(echo $SSH_USER_PASS | caddy hash-password)
export XRAY_PIK=$(xray x25519 | head -n1 | cut -d' ' -f 3)
export XRAY_PBK=$(xray x25519 -i $XRAY_PIK | tail -1 | cut -d' ' -f 3)
export XRAY_SID=$(openssl rand -hex 8)
export XRAY_UUID=$(xray uuid)
export XRAY_CFG="/usr/local/etc/xray/config.json"
export IMAGES_CADDY=("IL1.png", "IL2.png", "IL3.png", "SW1.png", "SW2.png", "SW3.png")
export IMAGE_CADDY=$(printf "%s\n" "${expressions[@]}" | shuf -n1)

# Install marzban
xray_setup() {
  if [[ "${marzban_input,,}" == "y" ]]; then
    export MARZBAN_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
    export MARZBAN_PATH=$(openssl rand -hex 8)
    export MARZBAN_SUB_PATH=$(openssl rand -hex 8)
    mkdir -p /opt/xray-vps-setup
    cd /opt/xray-vps-setup
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose | envsubst > ./docker-compose.yml
    yq -i \
    '.services.marzban.image = "gozargah/marzban:v0.7.0" |
     .services.marzban.restart = "always" |
     .services.marzban.env_file = "./marzban/.env" |
     .services.marzban.network_mode = "host" | 
     .services.marzban.volumes[0] = "/var/lib/marzban:/var/lib/marzban" | 
     .services.marzban.volumes[1] = "./marzban/xray_config.json:/code/xray_config.json" | 
     .services.caddy.volumes[3] = "/var/lib/marzban:/var/lib/marzban"' docker-compose.yml
    mkdir marzban caddy
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/marzban | envsubst > ./marzban/.env
    export CADDY_REVERSE="reverse_proxy http://127.0.0.1:8000"
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst > ./caddy/Caddyfile
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst > ./marzban/xray_config.json
    fi
  else
    yq -i \
    '.services.xray.image = "ghcr.io/xtls/xray-core:sha-db934f0" | 
    .services.xray.restart = "always" | 
    .services.xray.network_mode = "host" | 
    .services.xray.volumes[0] = "./xray:/etc/xray"' docker-compose.yml
    export CADDY_REVERSE="root * /srv
    basic_auth * {
      xray_user $CADDY_BASIC_AUTH
    }
    file_server browse"
    mkdir xray caddy
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst > ./xray/config.json
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst > ./caddy/Caddyfile
  fi
}

xray_setup

add_user() {
  if id "xray_user" >/dev/null 2>&1; then
    echo 'User already exists, not changing anything'
  else
    useradd $SSH_USER
    usermod -aG sudo $SSH_USER
    echo $SSH_USER:$SSH_USER_PASS | chpasswd
    echo root:$ROOT_USER_PASS | chpasswd
    mkdir -p /home/$SSH_USER/.ssh
    touch /home/$SSH_USER/.ssh/authorized_keys
    echo $input_ssh_pbk >> /home/$SSH_USER/.ssh/authorized_keys
    chmod 700 /home/$SSH_USER/.ssh/
    chmod 600 /home/$SSH_USER/.ssh/authorized_keys
    chown $SSH_USER:$SSH_USER -R /home/$SSH_USER
    groupadd docker
    usermod -aG docker $SSH_USER
  fi
}

if [[ ${create_new_user,,} -eq "y" ]]; then
  add_user
fi

# Set SSH config 
edti_sshd() {
  wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/ssh_template" | envsubst > /etc/ssh/sshd_config
  systemctl restart ssh
}

# Configure iptables
edit_iptables() {
  apt-get install iptables-persistent netfilter-persistent -y
  iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $SSH_PORT -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -P INPUT DROP
  netfilter-persistent save
}

edit_iptables

# Print user data
echo "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT. New password for root user: $ROOT_USER_PASS"

end_script() {
  if [[ "${marzban_input,,}" == "y" ]]; then
    systemctl enable --now marzban
    echo "Marzban location: https://$VLESS_DOMAIN/$MARZBAN_PATH. Marzban user: xray_admin, password: $MARZBAN_PASS"
  else
    systemctl start xray
    systemctl restart caddy
    echo "Clipboard string format"
    echo "vless://$XRAY_UUID@$VLESS_DOMAIN:443?type=tcp&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&spx=%2F&flow=xtls-rprx-vision" | envsubst
    echo "XRay outbound config"
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray_outbound | envsubst 
    echo "Sing-box outbound config"
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/sing_box_outbound | envsubst 
    echo "Plain data"
    echo "PBK: $XRAY_PBK, SID: $XRAY_SID, UUID: $XRAY_UUID"
  fi
}

end_script

# WARP Install function
# warp_install() {
#   curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
#   echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
#   apt-get update && apt-get install cloudflare-warp -y
#   
#   warp-cli registration new
#   warp-cli mode proxy
#   warp-cli proxy port 40000
#   warp-cli connect
# }
# 