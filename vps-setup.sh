#/bin/bash

set -e

export GIT_BRANCH="marzban"
export GIT_REPO="Akiyamov/xray-vps-setup"

# Check if script started as root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Install idn 
apt-get update
apt-get install idn -y

# Read domain input
read -ep "Enter your domain:"$'\n' input_domain

export VLESS_DOMAIN=$(echo $input_domain | idn)
export TEST_DOMAIN=$(nslookup $VLESS_DOMAIN | awk -F': ' 'NR==6 { print $2 } ')
if [ $TEST_DOMAIN -eq "" ]; then
  read -ep "Are you sure? That domain has no DNS record. If you didn't add that you will have to restart xray and caddy by yourself [y/N]"$'\n' prompt_response
  if [[ "$prompt_response" =~ ^([yY]) ]]; then
    echo "Ok"
  else 
    echo "Come back later"
    exit 1
  fi
fi

read -ep "Do you want to install marzban? [y/N] "$'\n' marzban_input

read -ep "Which page do you want to use to hide:
1) Custom page, you will provide link. (Not recomended)
2) Confluence login page "$'\n' camo_page_input
set +e
if [[ ${camo_page_input} == "1" ]]; then
  read -ep "Write a page you want to use to hide"$'\n' page_hide_input
  export PAGE_CAMO=$(echo $page_hide_input | cut -d'/' -f3)
  curl -sS -D - https://$page_hide_input -o /dev/null | grep x-frame-options
  iframe_test=$(echo $?)
  while [[ $iframe_test != "1" ]]; do
    read -ep "This website seem to forbid iframe. Try another one"$'\n' page_hide_input
    export PAGE_CAMO=$(echo $page_hide_input | cut -d'/' -f3)
    curl -sS -D - https://$page_hide_input -o /dev/null | grep x-frame-options
    iframe_test=$(echo $?)
  done
  read -ep "Write title for page. It will be displayed at tab name"$'\n' page_desc_input
fi
set -e

read -ep "Do you want to configure server security? Do this on first run only. [y/N] "$'\n' configure_ssh_input
if [[ ${configure_ssh_input,,} == "y" ]]; then
  # Read SSH port
  read -ep "Enter SSH port. Default 22, can't use ports: 80, 443 and 4123:"$'\n' input_ssh_port

  while [[ "$input_ssh_port" -eq "80" || "$input_ssh_port" -eq "443" || "$input_ssh_port" -eq "4123" ]]; do
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

read -ep "Do you want to install WARP and use it on russian websites? [y/N] "$'\n' configure_warp_input

# Check congestion protocol
if sysctl net.ipv4.tcp_congestion_control | grep bbr; then
    echo "BBR is already used"
else
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    echo "Enabled BBR"
fi

docker_install() {
  bash <(wget -qO- https://get.docker.com) @ -o get-docker.sh
}

if ! command -v docker 2>&1 >/dev/null; then
    docker_install
fi

# Generate values for XRay
export SSH_USER=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8; echo)
export SSH_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
export ROOT_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
export SSH_PORT=${input_ssh_port:-22}
export ROOT_LOGIN="yes"
export IP_CADDY=$(hostname -I | cut -d' ' -f1)
export CADDY_BASIC_AUTH=$(docker run --rm caddy caddy hash-password --plaintext $SSH_USER_PASS)
export XRAY_PIK=$(docker run --rm ghcr.io/xtls/xray-core x25519 | head -n1 | cut -d' ' -f 3)
export XRAY_PBK=$(docker run --rm ghcr.io/xtls/xray-core x25519 -i $XRAY_PIK | tail -1 | cut -d' ' -f 3)
export XRAY_SID=$(openssl rand -hex 8)
export XRAY_UUID=$(docker run --rm ghcr.io/xtls/xray-core uuid)
export XRAY_CFG="/usr/local/etc/xray/config.json"
if [[ ${camo_page_input} -eq 1 ]]; then
  export PAGE_NAME="mask_page"
else
  export PAGE_NAME="confluence_page"
fi

# Install marzban
xray_setup() {
  mkdir -p /opt/xray-vps-setup
  cd /opt/xray-vps-setup
  if [[ "${marzban_input,,}" == "y" ]]; then
    export MARZBAN_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
    export MARZBAN_PATH=$(openssl rand -hex 8)
    export MARZBAN_SUB_PATH=$(openssl rand -hex 8)
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose | envsubst > ./docker-compose.yml
    docker run --user root --rm -v ${PWD}:/workdir mikefarah/yq eval \
    '.services.marzban.image = "gozargah/marzban:v0.7.0" |
     .services.marzban.restart = "always" |
     .services.marzban.env_file = "./marzban/.env" |
     .services.marzban.network_mode = "host" | 
     .services.marzban.volumes[0] = "./marzban_lib:/var/lib/marzban" | 
     .services.marzban.volumes[1] = "./marzban/xray_config.json:/code/xray_config.json" |
     .services.marzban.volumes[2] = "./marzban/templates:/var/lib/marzban/templates" |
     .services.caddy.volumes[3] = "./marzban_lib:/run/marzban"' -i /workdir/docker-compose.yml
    mkdir -p marzban caddy
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/marzban | envsubst > ./marzban/.env
    mkdir -p /opt/xray-vps-setup/marzban/templates/home
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/$PAGE_NAME | envsubst > ./marzban/templates/home/index.html
    export CADDY_REVERSE="reverse_proxy * unix//run/marzban/marzban.socket"
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst > ./caddy/Caddyfile
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst > ./marzban/xray_config.json
  else
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose | envsubst > ./docker-compose.yml
    mkdir -p /opt/xray-vps-setup/caddy/templates
    docker run --user root --rm -v ${PWD}:/workdir mikefarah/yq eval \
    '.services.xray.image = "ghcr.io/xtls/xray-core:sha-db934f0" | 
    .services.xray.restart = "always" | 
    .services.xray.network_mode = "host" | 
    .services.caddy.volumes[3] = "./caddy/templates:/srv" |
    .services.xray.volumes[0] = "./xray:/etc/xray"' -i /workdir/docker-compose.yml
    wget -qO- https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/$PAGE_NAME | envsubst > ./caddy/templates/index.html
    export CADDY_REVERSE="root * /srv
    file_server"
    mkdir -p xray caddy
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" | envsubst > ./xray/config.json
    wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" | envsubst > ./caddy/Caddyfile
  fi
}

xray_setup

sshd_edit() {
  grep -r Port /etc/ssh -l | xargs -n 1 sed -i -e "/Port /c\Port $SSH_PORT"
  grep -r PasswordAuthentication /etc/ssh -l | xargs -n 1 sed -i -e "/PasswordAuthentication /c\PasswordAuthentication no"
  grep -r PermitRootLogin /etc/ssh -l | xargs -n 1 sed -i -e "/PermitRootLogin /c\PermitRootLogin no"
  systemctl restart ssh
}

add_user() {
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
  usermod -aG docker $SSH_USER
}

debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF

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

if [[ ${configure_ssh_input,,} == "y" ]]; then
  sshd_edit
  add_user
  edit_iptables
  echo "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT. New password for root user: $ROOT_USER_PASS"
fi


# WARP Install function
warp_install() {
  echo "If this fails then warp won't be added to routing and everything will work without it"
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list
  apt-get update 
  apt-get install cloudflare-warp -y
  
  echo "y" | warp-cli registration new
  export TRY_WARP=$(echo $?)
  if [[ $TRY_WARP != 0 ]]; then
    echo "Couldn't connect to WARP"
    exit 0
  else
    warp-cli mode proxy
    warp-cli proxy port 40000
    warp-cli connect
    if [[ "${marzban_input,,}" == "y" ]]; then
      export XRAY_CONFIG_WARP="/workdir/marzban/xray_config.json"
    else
      export XRAY_CONFIG_WARP="/workdir/xray/config.json"
    fi
    docker run --user root --rm -v ${PWD}:/workdir mikefarah/yq eval \
    '.outbounds[.outbounds | length ] |= . + 
    {"tag": "warp", "protocl": "socks", "settings": 
    {"servers": [{"address": "127.0.0.1", "port": "40000", "users": []}]}}' \
    -i $XRAY_CONFIG_WARP
    docker run --user root --rm -v ${PWD}:/workdir mikefarah/yq eval \
    '.routing.rules[.routing.rules | length ] |= . 
    + {"outboundTag": "warp", "domain": ["geosite:ru"]}' \
    -i $XRAY_CONFIG_WARP
    docker compose -f /opt/xray-vps-setup/docker-compose.yml down && docker compose -f /opt/xray-vps-setup/docker-compose.yml up -d
  fi
}

end_script() {
  if [[ "${marzban_input,,}" == "y" ]]; then
    docker run -v /opt/xray-vps-setup/caddy/Caddyfile:/workdir/Caddyfile --rm caddy caddy fmt --overwrite /workdir/Caddyfile
    docker compose -f /opt/xray-vps-setup/docker-compose.yml up -d
    echo "Marzban location: https://$VLESS_DOMAIN/$MARZBAN_PATH. Marzban user: xray_admin, password: $MARZBAN_PASS"
  else
    docker run -v /opt/xray-vps-setup/caddy/Caddyfile:/workdir/Caddyfile --rm caddy caddy fmt --overwrite /workdir/Caddyfile
    docker compose -f /opt/xray-vps-setup/docker-compose.yml up -d
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
set +e
if [[ ${configure_warp_input,,} == "y" ]]; then
  warp_install
fi
