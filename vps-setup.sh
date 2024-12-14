#/bin/bash

set -e

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
  read -ep "Are you sure? That domain has no DNS record. If you didn't add that you will have to restart xray and caddy by yourself [y/N]" prompt_response
  if [[ "$prompt_response" =~ ^([yY]) ]]; then
    echo "Ok"
  else 
    echo "Come back later"
    exit 1
  fi
fi

# Read SSH port
read -ep "Enter SSH port [default 22]:"$'\n' input_ssh_port

while [ "$input_ssh_port" -eq "80"] || [ "$input_ssh_port" -eq "443" ]; do
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

# Check congestion protocol
if sysctl net.ipv4.tcp_congestion_control | grep bbr; then
    echo "BBR is already used"
else
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p > /dev/null
    echo "Enabled BBR"
fi

# Set vars for deb
debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF

# Install Caddy, jq and sudo
apt-get update
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl iptables-persistent
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y caddy jq sudo

# Install XRay
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Generate values for XRay
export SSH_USER="xray_user"
export SSH_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
export ROOT_USER_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
export SSH_PORT=${input_ssh_port:-22}
export CADDY_BASIC_AUTH=$(echo $SSH_USER_PASS | caddy hash-password)
export XRAY_PIK=$(xray x25519 | head -n1 | cut -d' ' -f 3)
export XRAY_PBK=$(xray x25519 -i $XRAY_PIK | tail -1 | cut -d' ' -f 3)
export XRAY_SID=$(openssl rand -hex 8)
export XRAY_UUID=$(xray uuid)

# Setup config for Caddy and XRay
wget -qO- https://raw.githubusercontent.com/Akiyamov/xray-vps-setup/refs/heads/main/templates_for_script/caddy | envsubst > /etc/caddy/Caddyfile
wget -qO- https://raw.githubusercontent.com/Akiyamov/xray-vps-setup/refs/heads/main/templates_for_script/xray | envsubst > /usr/local/etc/xray/config.json

# Restart XRay and Caddy
systemctl restart xray
systemctl restart caddy

# Create user and add to sudoers
useradd $SSH_USER
usermod -aG sudo $SSH_USER
echo $SSH_USER:$SSH_USER_PASS | chpasswd

# Set new password for root user
echo root:$ROOT_USER_PASS | chpasswd

# Add ssh pbk to authorized_keys
mkdir -p /home/$SSH_USER/.ssh
touch /home/$SSH_USER/.ssh/authorized_keys
echo $input_ssh_pbk >> /home/$SSH_USER/.ssh/authorized_keys
chmod 700 /home/$SSH_USER/.ssh/
chmod 600 /home/$SSH_USER/.ssh/authorized_keys
chown $SSH_USER:$SSH_USER -R /home/$SSH_USER

# Set SSH config 
wget -qO- https://raw.githubusercontent.com/Akiyamov/xray-vps-setup/refs/heads/main/templates_for_script/ssh_template | envsubst > /etc/ssh/sshd_config
systemctl restart ssh

# Configure iptables
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $SSH_PORT -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -P INPUT DROP
netfilter-persistent save

# Print user data
echo "New user for ssh: $SSH_USER, password for user: $SSH_USER_PASS. New port for SSH: $SSH_PORT. New password for root user: $ROOT_USER_PASS"

# Print outbound and clipboard string
echo "Clipboard string format"
echo "vless://$XRAY_UUID@$VLESS_DOMAIN:443?type=tcp&security=reality&pbk=$XRAY_PBK&fp=chrome&sni=$VLESS_DOMAIN&sid=$XRAY_SID&spx=%2F&flow=xtls-rprx-vision" | envsubst
echo "XRay outbound config"
wget -qO- https://raw.githubusercontent.com/Akiyamov/xray-vps-setup/refs/heads/main/templates_for_script/xray_outbound | envsubst 
echo "Sing-box outbound config"
wget -qO- https://raw.githubusercontent.com/Akiyamov/xray-vps-setup/refs/heads/main/templates_for_script/sing_box_outbound | envsubst 
echo "Plain data"
echo "PBK: $XRAY_PBK, SID: $XRAY_SID, UUID: $XRAY_UUID"

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