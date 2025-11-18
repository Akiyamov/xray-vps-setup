#!/bin/bash

set -euo pipefail

# Constants
readonly GIT_BRANCH="main"
readonly GIT_REPO="Akiyamov/xray-vps-setup"
readonly RESERVED_PORTS="80 443 4123"
readonly REMNAWAVE_PORT=3000
readonly WARP_PROXY_PORT=40000

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m' # No Color

# Error handler
trap 'echo -e "${RED}Error occurred at line $LINENO. Exiting.${NC}" >&2' ERR

# Logging functions
log_info() { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1" >&2; }

# Check if script started as root
if [ "$EUID" -ne 0 ]; then
  log_error "Please run as root"
  exit 1
fi

# Function definitions must come before usage

# Install dependencies
install_dependencies() {
  log_info "Installing dependencies..."
  apt-get update -qq
  apt-get install -y -qq idn sudo curl wget gpg
}

# Install yq
install_yq() {
  if command -v yq &> /dev/null; then
    log_info "yq is already installed"
    return 0
  fi

  local arch
  arch=$(dpkg --print-architecture)
  log_info "Installing yq..."
  wget -q "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${arch}" -O /usr/bin/yq
  chmod +x /usr/bin/yq
}

# Install Docker
install_docker() {
  if command -v docker &> /dev/null; then
    log_info "Docker is already installed"
    return 0
  fi

  log_info "Installing Docker..."
  curl -fsSL https://get.docker.com | bash > /dev/null
}

# Validate domain
validate_domain() {
  local domain=$1
  local resolved_ip
  local server_ips

  server_ips=($(hostname -I))
  resolved_ip=$(dig +short "$domain" | tail -n1)

  if [ -z "$resolved_ip" ]; then
    log_warn "Domain has no DNS record"
    read -rep "Proceed without DNS verification? [y/N] " response
    [[ "$response" =~ ^([yY])$ ]] || { log_error "Come back later"; exit 1; }
  else
    local match_found=false
    for server_ip in "${server_ips[@]}"; do
      if [ "$resolved_ip" == "$server_ip" ]; then
        match_found=true
        break
      fi
    done

    if [ "$match_found" = true ]; then
      log_info "DNS record points to this server ($resolved_ip)"
    else
      log_warn "DNS record exists but points to different IP"
      log_warn "  Domain resolves to: $resolved_ip"
      log_warn "  This server's IPs: ${server_ips[*]}"
      read -rep "Continue anyway? [y/N] " response
      [[ "$response" =~ ^([yY])$ ]] || { log_error "Come back later"; exit 1; }
    fi
  fi
}

# Validate SSH port
validate_ssh_port() {
  local port=$1

  # Check if port is a number
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  # Check if port is in reserved range
  for reserved_port in $RESERVED_PORTS; do
    if [ "$port" == "$reserved_port" ]; then
      return 1
    fi
  done

  # Check if port is in valid range
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    return 1
  fi

  return 0
}

# Validate SSH public key
validate_ssh_key() {
  local key=$1
  local tmp_file
  tmp_file=$(mktemp)

  echo "$key" > "$tmp_file"
  if ssh-keygen -l -f "$tmp_file" &> /dev/null; then
    rm -f "$tmp_file"
    return 0
  else
    rm -f "$tmp_file"
    return 1
  fi
}

# Enable BBR
enable_bbr() {
  if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    log_info "BBR is already enabled"
  else
    log_info "Enabling BBR..."
    {
      echo "net.core.default_qdisc=fq"
      echo "net.ipv4.tcp_congestion_control=bbr"
    } >> /etc/sysctl.conf
    sysctl -p > /dev/null 2>&1
  fi
}

# Generate random string
generate_random() {
  local length=${1:-16}
  tr -dc A-Za-z0-9 < /dev/urandom | head -c "$length"
}

# Download file with error checking
download_file() {
  local url=$1
  local output=$2

  if ! wget -qO "$output" "$url"; then
    log_error "Failed to download: $url"
    return 1
  fi
}

# Configure SSH security
configure_ssh() {
  local ssh_port=$1
  local ssh_pubkey=$2
  local ssh_user=$3

  log_info "Configuring SSH security..."

  # Edit sshd_config
  local sshd_files
  sshd_files=$(grep -rl "Port " /etc/ssh 2>/dev/null || true)
  for file in $sshd_files; do
    sed -i -e "/^#*Port /c\Port $ssh_port" \
           -e "/^#*PasswordAuthentication /c\PasswordAuthentication no" \
           -e "/^#*PermitRootLogin /c\PermitRootLogin no" "$file"
  done

  # Create user
  if ! id "$ssh_user" &>/dev/null; then
    useradd -m -s /bin/bash "$ssh_user"
    usermod -aG sudo,docker "$ssh_user"

    # Set up SSH key
    mkdir -p "/home/$ssh_user/.ssh"
    echo "$ssh_pubkey" > "/home/$ssh_user/.ssh/authorized_keys"
    chmod 700 "/home/$ssh_user/.ssh"
    chmod 600 "/home/$ssh_user/.ssh/authorized_keys"
    chown -R "$ssh_user:$ssh_user" "/home/$ssh_user"
  fi

  systemctl daemon-reload
  systemctl restart ssh
}

# Configure firewall
configure_firewall() {
  local ssh_port=$1

  log_info "Configuring firewall..."

  # Pre-configure iptables-persistent
  debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF

  apt-get install -y -qq iptables-persistent netfilter-persistent

  # Clear existing rules
  iptables -F
  iptables -X

  # Set up rules
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p icmp -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport "$ssh_port" -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
  iptables -P INPUT DROP

  netfilter-persistent save > /dev/null 2>&1
}

# Setup Xray (for Marzban or standalone)
setup_xray() {
  local variant=$1
  local xray_pik xray_pbk xray_sid xray_uuid

  log_info "Setting up Xray ($variant)..."

  # Generate Xray credentials
  xray_pik=$(docker run --rm ghcr.io/xtls/xray-core x25519 | awk 'NR==1 {print $3}')
  xray_pbk=$(docker run --rm ghcr.io/xtls/xray-core x25519 -i "$xray_pik" | awk 'NR==2 {print $3}')
  xray_sid=$(openssl rand -hex 8)
  xray_uuid=$(docker run --rm ghcr.io/xtls/xray-core uuid)

  # Export for templates
  export XRAY_PIK=$xray_pik
  export XRAY_PBK=$xray_pbk
  export XRAY_SID=$xray_sid
  export XRAY_UUID=$xray_uuid
  export XRAY_CFG="/usr/local/etc/xray/config.json"

  mkdir -p /opt/xray-vps-setup
  cd /opt/xray-vps-setup

  # Download base compose
  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose" "./docker-compose.yml"

  if [ "$variant" == "marzban" ]; then
    setup_marzban
  else
    setup_xray_standalone
  fi
}

# Setup Marzban
setup_marzban() {
  log_info "Configuring Marzban..."

  export MARZBAN_PASS=$(generate_random 16)
  export MARZBAN_PATH=$(openssl rand -hex 8)
  export MARZBAN_SUB_PATH=$(openssl rand -hex 8)

  # Configure docker-compose for Marzban
  yq eval '
    .services.marzban.image = "gozargah/marzban:v0.8.4" |
    .services.marzban.container_name = "marzban" |
    .services.marzban.restart = "always" |
    .services.marzban.env_file = "./marzban/.env" |
    .services.marzban.network_mode = "host" |
    .services.marzban.volumes[0] = "./marzban_lib:/var/lib/marzban" |
    .services.marzban.volumes[1] = "./marzban/xray_config.json:/code/xray_config.json" |
    .services.marzban.volumes[2] = "./marzban/templates:/var/lib/marzban/templates" |
    .services.caddy.volumes[2] = "./marzban_lib:/run/marzban"
  ' -i ./docker-compose.yml

  mkdir -p marzban/templates/home caddy

  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/marzban" "./marzban/.env"
  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/confluence_page" "./marzban/templates/home/index.html"
  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" "./marzban/xray_config.json"

  export CADDY_REVERSE="reverse_proxy * unix//run/marzban/marzban.socket"
  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" "./caddy/Caddyfile"
}

# Setup standalone Xray
setup_xray_standalone() {
  log_info "Configuring standalone Xray..."

  yq eval '
    .services.xray.image = "ghcr.io/xtls/xray-core:25.6.8" |
    .services.xray.container_name = "xray" |
    .services.xray.user = "root" |
    .services.xray.command = "run -c /etc/xray/config.json" |
    .services.xray.restart = "always" |
    .services.xray.network_mode = "host" |
    .services.caddy.volumes[2] = "./caddy/templates:/srv" |
    .services.xray.volumes[0] = "./xray:/etc/xray"
  ' -i ./docker-compose.yml

  mkdir -p xray caddy/templates

  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/confluence_page" "./caddy/templates/index.html"
  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray" "./xray/config.json"

  export CADDY_REVERSE="root * /srv
    file_server"
  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" "./caddy/Caddyfile"
}

# Setup Remnawave
setup_remnawave() {
  log_info "Setting up Remnawave panel..."

  # Setup Remnawave backend
  mkdir -p /opt/remnawave
  cd /opt/remnawave

  # Download files
  if ! curl -fsSL -o docker-compose.yml "https://raw.githubusercontent.com/remnawave/backend/refs/heads/main/docker-compose-prod.yml"; then
    log_error "Failed to download Remnawave docker-compose"
    return 1
  fi

  if ! curl -fsSL -o .env "https://raw.githubusercontent.com/remnawave/backend/refs/heads/main/.env.sample"; then
    log_error "Failed to download Remnawave .env"
    return 1
  fi

  # Generate secrets
  local jwt_secret jwt_api_secret metrics_pass webhook_secret db_pass
  jwt_secret=$(openssl rand -hex 64)
  jwt_api_secret=$(openssl rand -hex 64)
  metrics_pass=$(openssl rand -hex 64)
  webhook_secret=$(openssl rand -hex 64)
  db_pass=$(openssl rand -hex 24)

  # Update .env file with all changes in one sed call for efficiency
  sed -i \
    -e "s|^JWT_AUTH_SECRET=.*|JWT_AUTH_SECRET=${jwt_secret}|" \
    -e "s|^JWT_API_TOKENS_SECRET=.*|JWT_API_TOKENS_SECRET=${jwt_api_secret}|" \
    -e "s|^METRICS_PASS=.*|METRICS_PASS=${metrics_pass}|" \
    -e "s|^WEBHOOK_SECRET_HEADER=.*|WEBHOOK_SECRET_HEADER=${webhook_secret}|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${db_pass}|" \
    -e "s|^\\(DATABASE_URL=\"postgresql://postgres:\\)[^@]*\\(@.*\\)|\\1${db_pass}\\2|" \
    -e "s|^FRONT_END_DOMAIN=.*|FRONT_END_DOMAIN=${VLESS_DOMAIN}|" \
    -e "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=${VLESS_DOMAIN}/api/sub|" \
    -e "s|^IS_DOCS_ENABLED=.*|IS_DOCS_ENABLED=false|" \
    .env

  export REMNAWAVE_DB_PASS=$db_pass

  # Start Remnawave services
  docker compose up -d

  # Setup Caddy reverse proxy
  cd /opt/xray-vps-setup
  mkdir -p caddy

  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/compose" "./docker-compose.yml"

  # Keep only Caddy service
  yq eval 'del(.services.xray)' -i ./docker-compose.yml

  export CADDY_REVERSE="reverse_proxy localhost:${REMNAWAVE_PORT}"
  download_file "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/caddy" "./caddy/Caddyfile"

  log_info "Remnawave services starting..."
  sleep 5
}

# Install WARP
install_warp() {
  local panel_type=$1

  log_info "Installing WARP..."

  # Check WARP API accessibility
  if ! curl -I https://api.cloudflareclient.com --connect-timeout 10 > /dev/null 2>&1; then
    log_warn "WARP API is not accessible, skipping WARP installation"
    return 1
  fi

  # Install WARP
  curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list > /dev/null
  apt-get update -qq
  apt-get install -y -qq cloudflare-warp

  # Register and configure
  if ! echo "y" | warp-cli registration new; then
    log_error "Failed to register with WARP"
    return 1
  fi

  warp-cli mode proxy
  warp-cli proxy port "$WARP_PROXY_PORT"
  warp-cli connect

  # Configure Xray to use WARP
  local xray_config
  case $panel_type in
    marzban)
      xray_config="/opt/xray-vps-setup/marzban/xray_config.json"
      ;;
    xray)
      xray_config="/opt/xray-vps-setup/xray/config.json"
      ;;
    remnawave)
      log_warn "WARP integration with Remnawave requires manual Xray node configuration"
      return 0
      ;;
    *)
      log_error "Unknown panel type: $panel_type"
      return 1
      ;;
  esac

  if [ -f "$xray_config" ]; then
    yq eval "
      .outbounds += {\"tag\": \"warp\",\"protocol\": \"socks\",\"settings\": {\"servers\": [{\"address\": \"127.0.0.1\",\"port\": $WARP_PROXY_PORT}]}} |
      .routing.rules += {\"outboundTag\": \"warp\", \"domain\": [\"geosite:category-ru\", \"regexp:.*\\\\.xn--$\", \"regexp:.*\\\\.ru$\", \"regexp:.*\\\\.su$\"]}
    " -i "$xray_config"

    # Restart services
    docker compose -f /opt/xray-vps-setup/docker-compose.yml restart > /dev/null 2>&1
  fi
}

# Start services and show final message
finalize_installation() {
  local panel_type=$1

  # Format Caddyfile
  if [ -f /opt/xray-vps-setup/caddy/Caddyfile ]; then
    docker run -v /opt/xray-vps-setup/caddy/Caddyfile:/opt/Caddyfile --rm caddy caddy fmt --overwrite /opt/Caddyfile > /dev/null 2>&1
  fi

  # Start services
  if [ -f /opt/xray-vps-setup/docker-compose.yml ]; then
    cd /opt/xray-vps-setup
    docker compose up -d
  fi

  # Clean up unused images
  docker rmi ghcr.io/xtls/xray-core:latest caddy:latest 2>/dev/null || true

  # Display final message
  clear
  echo "════════════════════════════════════════════════════════"
  echo "           Installation Complete!"
  echo "════════════════════════════════════════════════════════"
  echo

  case $panel_type in
    remnawave)
      cat <<EOF
Remnawave Panel: https://${VLESS_DOMAIN}

⚠️  IMPORTANT NEXT STEPS:
1. Access the panel at: https://${VLESS_DOMAIN}
2. Complete the initial setup wizard
3. Create your admin account
4. Configure Xray nodes if needed

Database Password: ${REMNAWAVE_DB_PASS}

Useful Commands:
- View credentials: cat /opt/remnawave/.env
- View logs: docker compose -f /opt/remnawave/docker-compose.yml logs -f
- Restart: docker compose -f /opt/remnawave/docker-compose.yml restart
EOF
      ;;
    marzban)
      cat <<EOF
Marzban Panel: https://${VLESS_DOMAIN}/${MARZBAN_PATH}

Admin Credentials:
- Username: xray_admin
- Password: ${MARZBAN_PASS}

Useful Commands:
- View logs: docker compose -f /opt/xray-vps-setup/docker-compose.yml logs -f
- Restart: docker compose -f /opt/xray-vps-setup/docker-compose.yml restart
EOF
      ;;
    xray)
      local xray_config singbox_config
      xray_config=$(wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/xray_outbound" | envsubst)
      singbox_config=$(wget -qO- "https://raw.githubusercontent.com/$GIT_REPO/refs/heads/$GIT_BRANCH/templates_for_script/sing_box_outbound" | envsubst)

      cat <<EOF
Connection String:
vless://${XRAY_UUID}@${VLESS_DOMAIN}:443?type=tcp&security=reality&pbk=${XRAY_PBK}&fp=chrome&sni=${VLESS_DOMAIN}&sid=${XRAY_SID}&spx=%2F&flow=xtls-rprx-vision

XRay Outbound Config:
${xray_config}

Sing-box Outbound Config:
${singbox_config}

Credentials:
- Public Key: ${XRAY_PBK}
- Short ID: ${XRAY_SID}
- UUID: ${XRAY_UUID}
EOF
      ;;
  esac

  if [ -n "${SSH_USER:-}" ]; then
    echo
    echo "SSH Access:"
    echo "- User: ${SSH_USER}"
    echo "- Password: ${SSH_USER_PASS}"
    echo "- Port: ${SSH_PORT}"
  fi

  echo
  echo "════════════════════════════════════════════════════════"
}

# Main installation flow
main() {
  log_info "Starting installation..."

  # Install basic dependencies
  install_dependencies

  # Get domain
  read -rep "Enter your domain: " input_domain
  export VLESS_DOMAIN=$(echo "$input_domain" | idn)
  validate_domain "$VLESS_DOMAIN"

  # Choose panel
  echo
  echo "Choose panel to install:"
  echo "  1) No panel (Xray only)"
  echo "  2) Marzban"
  echo "  3) Remnawave"
  read -rep "Enter choice [1/2/3]: " panel_choice

  case $panel_choice in
    2) panel_type="marzban" ;;
    3) panel_type="remnawave" ;;
    *) panel_type="xray" ;;
  esac

  # SSH configuration
  read -rep "Configure server security? (Do this on first run only) [y/N] " configure_ssh
  if [[ "${configure_ssh,,}" == "y" ]]; then
    # Get SSH port
    while true; do
      read -rep "Enter SSH port (default: 22, reserved: $RESERVED_PORTS): " input_ssh_port
      input_ssh_port=${input_ssh_port:-22}

      if validate_ssh_port "$input_ssh_port"; then
        break
      else
        log_error "Invalid port: $input_ssh_port"
      fi
    done

    # Get SSH public key
    while true; do
      read -rep "Enter SSH public key: " input_ssh_pbk

      if validate_ssh_key "$input_ssh_pbk"; then
        break
      else
        log_error "Invalid SSH public key. Include 'ssh-rsa' or 'ssh-ed25519' prefix"
      fi
    done

    export SSH_USER=$(generate_random 8)
    export SSH_USER_PASS=$(generate_random 16)
    export SSH_PORT=$input_ssh_port
  fi

  # WARP configuration
  read -rep "Install WARP for Russian websites? [y/N] " configure_warp

  # Enable BBR
  enable_bbr

  # Install tools
  install_yq
  install_docker

  # Generate common variables
  export IP_CADDY=$(hostname -I | cut -d' ' -f1)
  export CADDY_BASIC_AUTH=$(docker run --rm caddy caddy hash-password --plaintext "${SSH_USER_PASS:-$(generate_random 16)}")

  # Setup chosen panel
  case $panel_type in
    remnawave)
      setup_remnawave
      ;;
    marzban|xray)
      setup_xray "$panel_type"
      ;;
  esac

  # Configure SSH and firewall if requested
  if [[ "${configure_ssh,,}" == "y" ]]; then
    configure_ssh "$SSH_PORT" "$input_ssh_pbk" "$SSH_USER"
    configure_firewall "$SSH_PORT"
  fi

  # Install WARP if requested
  if [[ "${configure_warp,,}" == "y" ]]; then
    install_warp "$panel_type"
  fi

  # Finalize
  finalize_installation "$panel_type"
}

# Run main function
main

# Restore error handling
set +e
