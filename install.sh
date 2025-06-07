#!/bin/bash

# A script to automate the installation and configuration of Xray with Nginx,
# optional Cloudflare integration, and WARP for selective traffic routing.
#
# Author: GoodyOG (with assistance from Gemini)
# Version: 2.2 - Fixed input handling for curl|bash execution

# --- Color Definitions ---
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
reset=$(tput sgr0)

# --- Global Variables ---
configPath='/usr/local/etc/xray/config.json'
nginxPath='/etc/nginx/conf.d/xray.conf'
xrayPort=16500 # Default Xray listen port
userDomain=""
wsPath="/$(openssl rand -hex 8)" # Generate a random WebSocket path
useCloudflareProxy=false
cfApiToken=""
cfEmail=""

# --- Utility Functions ---

isRoot() {
    if [[ "$EUID" -ne '0' ]]; then
        echo "${red}Error: This script must be run as root. Please use 'sudo'.${reset}"
        exit 1
    fi
}

identifyOS() {
    if [[ "$(uname)" != 'Linux' ]]; then
        echo "${red}Error: This operating system is not supported.${reset}"
        exit 1
    fi
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
        'ubuntu' | 'debian')
            PACKAGE_MANAGEMENT_INSTALL='apt -y --no-install-recommends install'
            PACKAGE_MANAGEMENT_REMOVE='apt purge -y'
            PACKAGE_MANAGEMENT_UPDATE='apt update'
            package_provide_tput='ncurses-bin'
            package_provide_certbot='certbot python3-certbot-nginx'
            ;;
        'centos' | 'rhel' | 'fedora' | 'almalinux')
            if [[ "$(type -P dnf)" ]]; then
                PACKAGE_MANAGEMENT_INSTALL='dnf -y install'
                PACKAGE_MANAGEMENT_REMOVE='dnf remove -y'
                PACKAGE_MANAGEMENT_UPDATE='dnf update'
            else
                PACKAGE_MANAGEMENT_INSTALL='yum -y install'
                PACKAGE_MANAGEMENT_REMOVE='yum remove -y'
                PACKAGE_MANAGEMENT_UPDATE='yum update'
            fi
            ${PACKAGE_MANAGEMENT_INSTALL} 'epel-release' &>/dev/null
            package_provide_tput='ncurses'
            package_provide_certbot='certbot python3-certbot-nginx'
            ;;
        *)
            echo "${red}Error: The script does not support the package manager in this OS: $ID.${reset}"
            exit 1
            ;;
        esac
    else
        echo "${red}Error: Can't identify the operating system.${reset}"
        exit 1
    fi
}

isCommandExists() {
    command -v "$1" &>/dev/null
}

installPackage() {
    local package_name="$1"
    local command_to_check
    command_to_check=$(echo "$package_name" | awk '{print $1}')
    if ! isCommandExists "$command_to_check"; then
        echo "Info: Installing $package_name..."
        if ! ${PACKAGE_MANAGEMENT_INSTALL} ${package_name}; then
            echo "${red}Error: Installation of $package_name failed. Please check your network or install it manually.${reset}"
            exit 1
        fi
    fi
}

# --- Input and Validation Functions ---

inputDomain() {
    read -rp "${green}Please enter your domain name (e.g., mydomain.com):${reset} " userDomain < /dev/tty
    if [[ ! $userDomain =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$ ]]; then
        echo "${red}Invalid domain format. Please try again.${reset}"
        inputDomain
    fi
}

promptCloudflareUsage() {
    read -rp "${green}Are you using Cloudflare's proxy (orange cloud) for this domain? (y/n):${reset} " choice < /dev/tty
    case "$choice" in
        y|Y) useCloudflareProxy=true ;;
        n|N) useCloudflareProxy=false ;;
        *) echo "${red}Invalid input. Please enter 'y' or 'n'.${reset}"; promptCloudflareUsage ;;
    esac
}

inputCloudflareApi() {
    echo "Info: To use Cloudflare's DNS-01 challenge, API credentials are required."
    read -rp "${green}Please enter your Cloudflare Global API Key or an API Token with Zone:DNS edit permissions:${reset} " cfApiToken < /dev/tty
    read -rp "${green}Please enter your Cloudflare account email address:${reset} " cfEmail < /dev/tty
    if [[ -z "$cfApiToken" || -z "$cfEmail" ]]; then
        echo "${red}Both API Key/Token and Email are required.${reset}"
        inputCloudflareApi
    fi
}

# --- Certificate Management ---

getCertWithAcme() {
    echo "Info: Installing acme.sh and obtaining certificate via DNS-01..."
    installPackage "socat"
    
    if ! isCommandExists 'acme.sh'; then
        curl https://get.acme.sh | sh -s email="$cfEmail"
        source "/root/.acme.sh/acme.sh.env"
    fi
    
    export CF_Token="$cfApiToken"
    export CF_Email="$cfEmail"

    if ! ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$userDomain" -d "www.$userDomain" -k ec-256; then
        echo "${red}Error: Failed to issue certificate using acme.sh. Please check your Cloudflare API credentials and DNS settings.${reset}"
        exit 1
    fi
    
    local ssl_cert_dir="/etc/nginx/ssl/$userDomain"
    mkdir -p "$ssl_cert_dir"
    if ! ~/.acme.sh/acme.sh --install-cert -d "$userDomain" --ecc \
        --key-file       "$ssl_cert_dir/private.key" \
        --fullchain-file "$ssl_cert_dir/cert.pem"; then
        echo "${red}Error: Failed to install the certificate.${reset}"
        exit 1
    fi
    echo "Info: Certificate obtained and installed successfully."
}

getCertWithCertbot() {
    echo "Info: Installing Certbot and obtaining certificate via HTTP-01..."
    installPackage "$package_provide_certbot"
    
    echo "Info: Temporarily stopping Nginx for Certbot standalone challenge..."
    systemctl stop nginx &>/dev/null
    
    if ! certbot certonly --standalone -d "$userDomain" -d "www.$userDomain" --agree-tos -n -m "$cfEmail" --preferred-challenges http; then
        echo "${red}Error: Certbot failed to obtain a certificate. Please ensure your domain points to this server's IP and port 80 is accessible.${reset}"
        exit 1
    fi
    
    echo "Info: Certificate obtained successfully."
}

# --- Core Installation and Configuration ---

setupFakeWebsite() {
    echo "Info: Setting up a camouflage website..."
    local web_dir="/var/www/$userDomain/html"
    mkdir -p "$web_dir"
    cat > "$web_dir/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome!</title>
    <style>
        body { font-family: sans-serif; line-height: 1.6; text-align: center; margin-top: 5em; }
    </style>
</head>
<body>
    <h1>Success!</h1>
    <p>This server is up and running.</p>
</body>
</html>
EOF
    chown -R www-data:www-data "/var/www/$userDomain"
}

writeNginxConfig() {
    echo "Info: Configuring Nginx..."
    local ssl_cert_path
    local ssl_key_path

    if $useCloudflareProxy; then
        ssl_cert_path="/etc/nginx/ssl/$userDomain/cert.pem"
        ssl_key_path="/etc/nginx/ssl/$userDomain/private.key"
    else
        ssl_cert_path="/etc/letsencrypt/live/$userDomain/fullchain.pem"
        ssl_key_path="/etc/letsencrypt/live/$userDomain/privkey.pem"
    fi

    rm -f /etc/nginx/sites-enabled/default
    rm -f /etc/nginx/conf.d/default.conf

    cat > "$nginxPath" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $userDomain www.$userDomain;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $userDomain www.$userDomain;
    ssl_certificate $ssl_cert_path;
    ssl_certificate_key $ssl_key_path;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    root /var/www/$userDomain/html;
    index index.html;
    location / {
        try_files \$uri \$uri/ =404;
    }
    location $wsPath {
        if (\$http_upgrade != "websocket") {
            return 404;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$xrayPort;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
}

writeXrayConfig() {
    echo "Info: Configuring Xray..."
    local uuid
    uuid=$(cat /proc/sys/kernel/random/uuid)

    cat > "$configPath" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "127.0.0.1", "port": $xrayPort, "protocol": "vless",
      "settings": {
        "clients": [ { "id": "$uuid", "level": 0 } ], "decryption": "none"
      },
      "streamSettings": {
        "network": "ws", "wsSettings": { "path": "$wsPath" }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom" },
    {
      "tag": "warp", "protocol": "socks",
      "settings": { "servers": [ { "address": "127.0.0.1", "port": 40000 } ] }
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "outboundTag": "warp", "domain": ["geosite:openai"] }
    ]
  }
}
EOF
}

installWarp() {
    echo "Info: Installing Cloudflare WARP..."
    if isCommandExists 'warp-cli'; then
        echo "Info: WARP is already installed."
        return
    fi
    
    if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID" == "fedora" || "$ID" == "almalinux" ]]; then
        rpm -ivh "https://pkg.cloudflareclient.com/cloudflare-release-el$(grep -oP '(?<=VERSION_ID=")\d' /etc/os-release).rpm"
    fi
    ${PACKAGE_MANAGEMENT_UPDATE}
    installPackage "cloudflare-warp"
}

configWarp() {
    echo "Info: Configuring WARP..."
    warp-cli --accept-tos registration new &>/dev/null
    warp-cli set-mode proxy
    warp-cli connect
    sleep 3
    if curl -s -x socks5://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace/ | grep -q "warp=on"; then
        echo "${green}Success:${reset} WARP is connected and working."
    else
        echo "${yellow}Warning:${reset} Could not verify WARP connection. It might not work as expected."
    fi
}

install() {
    isRoot
    identifyOS
    
    inputDomain
    promptCloudflareUsage

    echo "Info: Preparing the system and installing dependencies..."
    ${PACKAGE_MANAGEMENT_UPDATE}
    installPackage "nginx"
    installPackage "curl"
    installPackage "gpg"
    installPackage "jq"
    installPackage "qrencode"
    
    if $useCloudflareProxy; then
        inputCloudflareApi
        getCertWithAcme
    else
        read -rp "${green}Please enter an email for Certbot (for renewal notices):${reset} " cfEmail < /dev/tty
        getCertWithCertbot
    fi
    
    echo "Info: Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-logfiles
    installWarp

    setupFakeWebsite
    writeXrayConfig
    writeNginxConfig
    configWarp

    echo "Info: Finalizing setup and starting services..."
    if ! nginx -t; then
        echo "${red}Error: Nginx configuration test failed. Please check the logs.${reset}"
        exit 1
    fi
    systemctl restart nginx
    systemctl restart xray
    systemctl enable nginx
    systemctl enable xray

    echo -e "\n\n${yellow}=========================================="
    echo -e "         Installation Complete!         "
    echo -e "==========================================${reset}\n"
    getShareUrl
    create_shortcut
}

create_shortcut() {
    echo "Info: Creating 'xray-menu' command for easy access..."
    
    local script_path="/usr/local/bin/xray-installer.sh"
    # Self-copy the script to a permanent location
    cat "$0" > "$script_path"
    chmod +x "$script_path"

    if [ -L "/usr/local/bin/xray-menu" ] || [ -f "/usr/local/bin/xray-menu" ]; then
        echo "Info: 'xray-menu' command already exists."
    else
        if ln -s "$script_path" /usr/local/bin/xray-menu; then
            echo "${green}Success! You can now run 'xray-menu' from anywhere to manage your setup.${reset}"
        else
            echo "${yellow}Warning:${reset} Could not create the 'xray-menu' command automatically."
        fi
    fi
}

getShareUrl() {
    if [[ ! -f $configPath ]]; then
        echo "${red}Error: Xray config file not found. Please install first.${reset}"
        return 1
    fi
    local uuid
    uuid=$(jq -r ".inbounds[0].settings.clients[0].id" $configPath)
    local address="$userDomain"

    local shareUrl="vless://${uuid}@${address}:443?encryption=none&security=tls&sni=${userDomain}&type=ws&host=${userDomain}&path=${wsPath}#${userDomain}-VLESS"
    
    echo -e "${green}Your VLESS configuration link:${reset}"
    echo -e "${yellow}${shareUrl}${reset}"
    
    echo -e "\n${green}Scan the QR code to import:${reset}"
    qrencode -t ANSIUTF8 "$shareUrl"
}

uninstall() {
    echo "${red}Warning: This will remove Xray, Nginx, Certbot/acme.sh certs, and WARP.${reset}"
    read -rp "Are you sure you want to proceed? (y/n): " confirm < /dev/tty
    if [[ "$confirm" != "y" ]]; then
        echo "Info: Uninstallation cancelled."
        exit 0
    fi

    systemctl stop nginx xray
    systemctl disable nginx xray

    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge &>/dev/null
    
    if isCommandExists 'warp-cli'; then warp-cli disconnect &>/dev/null; warp-cli delete &>/dev/null; fi
    ${PACKAGE_MANAGEMENT_REMOVE} cloudflare-warp &>/dev/null
    ${PACKAGE_MANAGEMENT_REMOVE} nginx* &>/dev/null
    ${PACKAGE_MANAGEMENT_REMOVE} $package_provide_certbot &>/dev/null

    rm -rf /usr/local/etc/xray /var/log/xray
    rm -rf /etc/nginx/ssl /etc/nginx/conf.d/xray.conf /etc/letsencrypt
    rm -rf /var/www/"$userDomain"
    rm -rf /root/.acme.sh
    rm -f /usr/local/bin/xray-menu /usr/local/bin/xray-installer.sh

    echo "${green}Info: All components have been uninstalled.${reset}"
}

main_menu() {
    clear
    echo -e "\n${yellow}Xray & Nginx Automation Script by GoodyOG (v2.2)${reset}"
    echo "----------------------------------------------------"
    echo -e "${green}1.${reset} Install Xray (VLESS + WS + TLS)"
    echo -e "${green}2.${reset} Uninstall All Components"
    echo -e "${green}3.${reset} Show Connection Link / QR Code"
    echo -e "${red}4.${reset} Exit"
    echo "----------------------------------------------------"
    read -rp "Please select an option [1-4]: " menu_choice < /dev/tty

    case $menu_choice in
        1) install ;;
        2) uninstall ;;
        3) getShareUrl ;;
        4) exit 0 ;;
        *) echo "${red}Invalid option. Please try again.${reset}"; sleep 2; main_menu ;;
    esac
}

# Logic to handle being run from curl vs. locally
# When piped from curl, stdin is not a terminal, so -t 0 is false.
if [ -t 0 ]; then
    main_menu
else
    install
fi
