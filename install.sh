#!/bin/bash

# A script to automate the installation of Xray with Nginx using a Cloudflare Origin Certificate.
#
# Author: GoodyOG (with assistance from Gemini)
# Version: 4.0 - Simplified to use Cloudflare Origin Certificates, removing all API and Certbot requirements.

# --- Color Definitions ---
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
reset=$(tput sgr0)

# --- Global Variables ---
configPath='/usr/local/etc/xray/config.json'
nginxPath='/etc/nginx/conf.d/xray.conf'
certPath="/etc/nginx/ssl/cert.pem"
keyPath="/etc/nginx/ssl/private.key"
xrayPort=16500
userDomain=""
wsPath="/$(openssl rand -hex 8)"

# --- Utility Functions ---

isRoot() {
    if [[ "$EUID" -ne '0' ]]; then
        echo "${red}Error: This script must be run as root. Please use 'sudo'.${reset}"
        exit 1
    fi
}

installPackage() {
    local package_name="$1"
    if ! command -v "$package_name" &>/dev/null; then
        echo "Info: Installing $package_name..."
        if ! (apt -y --no-install-recommends install "$package_name" || yum -y install "$package_name" || dnf -y install "$package_name") &>/dev/null; then
            echo "${red}Error: Installation of $package_name failed. Please check your system.${reset}"
            exit 1
        fi
    fi
}

# --- Input and Configuration ---

inputDomain() {
    read -rp "${green}Enter your domain name (the one used for the Origin Certificate):${reset} " userDomain
    if [[ ! $userDomain =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$ ]]; then
        echo "${red}Invalid domain format. Please try again.${reset}"
        inputDomain
    fi
}

inputCertificates() {
    echo -e "${yellow}Please copy the 'Origin Certificate' text from your Cloudflare dashboard.${reset}"
    echo -e "${yellow}Paste it here, then type 'EOF' on a new line and press Enter:${reset}"
    local cert_input
    cert_input=$(cat)
    if [[ -z "$cert_input" ]]; then
        echo "${red}Certificate cannot be empty. Please try again.${reset}"
        inputCertificates
    else
        echo "$cert_input" > "$certPath"
    fi

    echo -e "\n${yellow}Now, please copy the 'Private Key' text from your Cloudflare dashboard.${reset}"
    echo -e "${yellow}Paste it here, then type 'EOF' on a new line and press Enter:${reset}"
    local key_input
    key_input=$(cat)
    if [[ -z "$key_input" ]]; then
        echo "${red}Private key cannot be empty. Please try again.${reset}"
        # Clean up the cert file before retrying
        rm "$certPath"
        inputCertificates
    else
        echo "$key_input" > "$keyPath"
    fi
}

writeNginxConfig() {
    echo "Info: Configuring Nginx..."
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf

    cat > "$nginxPath" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $userDomain www.$userDomain;
    # Redirect all HTTP traffic to HTTPS, handled by Cloudflare
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $userDomain www.$userDomain;

    ssl_certificate $certPath;
    ssl_certificate_key $keyPath;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;

    # A simple page to show the server is alive
    location / {
        return 200 "Welcome.";
        add_header Content-Type text/plain;
    }

    location $wsPath {
        if (\$http_upgrade != "websocket") { return 404; }
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
        "clients": [ { "id": "$uuid" } ], "decryption": "none"
      },
      "streamSettings": {
        "network": "ws", "wsSettings": { "path": "$wsPath" }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom" } ]
}
EOF
}

install() {
    isRoot
    
    echo -e "${yellow}Welcome to the simplified Xray installer!${reset}"
    echo -e "${yellow}Please ensure you have your Cloudflare Origin Certificate and Private Key ready.${reset}"
    
    inputDomain
    
    echo "Info: Installing dependencies..."
    (apt update || yum update || dnf update) &>/dev/null
    installPackage "nginx"
    installPackage "curl"
    installPackage "jq"
    installPackage "qrencode"
    
    echo "Info: Setting up SSL directory..."
    mkdir -p /etc/nginx/ssl
    
    inputCertificates
    
    echo "Info: Installing Xray-core..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-logfiles
    
    writeXrayConfig
    writeNginxConfig
    
    echo "Info: Finalizing setup and starting services..."
    if ! nginx -t; then
        echo "${red}Error: Nginx configuration test failed.${reset}"
        exit 1
    fi
    systemctl restart nginx
    systemctl restart xray
    systemctl enable nginx
    systemctl enable xray

    echo -e "\n${green}-----------------------------------------------------------"
    echo -e "         ✅ Installation Complete! ✅"
    echo -e "Make sure your Cloudflare SSL/TLS mode is 'Full (strict)'."
    echo -e "-----------------------------------------------------------\n${reset}"
    
    getShareUrl
}

getShareUrl() {
    local uuid=$(jq -r ".inbounds[0].settings.clients[0].id" "$configPath")
    local shareUrl="vless://${uuid}@${userDomain}:443?encryption=none&security=tls&sni=${userDomain}&type=ws&host=${userDomain}&path=${wsPath}#${userDomain}-Origin"
    
    echo -e "${green}Your VLESS configuration link:${reset}"
    echo -e "${yellow}${shareUrl}${reset}"
    echo -e "\n${green}QR Code:${reset}"
    qrencode -t ANSIUTF8 "$shareUrl"
}

# --- Script Entry Point ---
install
