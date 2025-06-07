#!/bin/bash

# A script that automates the Xray/Nginx installation by temporarily toggling the
# Cloudflare proxy to acquire a Let's Encrypt certificate.
#
# Author: GoodyOG (with assistance from Gemini)
# Version: 5.0 - The Definitive "Tutorial Replica"

# --- Color Definitions ---
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
reset=$(tput sgr0)

# --- Global Variables ---
configPath='/usr/local/etc/xray/config.json'
nginxPath='/etc/nginx/conf.d/xray.conf'
xrayPort=16500
userDomain=""
wsPath="/$(openssl rand -hex 8)"
userEmail=""
cfApiToken=""
zone_id=""
dns_record_id=""

# --- Utility Functions ---

isRoot() {
    if [[ "$EUID" -ne '0' ]]; then
        echo "${red}Error: This script must be run as root. Please use 'sudo'.${reset}"
        exit 1
    fi
}

installPackage() {
    local pkg_name="$1"
    if ! command -v "$pkg_name" &>/dev/null; then
        echo "Info: Installing $pkg_name..."
        if ! (apt-get -y --no-install-recommends install "$pkg_name" || yum -y install "$pkg_name" || dnf -y install "$pkg_name") &>/dev/null; then
            echo "${red}Error: Installation of $pkg_name failed.${reset}"
            exit 1
        fi
    fi
}

# --- Cloudflare API Functions ---

# Function to set Cloudflare proxy status.
# $1: boolean (true for orange cloud, false for gray cloud)
set_proxy_status() {
    local proxied="$1"
    echo "Info: Setting Cloudflare proxy status to $proxied (orange cloud = true)..."
    
    response=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$dns_record_id" \
         -H "Authorization: Bearer $cfApiToken" \
         -H "Content-Type: application/json" \
         --data "{\"proxied\":$proxied}")

    if [[ $(echo "$response" | jq -r .success) != "true" ]]; then
        echo "${red}Error: Failed to change Cloudflare proxy status.${reset}"
        echo "Cloudflare API response: $(echo "$response" | jq .errors)"
        # Do not exit, allow the trap to restore status.
        return 1
    fi
    return 0
}

# Cleanup function to be called on exit
cleanup() {
    if [[ -n "$zone_id" && -n "$dns_record_id" ]]; then
        echo "Info: Ensuring Cloudflare proxy is re-enabled..."
        set_proxy_status true
    fi
}

# --- Certificate Management ---

getCertWithAutomatedToggling() {
    # Set a trap to ensure proxy is re-enabled on any script exit
    trap cleanup EXIT

    echo "Info: Finding Cloudflare Zone ID for $userDomain..."
    local domain_suffix=$(echo "$userDomain" | awk -F. '{print $(NF-1)"."$NF}')
    
    zone_info=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$domain_suffix" \
         -H "Authorization: Bearer $cfApiToken" \
         -H "Content-Type: application/json")

    zone_id=$(echo "$zone_info" | jq -r '.result[0].id')
    if [[ "$zone_id" == "null" || -z "$zone_id" ]]; then
        echo "${red}Error: Could not find Zone ID for $domain_suffix. Please check your domain and API token.${reset}"
        exit 1
    fi

    echo "Info: Finding DNS Record ID for $userDomain..."
    dns_records=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=A&name=$userDomain" \
        -H "Authorization: Bearer $cfApiToken" \
        -H "Content-Type: application/json")

    dns_record_id=$(echo "$dns_records" | jq -r '.result[0].id')
    if [[ "$dns_record_id" == "null" || -z "$dns_record_id" ]]; then
        echo "${red}Error: Could not find an A record for $userDomain. Please ensure it exists.${reset}"
        exit 1
    fi
    
    # This is the core logic
    echo "Info: Temporarily disabling Cloudflare proxy (gray cloud)..."
    set_proxy_status false
    
    echo "Info: Waiting 20 seconds for DNS changes to propagate..."
    sleep 20
    
    echo "Info: Requesting Let's Encrypt certificate..."
    installPackage "certbot"
    installPackage "python3-certbot-nginx"
    
    systemctl stop nginx &>/dev/null
    
    if ! certbot certonly --standalone -d "$userDomain" --agree-tos -n -m "$userEmail" --preferred-challenges http; then
        echo "${red}Error: Certbot failed to get a certificate.${reset}"
        # The trap will handle cleanup
        exit 1
    fi
    
    echo "${green}Success! Certificate obtained.${reset}"
    
    # The trap will automatically re-enable the proxy, but we can call it here for clarity
    cleanup
    # Disable the trap now that we're done.
    trap - EXIT
}

# --- Installation and Configuration ---

writeNginxConfig() {
    echo "Info: Configuring Nginx..."
    local ssl_cert_path="/etc/letsencrypt/live/$userDomain/fullchain.pem"
    local ssl_key_path="/etc/letsencrypt/live/$userDomain/privkey.pem"
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf

    cat > "$nginxPath" <<EOF
server {
    listen 80;
    server_name $userDomain;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name $userDomain;
    ssl_certificate $ssl_cert_path;
    ssl_certificate_key $ssl_key_path;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        return 200 "Online.";
    }
    location $wsPath {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_pass http://127.0.0.1:$xrayPort;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
}

writeXrayConfig() {
    echo "Info: Configuring Xray..."
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    cat > "$configPath" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":$xrayPort,"protocol":"vless","settings":{"clients":[{"id":"$uuid"}],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"path":"$wsPath"}}}],"outbounds":[{"protocol":"freedom"}]}
EOF
}

install() {
    isRoot
    
    echo -e "${yellow}Welcome to the automated Xray installer.${reset}"
    echo -e "This script will use the Cloudflare API to temporarily disable the proxy to get a Let's Encrypt SSL certificate."
    
    read -rp "${green}Enter your domain name:${reset} " userDomain
    read -rp "${green}Enter your email (for Let's Encrypt notices):${reset} " userEmail
    read -rp "${green}Enter your Cloudflare API Token (with DNS Edit permissions):${reset} " cfApiToken

    echo "Info: Installing dependencies..."
    (apt-get update || yum update || dnf update) &>/dev/null
    installPackage "curl"
    installPackage "jq"
    installPackage "nginx"
    installPackage "qrencode"

    getCertWithAutomatedToggling

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
    echo -e "Cloudflare proxy has been automatically re-enabled."
    echo -e "-----------------------------------------------------------\n${reset}"
    
    local uuid=$(jq -r ".inbounds[0].settings.clients[0].id" "$configPath")
    local shareUrl="vless://${uuid}@${userDomain}:443?encryption=none&security=tls&sni=${userDomain}&type=ws&host=${userDomain}&path=${wsPath}#${userDomain}-Auto"
    
    echo -e "${green}Your VLESS configuration link:${reset}"
    echo -e "${yellow}${shareUrl}${reset}"
    echo -e "\n${green}QR Code:${reset}"
    qrencode -t ANSIUTF8 "$shareUrl"
}

# --- Script Entry Point ---
install
