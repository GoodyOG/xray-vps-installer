#!/bin/bash

# ==============================================================================
# All-in-One Xray Server Management Script
# Author: GoodyOG (with assistance from Gemini)
# Version: 6.0
# ==============================================================================

# --- Globals and Colors ---
export SCRIPT_PATH="/usr/local/bin/xray-menu"
export XRAY_CONFIG_PATH="/usr/local/etc/xray/config.json"
export NGINX_CONFIG_PATH="/etc/nginx/conf.d/xray.conf"

red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
blue=$(tput setaf 4)
reset=$(tput sgr0)

# ==============================================================================
# SECTION 1: UTILITY AND HELPER FUNCTIONS
# ==============================================================================

isRoot() {
    if [[ "$EUID" -ne '0' ]]; then
        echo "${red}Error: This script must be run as root.${reset}"
        exit 1
    fi
}

installPackage() {
    local pkg_name="$1"
    if ! command -v "$pkg_name" &>/dev/null; then
        echo "Info: Installing $pkg_name..."
        if ! (apt-get -y --no-install-recommends install "$pkg_name" || yum -y install "$pkg_name" || dnf -y install "$pkg_name") &>/dev/null; then
            echo "${red}Error: Installation of $pkg_name failed.${reset}"
            return 1
        fi
    fi
}

restartServices() {
    echo "Info: Restarting Xray..."
    systemctl restart xray
    echo "Info: Restarting Nginx..."
    systemctl restart nginx
}

# ==============================================================================
# SECTION 2: CORE INSTALLATION
# ==============================================================================

# ... [Cloudflare API, Certbot, Nginx/Xray Config functions from v5 remain here] ...
# NOTE: Using the robust API-based cert installation from the last version

getCertWithAutomatedToggling() {
    local userDomain="$1"
    local userEmail="$2"
    local cfApiToken="$3"
    local zone_id dns_record_id

    trap 'echo "Restoring CF proxy..."; set_proxy_status true "$zone_id" "$dns_record_id" "$cfApiToken"' EXIT

    echo "Info: Finding Cloudflare Zone ID for $userDomain..."
    local domain_suffix=$(echo "$userDomain" | awk -F. '{print $(NF-1)"."$NF}')
    zone_info=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$domain_suffix" -H "Authorization: Bearer $cfApiToken" -H "Content-Type: application/json")
    zone_id=$(echo "$zone_info" | jq -r '.result[0].id')
    if [[ "$zone_id" == "null" || -z "$zone_id" ]]; then echo "${red}Error: Could not find Zone ID.${reset}"; exit 1; fi

    echo "Info: Finding DNS Record ID for $userDomain..."
    dns_records=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=A&name=$userDomain" -H "Authorization: Bearer $cfApiToken" -H "Content-Type: application/json")
    dns_record_id=$(echo "$dns_records" | jq -r '.result[0].id')
    if [[ "$dns_record_id" == "null" || -z "$dns_record_id" ]]; then echo "${red}Error: Could not find A record.${reset}"; exit 1; fi

    set_proxy_status false "$zone_id" "$dns_record_id" "$cfApiToken"
    echo "Info: Waiting 20 seconds for DNS to propagate..."
    sleep 20
    
    echo "Info: Requesting Let's Encrypt certificate..."
    systemctl stop nginx &>/dev/null
    if ! certbot certonly --standalone -d "$userDomain" --agree-tos -n -m "$userEmail" --preferred-challenges http; then
        echo "${red}Error: Certbot failed.${reset}"; exit 1;
    fi
    
    set_proxy_status true "$zone_id" "$dns_record_id" "$cfApiToken"
    trap - EXIT
    echo "${green}Success! Certificate obtained and proxy re-enabled.${reset}"
}

set_proxy_status() {
    local proxied="$1"
    local zone_id="$2"
    local dns_record_id="$3"
    local cfApiToken="$4"
    echo "Info: Setting Cloudflare proxy to $proxied..."
    curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$dns_record_id" -H "Authorization: Bearer $cfApiToken" -H "Content-Type: application/json" --data "{\"proxied\":$proxied}" > /dev/null
}

writeNginxConfig() {
    local userDomain="$1"
    local wsPath="$2"
    local xrayPort=16500
    local ssl_cert_path="/etc/letsencrypt/live/$userDomain/fullchain.pem"
    local ssl_key_path="/etc/letsencrypt/live/$userDomain/privkey.pem"
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf

    cat > "$NGINX_CONFIG_PATH" <<EOF
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
    location / { return 200 "Online."; }
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

writeXrayConfigInitial() {
    local clientName="$1"
    local uuid="$2"
    local wsPath="$3"
    local xrayPort=16500

    cat > "$XRAY_CONFIG_PATH" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": $xrayPort,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "email": "$clientName"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "$wsPath"
        }
      }
    }
  ],
  "outbounds": [
    {"protocol": "freedom", "tag": "direct"},
    {
      "protocol": "socks",
      "tag": "warp-socks",
      "settings": {
        "servers": [{"address": "127.0.0.1", "port": 40000}]
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "outboundTag": "warp-socks",
        "domain": []
      }
    ]
  }
}
EOF
}

# ==============================================================================
# SECTION 3: MENU ACTIONS
# ==============================================================================

installBBR() {
    echo "Info: Installing BBR..."
    if grep -q "BBR" /etc/sysctl.conf; then
        echo "${yellow}BBR seems to be already enabled.${reset}"
        return
    fi
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    echo "${green}BBR enabled. A reboot is recommended to ensure it's fully active.${reset}"
}

installWarp() {
    echo "Info: Installing Cloudflare WARP..."
    if command -v warp-cli &> /dev/null; then
        echo "${yellow}WARP is already installed.${reset}"; return;
    fi
    (apt update || yum update || dnf update) &>/dev/null
    curl -fsSL https://pkg.cloudflareclient.com/install.sh | bash
    warp-cli --accept-tos registration new
    warp-cli set-mode proxy
    warp-cli connect
    echo "${green}WARP installed and connected.${reset}"
}

addVlessUser() {
    read -rp "Enter a name for the new user (e.g., my-phone): " clientName
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    jq ".inbounds[0].settings.clients += [{\"id\": \"$uuid\", \"email\": \"$clientName\"}]" "$XRAY_CONFIG_PATH" > "$XRAY_CONFIG_PATH.tmp" && mv "$XRAY_CONFIG_PATH.tmp" "$XRAY_CONFIG_PATH"
    restartServices
    echo "${green}User '$clientName' added.${reset}"
    generateShareLink "$uuid" "$clientName"
}

deleteVlessUser() {
    client_list=$(jq -r '.inbounds[0].settings.clients[] | "\(.email)"' "$XRAY_CONFIG_PATH")
    if [[ $(echo "$client_list" | wc -l) -le 1 ]]; then
        echo "${red}Cannot delete the last user.${reset}"; return;
    fi
    
    echo "Select user to delete:"
    select clientName in $client_list; do
        if [[ -n "$clientName" ]]; then
            jq "del(.inbounds[0].settings.clients[] | select(.email == \"$clientName\"))" "$XRAY_CONFIG_PATH" > "$XRAY_CONFIG_PATH.tmp" && mv "$XRAY_CONFIG_PATH.tmp" "$XRAY_CONFIG_PATH"
            restartServices
            echo "${green}User '$clientName' deleted.${reset}"
            break
        else
            echo "${red}Invalid selection.${reset}"
        fi
    done
}

listVlessUsers() {
    jq -r '.inbounds[0].settings.clients[] | "User: \(.email)\nUUID: \(.id)\n"' "$XRAY_CONFIG_PATH"
    read -rp "Generate QR/Link for which user? (Enter name, or press Enter to skip): " clientName
    if [[ -n "$clientName" ]]; then
        uuid=$(jq -r ".inbounds[0].settings.clients[] | select(.email==\"$clientName\") | .id" "$XRAY_CONFIG_PATH")
        if [[ -n "$uuid" ]]; then generateShareLink "$uuid" "$clientName"; fi
    fi
}

generateShareLink() {
    local uuid="$1"
    local clientName="$2"
    local domain=$(grep -m 1 "server_name" "$NGINX_CONFIG_PATH" | awk '{print $2}' | sed 's/;//')
    local wsPath=$(jq -r '.inbounds[0].streamSettings.wsSettings.path' "$XRAY_CONFIG_PATH")
    local shareUrl="vless://${uuid}@${domain}:443?encryption=none&security=tls&sni=${domain}&type=ws&host=${domain}&path=${wsPath}#${clientName}"
    echo -e "${yellow}${shareUrl}${reset}"
    qrencode -t ANSIUTF8 "$shareUrl"
}

addDomainToWarp() {
    read -rp "Enter domain to route via WARP (e.g., netflix.com or geosite:google): " warp_domain
    jq ".routing.rules[0].domain += [\"$warp_domain\"]" "$XRAY_CONFIG_PATH" > "$XRAY_CONFIG_PATH.tmp" && mv "$XRAY_CONFIG_PATH.tmp" "$XRAY_CONFIG_PATH"
    restartServices
    echo "${green}Domain '$warp_domain' will now be routed through WARP.${reset}"
}

removeDomainFromWarp() {
    domain_list=$(jq -r '.routing.rules[0].domain[]' "$XRAY_CONFIG_PATH")
    if [[ -z "$domain_list" ]]; then echo "${red}WARP domain list is empty.${reset}"; return; fi
    
    echo "Select domain to remove from WARP routing:"
    select domain in $domain_list; do
        if [[ -n "$domain" ]]; then
            jq "del(.routing.rules[0].domain[] | select(. == \"$domain\"))" "$XRAY_CONFIG_PATH" > "$XRAY_CONFIG_PATH.tmp" && mv "$XRAY_CONFIG_PATH.tmp" "$XRAY_CONFIG_PATH"
            restartServices
            echo "${green}Domain '$domain' removed from WARP routing.${reset}"
            break
        fi
    done
}

viewLogs() {
    read -p "View logs for [1] Xray or [2] Nginx? " choice
    case "$choice" in
        1) journalctl -u xray -f --no-pager ;;
        2) tail -f /var/log/nginx/access.log ;;
        *) echo "Invalid choice." ;;
    esac
}

# ==============================================================================
# SECTION 4: MENUS
# ==============================================================================

show_xray_menu() {
    clear
    echo -e "${blue}--- Xray User & Routing Management ---${reset}"
    echo "1. Add VLESS User"
    echo "2. Delete VLESS User"
    echo "3. List VLESS Users / Get Links"
    echo "4. Add Domain to WARP Route"
    echo "5. Remove Domain from WARP Route"
    echo "6. List WARP-Routed Domains"
    echo "0. Back to Main Menu"
    read -rp "Select an option: " choice
    case "$choice" in
        1) addVlessUser ;;
        2) deleteVlessUser ;;
        3) listVlessUsers ;;
        4) addDomainToWarp ;;
        5) removeDomainFromWarp ;;
        6) echo "Domains routed via WARP:"; jq -r '.routing.rules[0].domain[]' "$XRAY_CONFIG_PATH" ;;
        0) return ;;
        *) echo "${red}Invalid option.${reset}" ;;
    esac
    read -n 1 -s -r -p "Press any key to continue..."
}

show_server_menu() {
    clear
    echo -e "${blue}--- Server & Service Management ---${reset}"
    echo "1. Install/Enable BBR"
    echo "2. Install/Connect WARP"
    echo "3. Check Service Status"
    echo "4. Restart Services (Xray & Nginx)"
    echo "5. View Live Logs"
    echo "6. Update Xray-core"
    echo "0. Back to Main Menu"
    read -rp "Select an option: " choice
    case "$choice" in
        1) installBBR ;;
        2) installWarp ;;
        3) systemctl status xray nginx ;;
        4) restartServices ;;
        5) viewLogs ;;
        6) bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install ;;
        0) return ;;
        *) echo "${red}Invalid option.${reset}" ;;
    esac
    read -n 1 -s -r -p "Press any key to continue..."
}

main_menu() {
    while true; do
        clear
        echo -e "${yellow}Xray All-in-One Management Panel (v6.0)${reset}"
        echo -e "Domain: ${green}$(grep -m 1 "server_name" "$NGINX_CONFIG_PATH" | awk '{print $2}' | sed 's/;//')${reset}"
        echo "----------------------------------------"
        echo "1. Manage Xray Users & Routing"
        echo "2. Manage Server & Services"
        echo "9. Uninstall Everything"
        echo "0. Exit"
        echo "----------------------------------------"
        read -rp "Select an option: " choice
        case "$choice" in
            1) show_xray_menu ;;
            2) show_server_menu ;;
            9) uninstall_all ;;
            0) break ;;
            *) echo "${red}Invalid option.${reset}"; sleep 1 ;;
        esac
    done
}

# ==============================================================================
# SECTION 5: INITIAL INSTALLATION & ENTRY POINT
# ==============================================================================

uninstall_all() {
    read -rp "${red}This will permanently delete everything. Are you sure? (y/n): ${reset}" confirm
    if [[ "$confirm" == "y" ]]; then
        systemctl stop xray nginx
        systemctl disable xray nginx
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
        (apt-get -y purge nginx* certbot* || yum -y remove nginx* certbot* || dnf -y remove nginx* certbot*)
        rm -rf /usr/local/etc/xray /etc/nginx /etc/letsencrypt /var/log/nginx
        rm -f "$SCRIPT_PATH"
        echo "${green}Uninstallation complete.${reset}"
    fi
}

first_time_install() {
    isRoot
    echo -e "${yellow}Welcome to the Xray All-in-One installer!${reset}"
    
    # Install base packages
    (apt-get update || yum update || dnf update) &>/dev/null
    installPackage "curl"
    installPackage "jq"
    installPackage "qrencode"
    
    # Get user info
    read -rp "Enter your domain name: " userDomain
    read -rp "Enter your email (for Let's Encrypt): " userEmail
    read -rp "Enter your Cloudflare API Token (with DNS Edit permissions): " cfApiToken

    # Get Cert
    getCertWithAutomatedToggling "$userDomain" "$userEmail" "$cfApiToken"
    
    # Install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-logfiles
    
    # Configure
    local initial_client="default-user"
    local initial_uuid=$(cat /proc/sys/kernel/random/uuid)
    local wsPath="/$(openssl rand -hex 8)"
    writeXrayConfigInitial "$initial_client" "$initial_uuid" "$wsPath"
    writeNginxConfig "$userDomain" "$wsPath"
    
    # Optional components
    read -rp "Do you want to install WARP now? (y/n): " warp_choice
    if [[ "$warp_choice" == "y" ]]; then installWarp; fi
    read -rp "Do you want to enable BBR now? (y/n): " bbr_choice
    if [[ "$bbr_choice" == "y" ]]; then installBBR; fi
    
    # Start services
    restartServices
    
    # Save script
    cat "$0" > "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    
    echo -e "\n${green}=======================================================${reset}"
    echo -e "      ✅ Installation Complete! ✅"
    echo -e "You can now run ${yellow}xray-menu${reset} anytime to manage your server."
    echo -e "${green}=======================================================${reset}\n"
    generateShareLink "$initial_uuid" "$initial_client"
}

# --- Entry Point ---
if [[ -f "$XRAY_CONFIG_PATH" ]]; then
    main_menu
else
    first_time_install
fi
