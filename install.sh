#!/bin/bash

# ==========================================
# StarTunnel - اسکریپت یکپارچه تونل‌سازی
# توسعه‌دهنده: MoriiStar
# کانال تلگرام: @ServerStar_ir
# GitHub: https://github.com/Moriistar
# ==========================================

# ---------------- INSTALL DEPENDENCIES ----------------
echo "[*] Updating package list..."
sudo apt update -y

echo "[*] Installing required packages..."
sudo apt install -y iproute2 net-tools grep gawk sudo iputils-ping jq curl haproxy iptables netplan.io screen

# ---------------- COLORS ----------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
TURQUOISE='\033[38;5;45m'
NC='\033[0m'
plain='\033[0m'

# ---------------- GLOBAL VARIABLES ----------------
cur_dir=$(pwd)

[[ $EUID -ne 0 ]] && echo -e "${RED}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

# ---------------- UTILITY FUNCTIONS ----------------
install_jq() {
    if ! command -v jq &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            echo -e "${RED}jq is not installed. Installing...${NC}"
            sleep 1
            sudo apt-get update
            sudo apt-get install -y jq
        else
            echo -e "${RED}Error: Unsupported package manager. Please install jq manually.${NC}\n"
            read -p "Press any key to continue..."
            exit 1
        fi
    fi
}

install_obfs4() {
    if ! command -v obfs4proxy &> /dev/null; then
        echo -e "${YELLOW}Installing obfs4proxy...${NC}"
        sudo apt-get update
        sudo apt-get install -y obfs4proxy
        if ! command -v obfs4proxy &> /dev/null; then
            echo -e "${RED}Failed to install obfs4proxy. Please install it manually.${NC}"
            exit 1
        else
            echo -e "${GREEN}obfs4proxy installed successfully.${NC}"
        fi
    fi
}

configure_obfs4() {
    local obfs4_dir="/etc/obfs4"
    local obfs4_cert="$obfs4_dir/obfs4_cert"
    local obfs4_key="$obfs4_dir/obfs4_key"

    mkdir -p "$obfs4_dir"

    if [ ! -f "$obfs4_cert" ] || [ ! -f "$obfs4_key" ]; then
        echo -e "${YELLOW}Generating obfs4 certificate and private key...${NC}"
        
        openssl genpkey -algorithm RSA -out "$obfs4_key" -pkeyopt rsa_keygen_bits:2048
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to generate private key.${NC}"
            exit 1
        fi

        openssl req -new -x509 -key "$obfs4_key" -out "$obfs4_cert" -days 365 -subj "/CN=obfs4"
        if [ $? -ne 0 ]; then
            echo -e "${RED}Failed to generate certificate.${NC}"
            exit 1
        fi

        echo -e "${GREEN}obfs4 certificate and private key generated successfully.${NC}"
    fi
}

start_obfs4() {
    echo -e "${YELLOW}Starting obfs4 service...${NC}"
    obfs4proxy -logLevel INFO -enableLogging >/dev/null 2>&1 &
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}obfs4 service started successfully.${NC}"
    else
        echo -e "${RED}Failed to start obfs4 service.${NC}"
        exit 1
    fi
}

check_core_status() {
    if ip link show | grep -q 'vxlan\|tunnel0858'; then
        echo -e "${GREEN}Active${NC}"
    else
        echo -e "${RED}Inactive${NC}"
    fi
}

netplan_setup() {
    command -v netplan &> /dev/null || { 
        sudo apt update && sudo apt install -y netplan.io && echo "netplan installed successfully." || echo "Failed to install netplan."; 
    }
}

find_last_tunnel_number() {
    local last_number=0
    for file in /etc/netplan/star-*.yaml; do
        if [ -f "$file" ]; then
            local number=$(echo "$file" | grep -o 'star-[0-9]*' | cut -d'-' -f2)
            if [ "$number" -gt "$last_number" ]; then
                last_number=$number
            fi
        fi
    done
    echo $last_number
}

# ---------------- MAIN MENU FUNCTION ----------------
StarTunnel_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country')
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp')
    tunnel_status=$(check_core_status)

    echo "+-----------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}    ╔═══╦════╦═══╦═══╗        ╔════╦╗─╔╦═╗─╔╦═══╦╗──╔╗${NC}"
    echo -e "${TURQUOISE}    ║╔═╗║╔╗╔╗║╔═╗║╔═╗║        ║╔╗╔╗║║─║║║╚╗║║╔══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ║╚══╬╝║║╚╣║─║║╚═╝║        ╚╝║║╚╣║─║║╔╗╚╝║╚══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ╚══╗║─║║─║╚═╝║╔╗╔╝        ──║║─║║─║║║╚╗║║╔══╣║─╔╣║─╔╗${NC}"
    echo -e "${TURQUOISE}    ║╚═╝║─║║─║╔═╗║║║╚╗        ──║║─║╚═╝║║─║║║╚══╣╚═╝║╚═╝║${NC}"
    echo -e "${TURQUOISE}    ╚═══╝─╚╝─╚╝─╚╩╝╚═╝        ──╚╝─╚═══╩╝─╚═╩═══╩═══╩═══╝${NC}" 
    echo "+-----------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${RED}@ServerStar_ir ${NC}| Developer : ${GREEN} MoriiStar ${NC} "
    echo "+-----------------------------------------------------------------------------+"      
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo -e "|${GREEN}Tunnel Status     |${NC} $tunnel_status"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose an option:${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo "1- Star VXLAN Tunnel"
    echo "2- Star SIT Tunnel" 
    echo "3- Star HAProxy Manager"
    echo "4- Install BBR"
    echo "5- Cronjob Settings"
    echo "6- Uninstall All Tunnels"
    echo "0- Exit"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "\033[0m"
}

# ---------------- VXLAN TUNNEL FUNCTIONS ----------------
install_vxlan_tunnel() {
    clear
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW} Star VXLAN Tunnel Configuration ${NC}"
    echo "+-----------------------------------------------------------------------------+"
    
    # Check if ip command is available
    if ! command -v ip >/dev/null 2>&1; then
        echo "[x] iproute2 is not installed. Aborting."
        exit 1
    fi

    # Variables
    VNI=88
    VXLAN_IF="vxlan${VNI}"

    # Choose Server Role
    echo "Choose server role:"
    echo "1- Iran"
    echo "2- Kharej"
    read -p "Enter choice (1/2): " role_choice

    if [[ "$role_choice" == "1" ]]; then
        read -p "Enter IRAN IP: " IRAN_IP
        read -p "Enter Kharej IP: " KHAREJ_IP

        # Port validation loop
        while true; do
            read -p "Tunnel port (1 ~ 64435): " DSTPORT
            if [[ $DSTPORT =~ ^[0-9]+$ ]] && (( DSTPORT >= 1 && DSTPORT <= 64435 )); then
                break
            else
                echo "Invalid port. Try again."
            fi
        done

        # Haproxy configuration
        while true; do
            read -p "Should port forwarding be done automatically? [1-yes, 2-no]: " haproxy_choice
            if [[ "$haproxy_choice" == "1" || "$haproxy_choice" == "2" ]]; then
                break
            else
                echo "Please enter 1 (yes) or 2 (no)."
            fi
        done
        
        if [[ "$haproxy_choice" == "1" ]]; then
            install_haproxy_and_configure
        fi

        VXLAN_IP="30.0.0.1/24"
        REMOTE_IP=$KHAREJ_IP

    elif [[ "$role_choice" == "2" ]]; then
        read -p "Enter IRAN IP: " IRAN_IP
        read -p "Enter Kharej IP: " KHAREJ_IP

        # Port validation loop
        while true; do
            read -p "Tunnel port (1 ~ 64435): " DSTPORT
            if [[ $DSTPORT =~ ^[0-9]+$ ]] && (( DSTPORT >= 1 && DSTPORT <= 64435 )); then
                break
            else
                echo "Invalid port. Try again."
            fi
        done

        VXLAN_IP="30.0.0.2/24"
        REMOTE_IP=$IRAN_IP
    else
        echo "[x] Invalid role selected."
        exit 1
    fi

    # Detect default interface
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    echo "Detected main interface: $INTERFACE"

    # Setup VXLAN
    echo "[+] Creating VXLAN interface..."
    ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning

    echo "[+] Assigning IP $VXLAN_IP to $VXLAN_IF"
    ip addr add $VXLAN_IP dev $VXLAN_IF
    ip link set $VXLAN_IF up

    echo "[+] Adding iptables rules"
    iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
    iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
    iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

    # Create systemd service
    echo "[+] Creating systemd service for VXLAN..."

    cat < /usr/local/bin/vxlan_bridge.sh
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
# Persistent keepalive: ping remote every 30s in background
( while true; do ping -c 1 $REMOTE_IP >/dev/null 2>&1; sleep 30; done ) &
EOF

    chmod +x /usr/local/bin/vxlan_bridge.sh

    cat < /etc/systemd/system/vxlan-tunnel.service
[Unit]
Description=VXLAN Tunnel Interface
After=network.target

[Service]
ExecStart=/usr/local/bin/vxlan_bridge.sh
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 /etc/systemd/system/vxlan-tunnel.service
    systemctl daemon-reexec
    systemctl daemon-reload
    systemctl enable vxlan-tunnel.service
    systemctl start vxlan-tunnel.service

    echo -e "\n${GREEN}[✓] VXLAN tunnel service enabled to run on boot.${NC}"
    echo "[✓] VXLAN tunnel setup completed successfully."
    echo -e "Your VXLAN IP: $VXLAN_IP"
}

install_haproxy_and_configure() {
    echo "[*] Configuring HAProxy..."

    # Ensure haproxy is installed
    if ! command -v haproxy >/dev/null 2>&1; then
        echo "[x] HAProxy is not installed. Installing..."
        sudo apt update && sudo apt install -y haproxy
    fi

    # Ensure config directory exists
    sudo mkdir -p /etc/haproxy

    local CONFIG_FILE="/etc/haproxy/haproxy.cfg"
    local BACKUP_FILE="/etc/haproxy/haproxy.cfg.bak"

    # Backup old config
    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$BACKUP_FILE"

    # Write base config
    cat < "$CONFIG_FILE"
global
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 4096

defaults
    mode    tcp
    option  dontlognull
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms
    retries 3
    option  tcpka
EOL

    read -p "Enter ports (comma-separated): " user_ports
    local local_ip=$(hostname -I | awk '{print $1}')

    IFS=',' read -ra ports <<< "$user_ports"

    for port in "${ports[@]}"; do
        cat <> "$CONFIG_FILE"

frontend frontend_$port
    bind *:$port
    default_backend backend_$port
    option tcpka

backend backend_$port
    option tcpka
    server server1 $local_ip:$port check maxconn 2048
EOL
    done

    # Validate haproxy config
    if haproxy -c -f "$CONFIG_FILE"; then
        echo "[*] Restarting HAProxy service..."
        systemctl restart haproxy
        systemctl enable haproxy
        echo -e "${GREEN}HAProxy configured and restarted successfully.${NC}"
    else
        echo -e "${YELLOW}Warning: HAProxy configuration is invalid!${NC}"
    fi
}

uninstall_all_vxlan() {
    echo "[!] Deleting all VXLAN interfaces and cleaning up..."
    for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
        ip link del $i 2>/dev/null
    done
    rm -f /usr/local/bin/vxlan_bridge.sh /etc/ping_vxlan.sh
    systemctl disable --now vxlan-tunnel.service 2>/dev/null
    rm -f /etc/systemd/system/vxlan-tunnel.service
    systemctl daemon-reload
    
    # Stop and disable HAProxy service
    systemctl stop haproxy 2>/dev/null
    systemctl disable haproxy 2>/dev/null
    
    # Remove related cronjobs
    crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' | grep -v '/etc/ping_vxlan.sh' > /tmp/cron_tmp || true
    crontab /tmp/cron_tmp
    rm /tmp/cron_tmp
    echo "[+] All VXLAN tunnels and related cronjobs deleted."
}

# ---------------- SIT TUNNEL FUNCTIONS ----------------
install_sit_tunnel() {
    clear
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW} Star SIT Tunnel Configuration ${NC}"
    echo "+-----------------------------------------------------------------------------+"
    
    echo "Choose tunnel type:"
    echo "1- IPv6 SIT Tunnel"
    echo "2- IPv4 SIT Tunnel"
    read -p "Enter choice (1/2): " tunnel_type
    
    echo "Choose server role:"
    echo "1- Iran"
    echo "2- Kharej"
    read -p "Enter choice (1/2): " role_choice
    
    if [[ "$tunnel_type" == "1" ]]; then
        # IPv6 SIT Tunnel
        if [[ "$role_choice" == "1" ]]; then
            install_iran_ipv6_sit
        else
            install_kharej_ipv6_sit
        fi
    else
        # IPv4 SIT Tunnel  
        if [[ "$role_choice" == "1" ]]; then
            install_iran_ipv4_sit
        else
            install_kharej_ipv4_sit
        fi
    fi
}

install_iran_ipv6_sit() {
    read -p "How many servers: " server_count
    last_number=$(find_last_tunnel_number)
    next_number=$((last_number + 1))

    echo -e "\n${GREEN}Choose IP configuration:${NC}"
    echo "1- Enter IP manually (recommended)"
    echo "2- Set IP automatically"
    read -p "Enter your choice: " ip_choice

    for ((i=next_number;i /etc/netplan/star-$1.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $ipv6_local::1/64
EOL
    chmod 600 /etc/netplan/star-$1.yaml
    
    netplan_setup
    sudo netplan apply 2>/dev/null
    start_obfs4

    cat < /root/star_connectors-$1.sh
ping $ipv6_local::2
EOL

    chmod +x /root/star_connectors-$1.sh
    screen -dmS star_connectors_session_$1 bash -c "/root/star_connectors-$1.sh"

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6 :                      #"
    echo -e "#  $ipv6_local::1                  #"
    echo -e "####################################"
}

iran_setup_auto_ipv6() {
    echo -e "${YELLOW}Setting up IRAN server $1 (IPv6 Auto)${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    
    cat < /etc/netplan/star-$1.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $2/64
EOL
    chmod 600 /etc/netplan/star-$1.yaml
    
    netplan_setup
    sudo netplan apply 2>/dev/null
    start_obfs4

    cat < /root/star_connectors-$1.sh
ping ${2%::1}::2
EOL

    chmod +x /root/star_connectors-$1.sh
    screen -dmS star_connectors_session_$1 bash -c "/root/star_connectors-$1.sh"

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6 :                      #"
    echo -e "#  $2                             #"
    echo -e "####################################"
}

kharej_setup_ipv6() {
    echo -e "${YELLOW}Setting up Kharej server $1 (IPv6)${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv6 Local : " ipv6_local
    
    cat < /etc/netplan/star-$1.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $kharej_ip
      remote: $iran_ip
      addresses:
        - $ipv6_local::2/64
EOL
    chmod 600 /etc/netplan/star-$1.yaml
    
    netplan_setup
    sudo netplan apply 2>/dev/null
    start_obfs4

    cat < /root/star_connectors-$1.sh
ping $ipv6_local::1
EOL

    chmod +x /root/star_connectors-$1.sh
    screen -dmS star_connectors_session_$1 bash -c "/root/star_connectors-$1.sh"

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6 :                      #"
    echo -e "#  $ipv6_local::2                  #"
    echo -e "####################################"
}

kharej_setup_auto_ipv6() {
    echo -e "${YELLOW}Setting up Kharej server $1 (IPv6 Auto)${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    
    cat < /etc/netplan/star-$1.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $kharej_ip
      remote: $iran_ip
      addresses:
        - $2/64
EOL
    chmod 600 /etc/netplan/star-$1.yaml
    
    netplan_setup
    sudo netplan apply 2>/dev/null
    start_obfs4

    cat < /root/star_connectors-$1.sh
ping ${2%::2}::1
EOL

    chmod +x /root/star_connectors-$1.sh
    screen -dmS star_connectors_session_$1 bash -c "/root/star_connectors-$1.sh"

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6 :                      #"
    echo -e "#  $2                             #"
    echo -e "####################################"
}

iran_setup_ipv4() {
    echo -e "${YELLOW}Setting up IRAN server $1 (IPv4)${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv4 Local : " ipv4_local
    
    cat < /etc/netplan/star-$1.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $ipv4_local/24
EOL
    chmod 600 /etc/netplan/star-$1.yaml
    
    netplan_setup
    sudo netplan apply 2>/dev/null
    start_obfs4

    cat < /root/star_connectors-$1.sh
ping ${ipv4_local%.*}.2
EOL

    chmod +x /root/star_connectors-$1.sh
    screen -dmS star_connectors_session_$1 bash -c "/root/star_connectors-$1.sh"

    # Unblock IPv4 local if blocked
    iptables -C INPUT -s $ipv4_local -j DROP 2>/dev/null && iptables -D INPUT -s $ipv4_local -j DROP

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4 :                      #"
    echo -e "#  $ipv4_local                     #"
    echo -e "####################################"
}

iran_setup_auto_ipv4() {
    echo -e "${YELLOW}Setting up IRAN server $1 (IPv4 Auto)${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    
    cat < /etc/netplan/star-$1.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $2/24
EOL
    chmod 600 /etc/netplan/star-$1.yaml
    
    netplan_setup
    sudo netplan apply 2>/dev/null
    start_obfs4

    cat < /root/star_connectors-$1.sh
ping ${2%.*}.2
EOL

    chmod +x /root/star_connectors-$1.sh
    screen -dmS star_connectors_session_$1 bash -c "/root/star_connectors-$1.sh"

    # Unblock IPv4 local if blocked
    iptables -C INPUT -s $2 -j DROP 2>/dev/null && iptables -D INPUT -s $2 -j DROP

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4 :                      #"
    echo -e "#  $2                             #"
    echo -e "####################################"
}

kharej_setup_ipv4() {
    echo -e "${YELLOW}Setting up Kharej server $1 (IPv4)${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv4 Local : " ipv4_local
    
    cat < /etc/netplan/star-$1.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $kharej_ip
      remote: $iran_ip
      addresses:
        - $ipv4_local/24
EOL
    chmod 600 /etc/netplan/star-$1.yaml
    
    netplan_setup
    sudo netplan apply 2>/dev/null
    start_obfs4

    cat < /root/star_connectors-$1.sh
ping ${ipv4_local%.*}.1
EOL

    chmod +x /root/star_connectors-$1.sh
    screen -dmS star_connectors_session_$1 bash -c "/root/star_connectors-$1.sh"

    # Unblock IPv4 local if blocked
    iptables -C INPUT -s $ipv4_local -j DROP 2>/dev/null && iptables -D INPUT -s $ipv4_local -j DROP

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4 :                      #"
    echo -e "#  $ipv4_local                     #"
    echo -e "####################################"
}

kharej_setup_auto_ipv4() {
    echo -e "${YELLOW}Setting up Kharej server $1 (IPv4 Auto)${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    
    cat < /etc/netplan/star-$1.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $kharej_ip
      remote: $iran_ip
      addresses:
        - $2/24
EOL
    chmod 600 /etc/netplan/star-$1.yaml
    
    netplan_setup
    sudo netplan apply 2>/dev/null
    start_obfs4

    cat < /root/star_connectors-$1.sh
ping ${2%.*}.1
EOL

    chmod +x /root/star_connectors-$1.sh
    screen -dmS star_connectors_session_$1 bash -c "/root/star_connectors-$1.sh"

    # Unblock IPv4 local if blocked
    iptables -C INPUT -s $2 -j DROP 2>/dev/null && iptables -D INPUT -s $2 -j DROP

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4 :                      #"
    echo -e "#  $2                             #"
    echo -e "####################################"
}

uninstall_sit_tunnels() {
    echo $'\e[32mUninstalling Star SIT Tunnels in 3 seconds... \e[0m' && sleep 1 && echo $'\e[32m2... \e[0m' && sleep 1 && echo $'\e[32m1... \e[0m' && sleep 1 && {
        # Stop all screen sessions
        pkill screen
        
        # Find all tunnel0858 interfaces and delete them
        for iface in $(ip link show | grep 'tunnel0858' | awk -F': ' '{print $2}' | cut -d'@' -f1); do
            echo -e "${YELLOW}Removing interface $iface...${NC}"
            ip link set $iface down
            ip link delete $iface
        done
        
        # Remove netplan configuration files
        rm -f /etc/netplan/star*.yaml
        netplan apply
        
        # Remove connector scripts
        rm -f /root/star_connectors-*.sh
        
        # Stop and disable ping monitor service
        systemctl stop ping-monitor.service 2>/dev/null
        systemctl disable ping-monitor.service 2>/dev/null
        rm -f /etc/systemd/system/ping-monitor.service
        rm -f /root/ping_monitor.sh
        
        # Kill any remaining obfs4proxy processes
        pkill obfs4proxy
        
        # Remove obfs4 configuration
        rm -rf /etc/obfs4
        
        # Restart networking to apply changes
        systemctl restart systemd-networkd
        
        clear
        echo -e "${GREEN}Star SIT Tunnels Uninstalled successfully!${NC}"
    }
}

# ---------------- HAPROXY MANAGEMENT FUNCTIONS ----------------
haproxy_management() {
    while true; do
        clear
        echo "+-----------------------------------------------------------------------------+"
        echo -e "|${YELLOW} Star HAProxy Management ${NC}"
        echo "+-----------------------------------------------------------------------------+"
        echo "|Select an option:"
        echo "|1) Install HAProxy"
        echo "|2) Add IPs and Ports to Forward"
        echo "|3) Clear Configurations"
        echo "|4) Remove HAProxy Completely"
        echo "|0) Back to Main Menu"
        echo "+-----------------------------------------------------------------------------+"

        read -p "Select a Number : " choice

        case $choice in
            1)
                install_haproxy_standalone
                ;;
            2)
                add_ip_ports_haproxy
                ;;
            3)
                clear_haproxy_configs
                ;;
            4)
                remove_haproxy_completely
                ;;
            0)
                break
                ;;
            *)
                echo "Invalid option. Please try again."
                sleep 1
                ;;
        esac
    done
}

install_haproxy_standalone() {
    echo "Installing HAProxy..."
    sudo apt-get update
    sudo apt-get install -y haproxy
    echo "HAProxy installed."
    default_haproxy_config
    read -p "Press Enter to continue..."
}

default_haproxy_config() {
    local config_file="/etc/haproxy/haproxy.cfg"
    cat < $config_file
global
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode    tcp
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
EOL
}

generate_haproxy_config() {
    local ports=($1)
    local target_ips=($2)
    local config_file="/etc/haproxy/haproxy.cfg"

    echo "Generating HAProxy configuration..."

    for port in "${ports[@]}"; do
        cat <> $config_file

frontend frontend_$port
    bind *:$port
    default_backend backend_$port

backend backend_$port
EOL
        for i in "${!target_ips[@]}"; do
            if [ $i -eq 0 ]; then
                cat <> $config_file
    server server$(($i+1)) ${target_ips[$i]}:$port check
EOL
            else
                cat <> $config_file
    server server$(($i+1)) ${target_ips[$i]}:$port check backup
EOL
            fi
        done
    done

    echo "HAProxy configuration generated at $config_file"
}

add_ip_ports_haproxy() {
    read -p "Enter the IPs to forward to (use comma , to separate multiple IPs): " user_ips
    IFS=',' read -r -a ips_array <<< "$user_ips"
    read -p "Enter the ports (use comma , to separate): " user_ports
    IFS=',' read -r -a ports_array <<< "$user_ports"
    generate_haproxy_config "${ports_array[*]}" "${ips_array[*]}"

    if haproxy -c -f /etc/haproxy/haproxy.cfg; then
        echo "Restarting HAProxy service..."
        service haproxy restart
        echo "HAProxy configuration updated and service restarted."
    else
        echo "HAProxy configuration is invalid. Please check the configuration file."
    fi
    read -p "Press Enter to continue..."
}

clear_haproxy_configs() {
    local config_file="/etc/haproxy/haproxy.cfg"
    local backup_file="/etc/haproxy/haproxy.cfg.bak"
    
    echo "Creating a backup of the HAProxy configuration..."
    cp $config_file $backup_file

    if [ $? -ne 0 ]; then
        echo "Failed to create a backup. Aborting."
        return
    fi

    echo "Clearing IP and port configurations from HAProxy configuration..."

    awk '
    /^frontend frontend_/ {skip = 1}
    /^backend backend_/ {skip = 1}
    skip {if (/^$/) {skip = 0}; next}
    {print}
    ' $backup_file > $config_file

    echo "Clearing IP and port configurations from $config_file."
    
    echo "Stopping HAProxy service..."
    sudo service haproxy stop
    
    if [ $? -eq 0 ]; then
        echo "HAProxy service stopped."
    else
        echo "Failed to stop HAProxy service."
    fi

    echo "Done!"
    read -p "Press Enter to continue..."
}

remove_haproxy_completely() {
    echo "Removing HAProxy..."
    sudo apt-get remove --purge -y haproxy
    sudo apt-get autoremove -y
    echo "HAProxy removed."
    read -p "Press Enter to continue..."
}

# ---------------- BBR INSTALLATION ----------------
install_bbr() {
    echo "Running BBR script..."
    curl -fsSL https://raw.githubusercontent.com/MrAminiDev/NetOptix/main/scripts/bbr.sh -o /tmp/bbr.sh
    bash /tmp/bbr.sh
    rm /tmp/bbr.sh
    read -p "Press Enter to return to menu..."
}

# ---------------- CRONJOB MANAGEMENT ----------------
cronjob_management() {
    while true; do
        clear
        echo "+-----------------------------------------------------------------------------+"
        echo -e "|${YELLOW} Star Cronjob Settings ${NC}"
        echo "+-----------------------------------------------------------------------------+"
        echo "1- Install cronjob"
        echo "2- Edit cronjob"
        echo "3- Delete cronjob"
        echo "0- Back to main menu"
        echo "+-----------------------------------------------------------------------------+"
        
        read -p "Enter your choice [0-3]: " cron_action
        case $cron_action in
            1)
                install_cronjob
                ;;
            2)
                edit_cronjob
                ;;
            3)
                delete_cronjob
                ;;
            0)
                break
                ;;
            *)
                echo "[x] Invalid option. Try again."
                sleep 1
                ;;
        esac
    done
}

install_cronjob() {
    while true; do
        read -p "How many hours between each restart? (1-24, b=Back): " cron_hours
        if [[ "$cron_hours" == "b" || "$cron_hours" == "B" ]]; then
            break
        elif [[ $cron_hours =~ ^[0-9]+$ ]] && (( cron_hours >= 1 && cron_hours <= 24 )); then
            # Remove any previous cronjobs for these services
            crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
            echo "0 */$cron_hours * * * systemctl restart haproxy >/dev/null 2>&1" >> /tmp/cron_tmp
            echo "0 */$cron_hours * * * systemctl restart vxlan-tunnel >/dev/null 2>&1" >> /tmp/cron_tmp
            crontab /tmp/cron_tmp
            rm /tmp/cron_tmp
            echo -e "${GREEN}Cronjob set successfully to restart haproxy and vxlan-tunnel every $cron_hours hour(s).${NC}"
            read -p "Press Enter to return to Cronjob settings..."
            break
        else
            echo "Invalid input. Please enter a number between 1 and 24 or 'b' to go back."
        fi
    done
}

edit_cronjob() {
    if crontab -l 2>/dev/null | grep -q 'systemctl restart haproxy'; then
        while true; do
            read -p "Enter new hours for cronjob (1-24, b=Back): " new_cron_hours
            if [[ "$new_cron_hours" == "b" || "$new_cron_hours" == "B" ]]; then
                break
            elif [[ $new_cron_hours =~ ^[0-9]+$ ]] && (( new_cron_hours >= 1 && new_cron_hours <= 24 )); then
                crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
                echo "0 */$new_cron_hours * * * systemctl restart haproxy >/dev/null 2>&1" >> /tmp/cron_tmp
                echo "0 */$new_cron_hours * * * systemctl restart vxlan-tunnel >/dev/null 2>&1" >> /tmp/cron_tmp
                crontab /tmp/cron_tmp
                rm /tmp/cron_tmp
                echo -e "${GREEN}Cronjob updated successfully to every $new_cron_hours hour(s).${NC}"
                read -p "Press Enter to return to Cronjob settings..."
                break
            else
                echo "Invalid input. Please enter a number between 1 and 24 or 'b' to go back."
            fi
        done
    else
        echo -e "${YELLOW}No cronjob found to edit. Please install first.${NC}"
        read -p "Press Enter to return to Cronjob settings..."
    fi
}

delete_cronjob() {
    if crontab -l 2>/dev/null | grep -q 'systemctl restart haproxy'; then
        crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
        crontab /tmp/cron_tmp
        rm /tmp/cron_tmp
        echo -e "${GREEN}Cronjob deleted successfully.${NC}"
    else
        echo -e "${YELLOW}No cronjob found to delete.${NC}"
    fi
    read -p "Press Enter to return to Cronjob settings..."
}

# ---------------- UNINSTALL ALL FUNCTIONS ----------------
uninstall_all_tunnels() {
    clear
    echo -e "${RED}WARNING: This will remove ALL Star tunnels and configurations!${NC}"
    read -p "Are you sure you want to continue? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Uninstalling all Star tunnels...${NC}"
        
        # Stop all screen sessions
        pkill screen
        
        # Remove VXLAN tunnels
        for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
            ip link del $i 2>/dev/null
        done
        
        # Remove SIT tunnels
        for iface in $(ip link show | grep 'tunnel0858' | awk -F': ' '{print $2}' | cut -d'@' -f1); do
            echo -e "${YELLOW}Removing interface $iface...${NC}"
            ip link set $iface down
            ip link delete $iface
        done
        
        # Remove configuration files
        rm -f /etc/netplan/star*.yaml
        rm -f /usr/local/bin/vxlan_bridge.sh
        rm -f /root/star_connectors-*.sh
        
        # Remove systemd services
        systemctl disable --now vxlan-tunnel.service 2>/dev/null
        rm -f /etc/systemd/system/vxlan-tunnel.service
        systemctl daemon-reload
        
        # Stop HAProxy
        systemctl stop haproxy 2>/dev/null
        systemctl disable haproxy 2>/dev/null
        
        # Remove cronjobs
        crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
        crontab /tmp/cron_tmp 2>/dev/null
        rm -f /tmp/cron_tmp
        
        # Remove obfs4 configuration
        pkill obfs4proxy 2>/dev/null
        rm -rf /etc/obfs4
        
        # Apply network changes
        netplan apply 2>/dev/null
        systemctl restart systemd-networkd
        
        echo -e "${GREEN}All Star tunnels have been uninstalled successfully!${NC}"
    else
        echo -e "${YELLOW}Uninstallation cancelled.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# ---------------- INITIALIZATION ----------------
init() {
    install_jq
    install_obfs4
    configure_obfs4
    echo -e "${GREEN}Star Tunnel initialization complete.${NC}"
}

# ---------------- MAIN PROGRAM LOOP ----------------
main_loop() {
    while true; do
        StarTunnel_menu
        read -p "Enter your choice [0-6]: " main_action
        case $main_action in
            0)
                echo -e "${GREEN}Exiting StarTunnel...${NC}"
                exit 0
                ;;
            1)
                install_vxlan_tunnel
                read -p "Press Enter to return to menu..."
                ;;
            2)
                install_sit_tunnel
                read -p "Press Enter to return to menu..."
                ;;
            3)
                haproxy_management
                ;;
            4)
                install_bbr
                ;;
            5)
                cronjob_management
                ;;
            6)
                uninstall_all_tunnels
                ;;
            *)
                echo "[x] Invalid option. Try again."
                sleep 1
                ;;
        esac
    done
}

# ---------------- START PROGRAM ----------------
clear
echo -e "${TURQUOISE}"
echo "  ╔═══╦════╦═══╦═══╗        ╔════╦╗─╔╦═╗─╔╦═══╦╗──╔╗"
echo "  ║╔═╗║╔╗╔╗║╔═╗║╔═╗║        ║╔╗╔╗║║─║║║╚╗║║╔══╣║──║║"
echo "  ║╚══╬╝║║╚╣║─║║╚═╝║        ╚╝║║╚╣║─║║╔╗╚╝║╚══╣║──║║"
echo "  ╚══╗║─║║─║╚═╝║╔╗╔╝        ──║║─║║─║║║╚╗║║╔══╣║─╔╣║─╔╗"
echo "  ║╚═╝║─║║─║╔═╗║║║╚╗        ──║║─║╚═╝║║─║║║╚══╣╚═╝║╚═╝║"
echo "  ╚═══╝─╚╝─╚╝─╚╩╝╚═╝        ──╚╝─╚═══╩╝─╚═╩═══╩═══╩═══╝"
echo -e "${NC}"
echo -e "${GREEN}Starting StarTunnel by MoriiStar...${NC}"
echo -e "${YELLOW}GitHub: https://github.com/Moriistar${NC}"
echo -e "${MAGENTA}Telegram: @ServerStar_ir${NC}"
sleep 2

# Initialize and start main loop
init
main_loop
