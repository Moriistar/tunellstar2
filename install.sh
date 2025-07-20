#!/bin/bash

# ================================================================================
# StarTunnel Combined Script - اسکریپت ترکیبی تونل‌ها
# Created by: MortezaStar (@ServerStar_ir)
# Version: 1.0.2 Beta
# Combined: StarTunnel, Lena VXLAN, Nebula SIT, HAProxy
# ================================================================================

# ---------------- INSTALL DEPENDENCIES ----------------
echo "[*] Updating package list..."
sudo apt update -y

echo "[*] Installing required packages..."
sudo apt install -y iproute2 net-tools grep awk sudo iputils-ping jq curl haproxy iptables screen obfs4proxy netplan.io

# ---------------- COLORS ----------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
TURQUOISE='\033[38;5;45m'
NC='\033[0m'

# ---------------- GLOBAL VARIABLES ----------------
SERVER_IP=$(hostname -I | awk '{print $1}')
SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country')
SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp')

# ---------------- MAIN MENU FUNCTION ----------------
StarTunnel_main_menu() {
    clear
    echo "+-----------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}    ╔═══╦════╦═══╦═══╗        ╔════╦╗─╔╦═╗─╔╦═══╦╗──╔╗${NC}"
    echo -e "${TURQUOISE}    ║╔═╗║╔╗╔╗║╔═╗║╔═╗║        ║╔╗╔╗║║─║║║╚╗║║╔══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ║╚══╬╝║║╚╣║─║║╚═╝║        ╚╝║║╚╣║─║║╔╗╚╝║╚══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ╚══╗║─║║─║╚═╝║╔╗╔╝        ──║║─║║─║║║╚╗║║╔══╣║─╔╣║─╔╗${NC}"
    echo -e "${TURQUOISE}    ║╚═╝║─║║─║╔═╗║║║╚╗        ──║║─║╚═╝║║─║║║╚══╣╚═╝║╚═╝║${NC}"
    echo -e "${TURQUOISE}    ╚═══╝─╚╝─╚╝─╚╩╝╚═╝        ──╚╝─╚═══╩╝─╚═╩═══╩═══╩═══╝${NC}" 
    echo "+-----------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${RED}@ServerStar_ir ${NC}| Version : ${GREEN} 1.0.2 Beta ${NC} "
    echo "+-----------------------------------------------------------------------------+"      
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose a tunnel type:${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "1- StarTunnel Original"
    echo -e "2- Lena VXLAN Tunnel"
    echo -e "3- Nebula SIT Tunnel"
    echo -e "4- HAProxy Configuration"
    echo -e "5- Install BBR"
    echo -e "6- System Management"
    echo -e "0- Exit"
    echo "+-----------------------------------------------------------------------------+"
}

# ---------------- CHECK FUNCTIONS ----------------
check_core_status() {
    ip link show | grep -q 'vxlan\|tunnel0858' && echo "Active" || echo "Inactive"
}

install_jq() {
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}jq is not installed. Installing...${NC}"
        sudo apt-get update && sudo apt-get install -y jq
    fi
}

install_obfs4() {
    if ! command -v obfs4proxy &> /dev/null; then
        echo -e "${YELLOW}Installing obfs4proxy...${NC}"
        sudo apt-get update && sudo apt-get install -y obfs4proxy
    fi
}

# ---------------- STARTUNNEL FUNCTIONS ----------------
StarTunnel_menu() {
    clear
    echo "+-----------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}    STAR TUNNEL - Original Menu${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${RED}@ServerStar_ir ${NC}| Version : ${GREEN} 1.0.2 Beta ${NC} "
    echo "+-----------------------------------------------------------------------------+"      
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW}StarTunnel Options:${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "1- Install new tunnel"
    echo -e "2- Uninstall tunnel(s)"
    echo -e "3- Install BBR"
    echo -e "4- Cronjob settings"
    echo -e "9- Back to main menu"
    echo -e "0- Exit"
    echo "+-----------------------------------------------------------------------------+"
}

# ---------------- LENA VXLAN FUNCTIONS ----------------
Lena_menu() {
    clear
    echo "+-------------------------------------------------------------------------+"
    echo -e "${MAGENTA}    LENA VXLAN TUNNEL${NC}"
    echo "+-------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${MAGENTA}@AminiDev ${NC}| Version : ${GREEN} 1.0.0 ${NC} "
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Lena VXLAN Options:${NC}"
    echo "+-------------------------------------------------------------------------+"
    echo -e "1- Install new VXLAN tunnel"
    echo -e "2- Uninstall VXLAN tunnel(s)"
    echo -e "3- Install BBR"
    echo -e "4- Cronjob settings"
    echo -e "9- Back to main menu"
    echo -e "0- Exit"
    echo "+-------------------------------------------------------------------------+"
}

install_vxlan_tunnel() {
    echo "Choose server role:"
    echo "1- Iran"
    echo "2- Kharej"
    read -p "Enter choice (1/2): " role_choice

    if [[ "$role_choice" == "1" ]]; then
        read -p "Enter IRAN IP: " IRAN_IP
        read -p "Enter Kharej IP: " KHAREJ_IP
        
        while true; do
            read -p "Tunnel port (1 ~ 64435): " DSTPORT
            if [[ $DSTPORT =~ ^[0-9]+$ ]] && (( DSTPORT >= 1 && DSTPORT <= 64435 )); then
                break
            else
                echo "Invalid port. Try again."
            fi
        done

        VXLAN_IP="30.0.0.1/24"
        REMOTE_IP=$KHAREJ_IP
        
        while true; do
            read -p "Should port forwarding be done automatically with HAProxy? [1-yes, 2-no]: " haproxy_choice
            if [[ "$haproxy_choice" == "1" || "$haproxy_choice" == "2" ]]; then
                break
            else
                echo "Please enter 1 (yes) or 2 (no)."
            fi
        done

        if [[ "$haproxy_choice" == "1" ]]; then
            install_haproxy_and_configure
        fi

    elif [[ "$role_choice" == "2" ]]; then
        read -p "Enter IRAN IP: " IRAN_IP
        read -p "Enter Kharej IP: " KHAREJ_IP
        
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
    fi

    # Setup VXLAN
    VNI=88
    VXLAN_IF="vxlan${VNI}"
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)

    echo "[+] Creating VXLAN interface..."
    ip link add $VXLAN_IF type vxlan id $VNI local $SERVER_IP remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
    ip addr add $VXLAN_IP dev $VXLAN_IF
    ip link set $VXLAN_IF up

    echo "[+] Adding iptables rules"
    iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
    iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
    iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

    # Create systemd service
    create_vxlan_service
    
    echo -e "${GREEN}[✓] VXLAN tunnel setup completed successfully.${NC}"
}

create_vxlan_service() {
    cat < /usr/local/bin/vxlan_bridge.sh
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $SERVER_IP remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
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

    systemctl daemon-reload
    systemctl enable vxlan-tunnel.service
    systemctl start vxlan-tunnel.service
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
    systemctl stop haproxy 2>/dev/null
    systemctl disable haproxy 2>/dev/null
    echo "[+] All VXLAN tunnels deleted."
}

# ---------------- NEBULA SIT FUNCTIONS ----------------
nebula_menu() {
    clear
    echo "+--------------------------------------------------------------------------------+"
    echo -e "${GREEN}    NEBULA SIT TUNNEL${NC}"
    echo "+--------------------------------------------------------------------------------+"
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo -e "|${GREEN}Server Tunnel     |${NC} $(check_core_status)"
    echo "+--------------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Nebula SIT Options:${NC}"
    echo "+--------------------------------------------------------------------------------+"
    echo -e "1- Install IRAN tunnel"
    echo -e "2- Install Kharej tunnel"
    echo -e "3- Install IRAN (IPv4 Local)"
    echo -e "4- Install Kharej (IPv4 Local)"
    echo -e "5- Uninstall tunnels"
    echo -e "6- Manage tunnels"
    echo -e "9- Back to main menu"
    echo -e "0- Exit"
    echo "+--------------------------------------------------------------------------------+"
}

install_nebula_tunnel() {
    local tunnel_type=$1
    local server_count
    local last_number
    local next_number
    
    install_jq
    install_obfs4
    
    case $tunnel_type in
        1|3) # Iran
            read -p "How many servers: " server_count
            last_number=$(find_last_tunnel_number)
            next_number=$((last_number + 1))

            echo -e "\n${GREEN}Choose IP configuration:${NC}"
            echo "1- Enter IP manually (recommended)"
            echo "2- Set IP automatically"
            read -p "Enter your choice: " ip_choice

            for ((i=next_number;i /etc/netplan/mramini-$1.yaml
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
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply 2>/dev/null

    cat < /root/connectors-$1.sh
ping $ipv6_local::2
EOL
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6: $ipv6_local::1         #"
    echo -e "####################################"
}

iran_setup_ipv4() {
    echo -e "${YELLOW}Setting up IRAN server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv4 Local : " ipv4_local
    
    cat < /etc/netplan/mramini-$1.yaml
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
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply 2>/dev/null

    cat < /root/connectors-$1.sh
ping ${ipv4_local%.*}.2
EOL
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4: $ipv4_local            #"
    echo -e "####################################"
}

kharej_setup() {
    echo -e "${YELLOW}Setting up Kharej server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv6 Local : " ipv6_local
    
    cat < /etc/netplan/mramini-$1.yaml
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
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply 2>/dev/null

    cat < /root/connectors-$1.sh
ping $ipv6_local::1
EOL
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6: $ipv6_local::2         #"
    echo -e "####################################"
}

kharej_setup_ipv4() {
    echo -e "${YELLOW}Setting up Kharej server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv4 Local : " ipv4_local
    
    cat < /etc/netplan/mramini-$1.yaml
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
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply 2>/dev/null

    cat < /root/connectors-$1.sh
ping ${ipv4_local%.*}.1
EOL
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4: $ipv4_local            #"
    echo -e "####################################"
}

uninstall_nebula() {
    echo $'\e[32mUninstalling Nebula in 3 seconds... \e[0m' && sleep 1 && echo $'\e[32m2... \e[0m' && sleep 1 && echo $'\e[32m1... \e[0m' && sleep 1
    
    # Stop all screen sessions
    pkill screen
    
    # Find all tunnel0858 interfaces and delete them
    for iface in $(ip link show | grep 'tunnel0858' | awk -F': ' '{print $2}' | cut -d'@' -f1); do
        echo -e "${YELLOW}Removing interface $iface...${NC}"
        ip link set $iface down
        ip link delete $iface
    done
    
    # Remove netplan configuration files
    rm -f /etc/netplan/mramini*.yaml
    netplan apply
    
    # Remove connector scripts
    rm -f /root/connectors-*.sh
    
    echo -e "${GREEN}Nebula Uninstalled successfully!${NC}"
}

# ---------------- HAPROXY FUNCTIONS ----------------
haproxy_menu() {
    clear
    echo "+----------------------------------------------------------------------------+"
    echo -e "${RED}    HAPROXY CONFIGURATION${NC}"
    echo "+----------------------------------------------------------------------------+"
    echo "|Select an option:"
    echo "|1) Install HAProxy"
    echo "|2) Add IPs and Ports to Forward"
    echo "|3) Clear Configurations"
    echo "|4) Remove HAProxy Completely"
    echo "|9) Back to main menu"
    echo "|0) Exit"
    echo "+----------------------------------------------------------------------------+"
}

install_haproxy() {
    echo "Installing HAProxy..."
    sudo apt-get update
    sudo apt-get install -y haproxy
    echo "HAProxy installed."
    default_haproxy_config
}

default_haproxy_config() {
    cat < /etc/haproxy/haproxy.cfg
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

install_haproxy_and_configure() {
    echo "[*] Configuring HAProxy..."

    if ! command -v haproxy >/dev/null 2>&1; then
        echo "[x] HAProxy is not installed. Installing..."
        sudo apt update && sudo apt install -y haproxy
    fi

    sudo mkdir -p /etc/haproxy
    local CONFIG_FILE="/etc/haproxy/haproxy.cfg"
    local BACKUP_FILE="/etc/haproxy/haproxy.cfg.bak"

    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$BACKUP_FILE"

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

    if haproxy -c -f "$CONFIG_FILE"; then
        echo "[*] Restarting HAProxy service..."
        systemctl restart haproxy
        systemctl enable haproxy
        echo -e "${GREEN}HAProxy configured and restarted successfully.${NC}"
    else
        echo -e "${YELLOW}Warning: HAProxy configuration is invalid!${NC}"
    fi
}

add_haproxy_ip_ports() {
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

clear_haproxy_configs() {
    local config_file="/etc/haproxy/haproxy.cfg"
    local backup_file="/etc/haproxy/haproxy.cfg.bak"
    
    echo "Creating a backup of the HAProxy configuration..."
    cp $config_file $backup_file

    echo "Clearing IP and port configurations from HAProxy configuration..."

    awk '
    /^frontend frontend_/ {skip = 1}
    /^backend backend_/ {skip = 1}
    skip {if (/^$/) {skip = 0}; next}
    {print}
    ' $backup_file > $config_file

    echo "Stopping HAProxy service..."
    sudo service haproxy stop
    echo "Done!"
}

remove_haproxy() {
    echo "Removing HAProxy..."
    sudo apt-get remove --purge -y haproxy
    sudo apt-get autoremove -y
    echo "HAProxy removed."
}

# ---------------- BBR INSTALLATION ----------------
install_bbr() {
    echo "Running BBR script..."
    curl -fsSL https://raw.githubusercontent.com/MrAminiDev/NetOptix/main/scripts/bbr.sh -o /tmp/bbr.sh
    bash /tmp/bbr.sh
    rm /tmp/bbr.sh
}

# ---------------- CRONJOB FUNCTIONS ----------------
cronjob_menu() {
    clear
    echo "+-----------------------------+"
    echo "|      Cronjob settings       |"
    echo "+-----------------------------+"
    echo "1- Install cronjob"
    echo "2- Edit cronjob"
    echo "3- Delete cronjob"
    echo "4- Back to previous menu"
}

install_cronjob() {
    while true; do
        read -p "How many hours between each restart? (1-24, b=Back): " cron_hours
        if [[ "$cron_hours" == "b" || "$cron_hours" == "B" ]]; then
            break
        elif [[ $cron_hours =~ ^[0-9]+$ ]] && (( cron_hours >= 1 && cron_hours <= 24 )); then
            crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
            echo "0 */$cron_hours * * * systemctl restart haproxy >/dev/null 2>&1" >> /tmp/cron_tmp
            echo "0 */$cron_hours * * * systemctl restart vxlan-tunnel >/dev/null 2>&1" >> /tmp/cron_tmp
            crontab /tmp/cron_tmp
            rm /tmp/cron_tmp
            echo -e "${GREEN}Cronjob set successfully to restart services every $cron_hours hour(s).${NC}"
            read -p "Press Enter to continue..."
            break
        else
            echo "Invalid input. Please enter a number between 1 and 24 or 'b' to go back."
        fi
    done
}

# ---------------- SYSTEM MANAGEMENT ----------------
system_management_menu() {
    clear
    echo "+-----------------------------+"
    echo "|    System Management        |"
    echo "+-----------------------------+"
    echo "1- Check system status"
    echo "2- Update system"
    echo "3- Clean system"
    echo "4- Back to main menu"
}

check_system_status() {
    clear
    echo -e "${GREEN}=== SYSTEM STATUS ===${NC}"
    echo -e "Uptime: $(uptime -p)"
    echo -e "Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo -e "Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
    echo -e "Disk: $(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
    echo ""
    echo -e "${GREEN}=== ACTIVE TUNNELS ===${NC}"
    echo "VXLAN interfaces: $(ip link show | grep -c vxlan || echo 0)"
    echo "SIT interfaces: $(ip link show | grep -c tunnel0858 || echo 0)"
    echo "HAProxy status: $(systemctl is-active haproxy 2>/dev/null || echo inactive)"
    read -p "Press Enter to continue..."
}

# ---------------- MAIN SCRIPT LOOP ----------------
main() {
    while true; do
        StarTunnel_main_menu
        read -p "Enter your choice [0-6]: " main_choice
        
        case $main_choice in
            1)
                while true; do
                    StarTunnel_menu
                    read -p "Enter your choice [0-4,9]: " star_choice
                    case $star_choice in
                        1)
                            echo "StarTunnel installation - Feature coming soon..."
                            read -p "Press Enter to continue..."
                            ;;
                        2)
                            echo "StarTunnel uninstallation - Feature coming soon..."
                            read -p "Press Enter to continue..."
                            ;;
                        3)
                            install_bbr
                            read -p "Press Enter to continue..."
                            ;;
                        4)
                            while true; do
                                cronjob_menu
                                read -p "Enter your choice [1-4]: " cron_choice
                                case $cron_choice in
                                    1) install_cronjob ;;
                                    2) echo "Edit cronjob feature coming soon..." && read -p "Press Enter to continue..." ;;
                                    3) echo "Delete cronjob feature coming soon..." && read -p "Press Enter to continue..." ;;
                                    4) break ;;
                                    *) echo "Invalid option" && sleep 1 ;;
                                esac
                            done
                            ;;
                        9) break ;;
                        0) echo "Exiting..." && exit 0 ;;
                        *) echo "Invalid option" && sleep 1 ;;
                    esac
                done
                ;;
            2)
                while true; do
                    Lena_menu
                    read -p "Enter your choice [0-4,9]: " lena_choice
                    case $lena_choice in
                        1)
                            install_vxlan_tunnel
                            read -p "Press Enter to continue..."
                            ;;
                        2)
                            uninstall_all_vxlan
                            read -p "Press Enter to continue..."
                            ;;
                        3)
                            install_bbr
                            read -p "Press Enter to continue..."
                            ;;
                        4)
                            while true; do
                                cronjob_menu
                                read -p "Enter your choice [1-4]: " cron_choice
                                case $cron_choice in
                                    1) install_cronjob ;;
                                    2) echo "Edit cronjob feature coming soon..." && read -p "Press Enter to continue..." ;;
                                    3) echo "Delete cronjob feature coming soon..." && read -p "Press Enter to continue..." ;;
                                    4) break ;;
                                    *) echo "Invalid option" && sleep 1 ;;
                                esac
                            done
                            ;;
                        9) break ;;
                        0) echo "Exiting..." && exit 0 ;;
                        *) echo "Invalid option" && sleep 1 ;;
                    esac
                done
                ;;
            3)
                while true; do
                    nebula_menu
                    read -p "Enter your choice [0-6,9]: " nebula_choice
                    case $nebula_choice in
                        1) install_nebula_tunnel 1 && read -p "Press Enter to continue..." ;;
                        2) install_nebula_tunnel 2 && read -p "Press Enter to continue..." ;;
                        3) install_nebula_tunnel 3 && read -p "Press Enter to continue..." ;;
                        4) install_nebula_tunnel 4 && read -p "Press Enter to continue..." ;;
                        5) uninstall_nebula && read -p "Press Enter to continue..." ;;
                        6) echo "Manage tunnels feature coming soon..." && read -p "Press Enter to continue..." ;;
                        9) break ;;
                        0) echo "Exiting..." && exit 0 ;;
                        *) echo "Invalid option" && sleep 1 ;;
                    esac
                done
                ;;
            4)
                while true; do
                    haproxy_menu
                    read -p "Select a Number: " haproxy_choice
                    case $haproxy_choice in
                        1) install_haproxy && read -p "Press Enter to continue..." ;;
                        2) add_haproxy_ip_ports && read -p "Press Enter to continue..." ;;
                        3) clear_haproxy_configs && read -p "Press Enter to continue..." ;;
                        4) remove_haproxy && read -p "Press Enter to continue..." ;;
                        9) break ;;
                        0) echo "Exiting..." && exit 0 ;;
                        *) echo "Invalid option" && sleep 1 ;;
                    esac
                done
                ;;
            5)
                install_bbr
                read -p "Press Enter to continue..."
                ;;
            6)
                while true; do
                    system_management_menu
                    read -p "Enter your choice [1-4]: " sys_choice
                    case $sys_choice in
                        1) check_system_status ;;
                        2) echo "Updating system..." && sudo apt update && sudo apt upgrade -y && read -p "Press Enter to continue..." ;;
                        3) echo "Cleaning system..." && sudo apt autoremove -y && sudo apt autoclean && read -p "Press Enter to continue..." ;;
                        4) break ;;
                        *) echo "Invalid option" && sleep 1 ;;
                    esac
                done
                ;;
            0)
                echo -e "${GREEN}Exiting StarTunnel Combined Script...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 1
                ;;
        esac
    done
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}" 
   exit 1
fi

# Start main function
main
