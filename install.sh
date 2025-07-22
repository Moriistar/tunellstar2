#!/bin/bash

# StarTunnel Script - MoriiStar
# GitHub: https://github.com/Moriistar/tunellstar
# Telegram: @ServerStar_ir

# ---------------- INSTALL DEPENDENCIES ----------------
install_dependencies() {
    echo "[*] Updating package list..."
    sudo apt update -y

    echo "[*] Installing required packages..."
    sudo apt install -y iproute2 net-tools grep gawk sudo iputils-ping jq curl haproxy iptables screen netplan.io
}

# ---------------- COLORS ----------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
TURQUOISE='\033[38;5;45m'
NC='\033[0m'

# ---------------- MAIN MENU ----------------
StarTunnel_main_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country' 2>/dev/null || echo "Unknown")
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp' 2>/dev/null || echo "Unknown")

    echo "+-----------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}     _____ ______ ___     ____     ______ __  __ _   __ ______ __     __ ${NC}"
    echo -e "${TURQUOISE}    / ___//_  __//   |   / __ \   /_  __// / / // | / // ____// /    / / ${NC}"
    echo -e "${TURQUOISE}    \__ \  / /  / /| |  / /_/ /    / /  / / / //  |/ // __/  / /    / /  ${NC}"
    echo -e "${TURQUOISE}   ___/ / / /  / ___ | / _, _/    / /  / /_/ // /|  // /___ / /___ / /___${NC}"
    echo -e "${TURQUOISE}  /____/ /_/  /_/  |_|/_/ |_|    /_/   \____//_/ |_//_____//_____//_____/ ${NC}"
    echo -e "${TURQUOISE}                                                                           ${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${RED}@ServerStar_ir ${NC}| Version : ${GREEN} 2.0.0 ${NC} "
    echo "+-----------------------------------------------------------------------------+"      
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Select Tunnel Type:${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo "1- Star VXLAN Tunnel (Original)"
    echo "2- Star VXLAN Tunnel (Advanced)"
    echo "3- Star SIT Tunnel (IPv4/IPv6)"
    echo "4- Star HAProxy Manager"
    echo "5- Install BBR"
    echo "6- System Tools"
    echo "0- Exit"
    echo "+-----------------------------------------------------------------------------+"
}

# ---------------- STAR VXLAN TUNNEL (ORIGINAL) ----------------
star_vxlan_original() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country' 2>/dev/null || echo "Unknown")
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp' 2>/dev/null || echo "Unknown")

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
    echo -e "|${YELLOW}Please choose an option:${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo "1- Install new tunnel"
    echo "2- Uninstall tunnel(s)"
    echo "3- Install BBR"
    echo "4- Cronjob settings"
    echo "0- Back to main menu"
    echo "+-----------------------------------------------------------------------------+"

    read -p "Enter your choice [0-4]: " choice
    case $choice in
        0) return ;;
        1) setup_vxlan_original ;;
        2) uninstall_all_vxlan ;;
        3) install_bbr ;;
        4) cronjob_settings ;;
        *) echo "Invalid option" && sleep 2 && star_vxlan_original ;;
    esac
}

setup_vxlan_original() {
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

        # HAProxy choice
        while true; do
            read -p "Should port forwarding be done automatically? (It is done with haproxy tool) [1-yes, 2-no]: " haproxy_choice
            if [[ "$haproxy_choice" == "1" || "$haproxy_choice" == "2" ]]; then
                break
            else
                echo "Please enter 1 (yes) or 2 (no)."
            fi
        done
        
        if [[ "$haproxy_choice" == "1" ]]; then
            install_haproxy_and_configure
        else
            echo "IRAN Server setup complete."
            echo -e "####################################"
            echo -e "# Your IPv4 : 30.0.0.1            #"
            echo -e "####################################"
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

        echo "Kharej Server setup complete."
        echo -e "####################################"
        echo -e "# Your IPv4 : 30.0.0.2            #"
        echo -e "####################################"

        VXLAN_IP="30.0.0.2/24"
        REMOTE_IP=$IRAN_IP
    else
        echo "[x] Invalid role selected."
        return
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

    cat <<EOF > /usr/local/bin/vxlan_bridge.sh
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
# Persistent keepalive: ping remote every 30s in background
( while true; do ping -c 1 $REMOTE_IP >/dev/null 2>&1; sleep 30; done ) &
EOF

    chmod +x /usr/local/bin/vxlan_bridge.sh

    cat <<EOF > /etc/systemd/system/vxlan-tunnel.service
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
    systemctl daemon-reload
    systemctl enable vxlan-tunnel.service
    systemctl start vxlan-tunnel.service

    echo -e "\n${GREEN}[✓] VXLAN tunnel service enabled to run on boot.${NC}"
    echo "[✓] VXLAN tunnel setup completed successfully."
    
    read -p "Press Enter to return to menu..."
    star_vxlan_original
}

# ---------------- STAR VXLAN TUNNEL (ADVANCED) ----------------
star_vxlan_advanced() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country' 2>/dev/null || echo "Unknown")
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp' 2>/dev/null || echo "Unknown")

    echo "+-------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}     _____ ______ ___     ____     ______ __  __ _   __ ______ __     __ ${NC}"
    echo -e "${TURQUOISE}    / ___//_  __//   |   / __ \   /_  __// / / // | / // ____// /    / / ${NC}"
    echo -e "${TURQUOISE}    \__ \  / /  / /| |  / /_/ /    / /  / / / //  |/ // __/  / /    / /  ${NC}"
    echo -e "${TURQUOISE}   ___/ / / /  / ___ | / _, _/    / /  / /_/ // /|  // /___ / /___ / /___${NC}"
    echo -e "${TURQUOISE}  /____/ /_/  /_/  |_|/_/ |_|    /_/   \____//_/ |_//_____//_____//_____/ ${NC}"
    echo "+-------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${MAGENTA}@ServerStar_ir ${NC}| Version : ${GREEN} 2.0.0 ${NC} "
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose an option:${NC}"
    echo "+-------------------------------------------------------------------------+"
    echo "1- Install new tunnel"
    echo "2- Uninstall tunnel(s)"
    echo "3- Install BBR"
    echo "4- Cronjob settings"
    echo "0- Back to main menu"
    echo "+-------------------------------------------------------------------------+"

    read -p "Enter your choice [0-4]: " main_action
    case $main_action in
        0) return ;;
        1) install_advanced_tunnel ;;
        2) uninstall_all_vxlan ;;
        3) install_bbr ;;
        4) cronjob_settings ;;
        *) echo "[x] Invalid option. Try again." && sleep 1 && star_vxlan_advanced ;;
    esac
}

install_advanced_tunnel() {
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

        # HAProxy choice
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
        return
    fi

    # Detect default interface
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    
    # Setup VXLAN (same as original)
    ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
    ip addr add $VXLAN_IP dev $VXLAN_IF
    ip link set $VXLAN_IF up

    # Add iptables rules
    iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
    iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
    iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

    echo -e "${GREEN}[✓] Advanced VXLAN tunnel setup completed.${NC}"
    read -p "Press Enter to return to menu..."
    star_vxlan_advanced
}

# ---------------- STAR SIT TUNNEL ----------------
star_sit_tunnel() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country' 2>/dev/null || echo "Unknown")
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp' 2>/dev/null || echo "Unknown")
    tunnel_status=$(check_sit_status)

    echo "+--------------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}     _____ ______ ___     ____     ______ __  __ _   __ ______ __     __ ${NC}"
    echo -e "${TURQUOISE}    / ___//_  __//   |   / __ \   /_  __// / / // | / // ____// /    / / ${NC}"
    echo -e "${TURQUOISE}    \__ \  / /  / /| |  / /_/ /    / /  / / / //  |/ // __/  / /    / /  ${NC}"
    echo -e "${TURQUOISE}   ___/ / / /  / ___ | / _, _/    / /  / /_/ // /|  // /___ / /___ / /___${NC}"
    echo -e "${TURQUOISE}  /____/ /_/  /_/  |_|/_/ |_|    /_/   \____//_/ |_//_____//_____//_____/ ${NC}"
    echo "+--------------------------------------------------------------------------------+"
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo -e "|${GREEN}Server Tunnel     |${NC} $tunnel_status"
    echo "+--------------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose an option:${NC}"
    echo "+--------------------------------------------------------------------------------+"
    echo "1- Config Tunnel"
    echo "2- Uninstall"
    echo "3- Install BBR"
    echo "4- Manage Tunnels"
    echo "0- Back to main menu"
    echo "+--------------------------------------------------------------------------------+"

    read -p "Enter option number: " choice
    case $choice in
        0) return ;;
        1) install_sit_tunnel ;;
        2) uninstall_sit ;;
        3) install_bbr ;;
        4) manage_sit_tunnels ;;
        *) echo "Invalid option" && sleep 1 && star_sit_tunnel ;;
    esac
}

install_sit_tunnel() {
    echo "| 1  - IRAN"
    echo "| 2  - Kharej"
    echo "| 3  - IRAN (IPv4 Local)"
    echo "| 4  - Kharej (IPv4 Local)"
    echo "| 0  - Exit"

    read -p "Enter option number: " setup

    case $setup in
    1|3)
        read -p "How many servers: " server_count
        last_number=$(find_last_tunnel_number)
        next_number=$((last_number + 1))

        echo -e "\n${GREEN}Choose IP configuration:${NC}"
        echo "1- Enter IP manually (recommended)"
        echo "2- Set IP automatically"
        read -p "Enter your choice: " ip_choice

        for ((i=next_number;i<next_number+server_count;i++))
        do
            if [ "$ip_choice" = "1" ]; then
                if [ "$setup" = "1" ]; then
                    iran_setup $i
                else
                    iran_setup_ipv4 $i
                fi
            else
                if [ "$setup" = "1" ]; then
                    auto_ipv6="fd25:2895:dc$(printf "%02d" $i)::1"
                    iran_setup_auto $i "$auto_ipv6"
                else
                    auto_ipv4="10.0.$(printf "%d" $i).1"
                    iran_setup_auto_ipv4 $i "$auto_ipv4"
                fi
            fi
        done
        ;;  
    2|4)
        echo -e "\n${GREEN}Choose IP configuration:${NC}"
        echo "1- Enter IP manually (recommended)"
        echo "2- Set IP automatically"
        read -p "Enter your choice: " ip_choice

        if [ "$ip_choice" = "1" ]; then
            read -p "How many servers: " server_count
            last_number=$(find_last_tunnel_number)
            next_number=$((last_number + 1))
            for ((i=next_number;i<next_number+server_count;i++))
            do
                if [ "$setup" = "2" ]; then
                    kharej_setup $i
                else
                    kharej_setup_ipv4 $i
                fi
            done
        else
            read -p "What is the server number? " server_number
            if [ "$setup" = "2" ]; then
                auto_ipv6="fd25:2895:dc$(printf "%02d" $server_number)::2"
                kharej_setup_auto $server_number "$auto_ipv6"
            else
                auto_ipv4="10.0.$(printf "%d" $server_number).2"
                kharej_setup_auto_ipv4 $server_number "$auto_ipv4"
            fi
        fi
        ;;
    0)
        return
        ;;
    *)
        echo "Not valid"
        ;;
    esac
    
    read -p "Press Enter to return to menu..."
    star_sit_tunnel
}

# ---------------- SIT TUNNEL FUNCTIONS ----------------
find_last_tunnel_number() {
    local last_number=0
    for file in /etc/netplan/starconfig-*.yaml; do
        if [ -f "$file" ]; then
            local number=$(echo "$file" | grep -o 'starconfig-[0-9]*' | cut -d'-' -f2)
            if [ "$number" -gt "$last_number" ]; then
                last_number=$number
            fi
        fi
    done
    echo $last_number
}

iran_setup() {
    echo -e "${YELLOW}Setting up IRAN server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv6 Local : " ipv6_local
    
    cat <<EOL > /etc/netplan/starconfig-$1.yaml
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
    chmod 600 /etc/netplan/starconfig-$1.yaml
    
    netplan apply 2>/dev/null

    cat <<EOL > /root/connectors-$1.sh
#!/bin/bash
while true; do
    ping6 -c 1 $ipv6_local::2 >/dev/null 2>&1
    sleep 30
done
EOL

    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6 : $ipv6_local::1      #"
    echo -e "####################################"
}

iran_setup_ipv4() {
    echo -e "${YELLOW}Setting up IRAN server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv4 Local : " ipv4_local
    
    cat <<EOL > /etc/netplan/starconfig-$1.yaml
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
    chmod 600 /etc/netplan/starconfig-$1.yaml
    
    netplan apply 2>/dev/null

    cat <<EOL > /root/connectors-$1.sh
#!/bin/bash
while true; do
    ping -c 1 ${ipv4_local%.*}.2 >/dev/null 2>&1
    sleep 30
done
EOL

    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4 : $ipv4_local         #"
    echo -e "####################################"
}

kharej_setup() {
    echo -e "${YELLOW}Setting up Kharej server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv6 Local : " ipv6_local
    
    cat <<EOL > /etc/netplan/starconfig-$1.yaml
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
    chmod 600 /etc/netplan/starconfig-$1.yaml
    
    netplan apply 2>/dev/null

    cat <<EOL > /root/connectors-$1.sh
#!/bin/bash
while true; do
    ping6 -c 1 $ipv6_local::1 >/dev/null 2>&1
    sleep 30
done
EOL

    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6 : $ipv6_local::2      #"
    echo -e "####################################"
}

kharej_setup_ipv4() {
    echo -e "${YELLOW}Setting up Kharej server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    read -p "Enter IPv4 Local : " ipv4_local
    
    cat <<EOL > /etc/netplan/starconfig-$1.yaml
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
    chmod 600 /etc/netplan/starconfig-$1.yaml
    
    netplan apply 2>/dev/null

    cat <<EOL > /root/connectors-$1.sh
#!/bin/bash
while true; do
    ping -c 1 ${ipv4_local%.*}.1 >/dev/null 2>&1
    sleep 30
done
EOL

    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4 : $ipv4_local         #"
    echo -e "####################################"
}

iran_setup_auto() {
    echo -e "${YELLOW}Setting up IRAN server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    
    cat <<EOL > /etc/netplan/starconfig-$1.yaml
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
    chmod 600 /etc/netplan/starconfig-$1.yaml
    
    netplan apply 2>/dev/null

    cat <<EOL > /root/connectors-$1.sh
#!/bin/bash
while true; do
    ping6 -c 1 ${2%::1}::2 >/dev/null 2>&1
    sleep 30
done
EOL

    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6 : $2                  #"
    echo -e "####################################"
}

kharej_setup_auto() {
    echo -e "${YELLOW}Setting up Kharej server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    
    cat <<EOL > /etc/netplan/starconfig-$1.yaml
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
    chmod 600 /etc/netplan/starconfig-$1.yaml
    
    netplan apply 2>/dev/null

    cat <<EOL > /root/connectors-$1.sh
#!/bin/bash
while true; do
    ping6 -c 1 ${2%::2}::1 >/dev/null 2>&1
    sleep 30
done
EOL

    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv6 : $2                  #"
    echo -e "####################################"
}

iran_setup_auto_ipv4() {
    echo -e "${YELLOW}Setting up IRAN server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    
    cat <<EOL > /etc/netplan/starconfig-$1.yaml
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
    chmod 600 /etc/netplan/starconfig-$1.yaml
    
    netplan apply 2>/dev/null

    cat <<EOL > /root/connectors-$1.sh
#!/bin/bash
while true; do
    ping -c 1 ${2%.*}.2 >/dev/null 2>&1
    sleep 30
done
EOL

    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "IRAN Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4 : $2                  #"
    echo -e "####################################"
}

kharej_setup_auto_ipv4() {
    echo -e "${YELLOW}Setting up Kharej server $1${NC}"
    
    read -p "Enter IRAN IP    : " iran_ip
    read -p "Enter Kharej IP  : " kharej_ip
    
    cat <<EOL > /etc/netplan/starconfig-$1.yaml
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
    chmod 600 /etc/netplan/starconfig-$1.yaml
    
    netplan apply 2>/dev/null

    cat <<EOL > /root/connectors-$1.sh
#!/bin/bash
while true; do
    ping -c 1 ${2%.*}.1 >/dev/null 2>&1
    sleep 30
done
EOL

    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"

    echo "Kharej Server $1 setup complete."
    echo -e "####################################"
    echo -e "# Your IPv4 : $2                  #"
    echo -e "####################################"
}

check_sit_status() {
    local file_path="/etc/netplan/starconfig-1.yaml"
    if [ -f "$file_path" ]; then
        echo -e "${GREEN}Installed${NC}"
    else
        echo -e "${RED}Not installed${NC}"
    fi
}

uninstall_sit() {
    echo -e "${GREEN}Uninstalling Star SIT tunnels...${NC}"
    
    # Stop all screen sessions
    pkill screen
    
    # Find all tunnel0858 interfaces and delete them
    for iface in $(ip link show | grep 'tunnel0858' | awk -F': ' '{print $2}' | cut -d'@' -f1); do
        echo -e "${YELLOW}Removing interface $iface...${NC}"
        ip link set $iface down 2>/dev/null
        ip link delete $iface 2>/dev/null
    done
    
    # Remove netplan configuration files
    rm -f /etc/netplan/starconfig*.yaml
    netplan apply 2>/dev/null
    
    # Remove connector scripts
    rm -f /root/connectors-*.sh
    
    echo -e "${GREEN}Star SIT tunnels uninstalled successfully!${NC}"
    
    read -p "Press Enter to return to menu..."
    star_sit_tunnel
}

manage_sit_tunnels() {
    clear
    echo "+--------------------------------------------------------------+"
    echo "|                    Star Tunnel Management                   |"
    echo "+--------------------------------------------------------------+"
    
    # List all existing tunnels
    echo -e "\n${GREEN}Existing Tunnels:${NC}"
    ls /etc/netplan/starconfig-*.yaml 2>/dev/null | while read -r file; do
        tunnel_name=$(basename "$file" .yaml)
        echo -e "${YELLOW}$tunnel_name${NC}"
    done
    
    echo -e "\n${GREEN}Options:${NC}"
    echo "1) Delete Tunnel"
    echo "0) Back to SIT Menu"
    
    read -p "Enter your choice: " choice
    
    case $choice in
        1)
            read -p "Enter tunnel name to delete (e.g., starconfig-1): " tunnel_name
            if [ -f "/etc/netplan/$tunnel_name.yaml" ]; then
                # Stop the connector script if it exists
                tunnel_num=$(echo $tunnel_name | cut -d'-' -f2)
                if [ -f "/root/connectors-$tunnel_num.sh" ]; then
                    pkill -f "connectors-$tunnel_num.sh"
                    rm "/root/connectors-$tunnel_num.sh"
                fi
                
                # Remove the tunnel interface
                iface_name="tunnel0858-$tunnel_num"
                ip link set $iface_name down 2>/dev/null
                ip link delete $iface_name 2>/dev/null
                
                # Remove the tunnel configuration
                rm "/etc/netplan/$tunnel_name.yaml"
                netplan apply 2>/dev/null
                echo -e "${GREEN}Tunnel deleted successfully!${NC}"
            else
                echo -e "${RED}Tunnel not found!${NC}"
            fi
            ;;
        0)
            star_sit_tunnel
            return
            ;;
        *)
            echo -e "${RED}Invalid choice!${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
    manage_sit_tunnels
}

# ---------------- STAR HAPROXY MANAGER ----------------
star_haproxy_manager() {
    clear
    echo "+----------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}     _____ ______ ___     ____     ______ __  __ _   __ ______ __     __ ${NC}"
    echo -e "${TURQUOISE}    / ___//_  __//   |   / __ \   /_  __// / / // | / // ____// /    / / ${NC}"
    echo -e "${TURQUOISE}    \__ \  / /  / /| |  / /_/ /    / /  / / / //  |/ // __/  / /    / /  ${NC}"
    echo -e "${TURQUOISE}   ___/ / / /  / ___ | / _, _/    / /  / /_/ // /|  // /___ / /___ / /___${NC}"
    echo -e "${TURQUOISE}  /____/ /_/  /_/  |_|/_/ |_|    /_/   \____//_/ |_//_____//_____//_____/ ${NC}"
    echo "+----------------------------------------------------------------------------+"
    echo "|Select an option:"
    echo "|1) Install HAProxy"
    echo "|2) Add IPs and Ports to Forward"
    echo "|3) Clear Configurations"
    echo "|4) Remove HAProxy Completely"
    echo "|0) Back to main menu"
    echo "+----------------------------------------------------------------------------+"

    read -p "Select a Number : " choice

    case $choice in
        0) return ;;
        1) install_haproxy_standalone ;;
        2) add_ip_ports ;;
        3) clear_configs ;;
        4) remove_haproxy ;;
        *) echo "Invalid option. Please try again." && sleep 2 && star_haproxy_manager ;;
    esac
}

install_haproxy_standalone() {
    echo "Installing HAProxy..."
    sudo apt-get update
    sudo apt-get install -y haproxy
    echo "HAProxy installed."
    default_haproxy_config
    read -p "Press Enter to return to menu..."
    star_haproxy_manager
}

default_haproxy_config() {
    local config_file="/etc/haproxy/haproxy.cfg"
    cat <<EOL > $config_file
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

add_ip_ports() {
    read -p "Enter the IPs to forward to (use comma , to separate multiple IPs): " user_ips
    IFS=',' read -r -a ips_array <<< "$user_ips"
    read -p "Enter the ports (use comma , to separate): " user_ports
    IFS=',' read -r -a ports_array <<< "$user_ports"
    generate_haproxy_config "${ports_array[*]}" "${ips_array[*]}"

    if haproxy -c -f /etc/haproxy/haproxy.cfg; then
        echo "Restarting HAProxy service..."
        systemctl restart haproxy
        echo "HAProxy configuration updated and service restarted."
    else
        echo "HAProxy configuration is invalid. Please check the configuration file."
    fi
    
    read -p "Press Enter to return to menu..."
    star_haproxy_manager
}

generate_haproxy_config() {
    local ports=($1)
    local target_ips=($2)
    local config_file="/etc/haproxy/haproxy.cfg"

    echo "Generating HAProxy configuration..."

    for port in "${ports[@]}"; do
        cat <<EOL >> $config_file

frontend frontend_$port
    bind *:$port
    default_backend backend_$port

backend backend_$port
EOL
        for i in "${!target_ips[@]}"; do
            if [ $i -eq 0 ]; then
                cat <<EOL >> $config_file
    server server$(($i+1)) ${target_ips[$i]}:$port check
EOL
            else
                cat <<EOL >> $config_file
    server server$(($i+1)) ${target_ips[$i]}:$port check backup
EOL
            fi
        done
    done

    echo "HAProxy configuration generated at $config_file"
}

clear_configs() {
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
    sudo systemctl stop haproxy
    
    echo "Configurations cleared!"
    
    read -p "Press Enter to return to menu..."
    star_haproxy_manager
}

remove_haproxy() {
    echo "Removing HAProxy..."
    sudo apt-get remove --purge -y haproxy
    sudo apt-get autoremove -y
    echo "HAProxy removed."
    
    read -p "Press Enter to return to menu..."
    star_haproxy_manager
}

# ---------------- SHARED FUNCTIONS ----------------
install_haproxy_and_configure() {
    echo "[*] Configuring HAProxy..."

    # Ensure haproxy is installed
    if ! command -v haproxy >/dev/null 2>&1; then
        echo "[x] HAProxy is not installed. Installing..."
        sudo apt update && sudo apt install -y haproxy
    fi

    # Ensure config directory exists
    sudo mkdir -p /etc/haproxy

    # Default HAProxy config file
    local CONFIG_FILE="/etc/haproxy/haproxy.cfg"
    local BACKUP_FILE="/etc/haproxy/haproxy.cfg.bak"

    # Backup old config
    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$BACKUP_FILE"

    # Write base config
    cat <<EOL > "$CONFIG_FILE"
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
        cat <<EOL >> "$CONFIG_FILE"

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
    # Remove HAProxy package
    apt remove -y haproxy 2>/dev/null
    apt purge -y haproxy 2>/dev/null
    apt autoremove -y 2>/dev/null
    # Remove related cronjobs
    crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' | grep -v '/etc/ping_vxlan.sh' > /tmp/cron_tmp || true
    crontab /tmp/cron_tmp 2>/dev/null
    rm -f /tmp/cron_tmp
    echo "[+] All VXLAN tunnels and related cronjobs deleted."
    
    read -p "Press Enter to return to menu..."
}

install_bbr() {
    echo "Running BBR script..."
    curl -fsSL https://raw.githubusercontent.com/Moriistar/tunellstar/main/bbr.sh -o /tmp/bbr.sh
    bash /tmp/bbr.sh
    rm -f /tmp/bbr.sh
    
    read -p "Press Enter to return to menu..."
}

cronjob_settings() {
    while true; do
        clear
        echo "+-----------------------------+"
        echo "|      Cronjob settings       |"
        echo "+-----------------------------+"
        echo "1- Install cronjob"
        echo "2- Edit cronjob"
        echo "3- Delete cronjob"
        echo "4- Back to previous menu"
        read -p "Enter your choice [1-4]: " cron_action
        case $cron_action in
            1)
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
                        rm -f /tmp/cron_tmp
                        echo -e "${GREEN}Cronjob set successfully to restart services every $cron_hours hour(s).${NC}"
                        read -p "Press Enter to return to Cronjob settings..."
                        break
                    else
                        echo "Invalid input. Please enter a number between 1 and 24 or 'b' to go back."
                    fi
                done
                ;;
            2)
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
                            rm -f /tmp/cron_tmp
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
                ;;
            3)
                if crontab -l 2>/dev/null | grep -q 'systemctl restart haproxy'; then
                    crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
                    crontab /tmp/cron_tmp
                    rm -f /tmp/cron_tmp
                    echo -e "${GREEN}Cronjob deleted successfully.${NC}"
                else
                    echo -e "${YELLOW}No cronjob found to delete.${NC}"
                fi
                read -p "Press Enter to return to Cronjob settings..."
                ;;
            4)
                break
                ;;
            *)
                echo "[x] Invalid option. Try again."
                sleep 1
                ;;
        esac
    done
}

system_tools() {
    clear
    echo "+-----------------------------+"
    echo "|       System Tools          |"
    echo "+-----------------------------+"
    echo "1- Update System"
    echo "2- Install Dependencies"
    echo "3- System Information"
    echo "0- Back to main menu"
    
    read -p "Enter your choice: " choice
    case $choice in
        0) return ;;
        1) 
            echo "Updating system..."
            sudo apt update && sudo apt upgrade -y
            echo "System updated successfully!"
            read -p "Press Enter to continue..."
            system_tools
            ;;
        2)
            install_dependencies
            echo "Dependencies installed successfully!"
            read -p "Press Enter to continue..."
            system_tools
            ;;
        3)
            clear
            echo "=== System Information ==="
            echo "Hostname: $(hostname)"
            echo "OS: $(lsb_release -d | cut -f2)"
            echo "Kernel: $(uname -r)"
            echo "CPU: $(lscpu | grep 'Model name' | cut -d':' -f2 | xargs)"
            echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
            echo "Disk: $(df -h / | tail -1 | awk '{print $3 "/" $2 " (" $5 " used)"}')"
            echo "Uptime: $(uptime -p)"
            read -p "Press Enter to continue..."
            system_tools
            ;;
        *)
            echo "Invalid option"
            sleep 1
            system_tools
            ;;
    esac
}

# ---------------- SETUP PANEL COMMAND ----------------
setup_panel_command() {
    # Create the panel-star command
    cat << 'EOF' > /usr/local/bin/panel-star
#!/bin/bash
bash <(curl -Ls https://raw.githubusercontent.com/Moriistar/tunellstar/main/install.sh)
EOF
    
    chmod +x /usr/local/bin/panel-star
    
    echo -e "${GREEN}Panel command installed successfully!${NC}"
    echo -e "${YELLOW}You can now run 'panel-star' command from anywhere to access the tunnel panel.${NC}"
}

# ---------------- MAIN PROGRAM ----------------
main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        exit 1
    fi

    # Install dependencies on first run
    install_dependencies
    
    # Setup panel command
    setup_panel_command

    while true; do
        StarTunnel_main_menu
        read -p "Enter your choice [0-6]: " choice
        
        case $choice in
            0)
                echo -e "${GREEN}Thanks for using StarTunnel!${NC}"
                echo -e "${YELLOW}Telegram: @ServerStar_ir${NC}"
                exit 0
                ;;
            1)
                star_vxlan_original
                ;;
            2)
                star_vxlan_advanced
                ;;
            3)
                star_sit_tunnel
                ;;
            4)
                star_haproxy_manager
                ;;
            5)
                install_bbr
                ;;
            6)
                system_tools
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 2
                ;;
        esac
    done
}

# Start the main program
main "$@"
