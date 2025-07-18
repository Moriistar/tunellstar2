#!/bin/bash

# StarTunnel Enhanced - Created by MoriiStar
# Telegram Channel: @ServerStar_ir
# Enhanced with features from Lena, Nebula, and HAProxy

# ---------------- INSTALL DEPENDENCIES ----------------
echo "[*] Installing prerequisites..."
sudo apt update -y >/dev/null 2>&1
sudo apt install -y iproute2 net-tools grep awk sudo iputils-ping jq curl haproxy obfs4proxy screen iptables >/dev/null 2>&1

# ---------------- COLORS ----------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
TURQUOISE='\033[38;5;45m'
NC='\033[0m'

# ---------------- FUNCTIONS ----------------

check_core_status() {
    if ip link show | grep -q 'vxlan'; then
        echo "VXLAN Active"
    elif ls /etc/netplan/mramini-*.yaml >/dev/null 2>&1; then
        echo "SIT Active"
    else
        echo "Inactive"
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit 1
    fi
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
        if ! command -v obfs4proxy &> /dev/null; then
            echo -e "${RED}Failed to install obfs4proxy. Please install it manually.${NC}"
            exit 1
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
        openssl req -new -x509 -key "$obfs4_key" -out "$obfs4_cert" -days 365 -subj "/CN=obfs4"
        
        echo -e "${GREEN}obfs4 certificate and private key generated successfully.${NC}"
    fi
}

start_obfs4() {
    echo -e "${YELLOW}Starting obfs4 service...${NC}"
    obfs4proxy -logLevel INFO -enableLogging >/dev/null 2>&1 &
    echo -e "${GREEN}obfs4 service started successfully.${NC}"
}

StarTunnel_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country')
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp')
    TUNNEL_STATUS=$(check_core_status)

    echo "+-----------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}    ╔═══╦════╦═══╦═══╗        ╔════╦╗─╔╦═╗─╔╦═══╦╗──╔╗${NC}"
    echo -e "${TURQUOISE}    ║╔═╗║╔╗╔╗║╔═╗║╔═╗║        ║╔╗╔╗║║─║║║╚╗║║╔══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ║╚══╬╝║║╚╣║─║║╚═╝║        ╚╝║║╚╣║─║║╔╗╚╝║╚══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ╚══╗║─║║─║╚═╝║╔╗╔╝        ──║║─║║─║║║╚╗║║╔══╣║─╔╣║─╔╗${NC}"
    echo -e "${TURQUOISE}    ║╚═╝║─║║─║╔═╗║║║╚╗        ──║║─║╚═╝║║─║║║╚══╣╚═╝║╚═╝║${NC}"
    echo -e "${TURQUOISE}    ╚═══╝─╚╝─╚╝─╚╩╝╚═╝        ──╚╝─╚═══╩╝─╚═╩═══╩═══╩═══╝${NC}" 
    echo "+-----------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${RED}@ServerStar_ir ${NC}| Version : ${GREEN} 2.0.0 Enhanced ${NC} "
    echo -e "| Created by : ${MAGENTA}MoriiStar ${NC}| Enhanced with Lena, Nebula, HAProxy ${NC}"
    echo "+-----------------------------------------------------------------------------+"      
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo -e "|${GREEN}Tunnel Status     |${NC} $TUNNEL_STATUS"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose an option:${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "1- VXLAN Tunnel (Original StarTunnel)"
    echo -e "2- SIT Tunnel (IPv6/IPv4 - Nebula Style)"
    echo -e "3- Tunnel Management"
    echo -e "4- HAProxy Management"
    echo -e "5- Cronjob Management"
    echo -e "6- Install BBR"
    echo -e "7- Uninstall All Tunnels"
    echo -e "0- Exit"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "\033[0m"
}

# VXLAN Tunnel Functions (Original StarTunnel)
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
        
        # Ask about HAProxy
        while true; do
            read -p "Do you want to use HAProxy for port forwarding? (y/n): " haproxy_choice
            case $haproxy_choice in
                [Yy]|[Yy][Ee][Ss]) install_haproxy_and_configure; break ;;
                [Nn]|[Nn][Oo]) echo "Continuing without HAProxy..."; break ;;
                *) echo "Please answer y or n." ;;
            esac
        done

        VXLAN_IP="30.0.0.1/24"
        REMOTE_IP=$KHAREJ_IP
        echo "IRAN Server setup complete."
        echo "Your IPv4: 30.0.0.1"

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
        echo "Kharej Server setup complete."
        echo "Your IPv4: 30.0.0.2"
    else
        echo "Invalid role selected."
        return
    fi

    # Setup VXLAN
    VNI=88
    VXLAN_IF="vxlan${VNI}"
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    
    echo "[+] Creating VXLAN interface..."
    ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
    ip addr add $VXLAN_IP dev $VXLAN_IF
    ip link set $VXLAN_IF up

    # Add iptables rules
    iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
    iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
    iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

    # Create systemd service
    cat > /usr/local/bin/vxlan_bridge.sh << EOF
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
EOF
    chmod +x /usr/local/bin/vxlan_bridge.sh

    cat > /etc/systemd/system/vxlan-tunnel.service << EOF
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

    echo -e "${GREEN}VXLAN tunnel setup completed successfully.${NC}"
}

# SIT Tunnel Functions (Nebula Style)
find_last_tunnel_number() {
    local last_number=0
    for file in /etc/netplan/mramini-*.yaml; do
        if [ -f "$file" ]; then
            local number=$(echo "$file" | grep -o 'mramini-[0-9]*' | cut -d'-' -f2)
            if [ "$number" -gt "$last_number" ]; then
                last_number=$number
            fi
        fi
    done
    echo $last_number
}

install_sit_tunnel() {
    echo "Choose server role:"
    echo "1- Iran (IPv6)"
    echo "2- Kharej (IPv6)"
    echo "3- Iran (IPv4)"
    echo "4- Kharej (IPv4)"
    read -p "Enter choice (1-4): " sit_choice

    case $sit_choice in
        1|3)
            read -p "How many servers: " server_count
            last_number=$(find_last_tunnel_number)
            next_number=$((last_number + 1))

            echo "Choose IP configuration:"
            echo "1- Enter IP manually"
            echo "2- Set IP automatically"
            read -p "Enter your choice: " ip_choice

            for ((i=next_number;i<next_number+server_count;i++)); do
                if [ "$ip_choice" = "1" ]; then
                    if [ "$sit_choice" = "1" ]; then
                        iran_setup_ipv6 $i
                    else
                        iran_setup_ipv4 $i
                    fi
                else
                    if [ "$sit_choice" = "1" ]; then
                        auto_ipv6="fd25:2895:dc$(printf "%02d" $i)::1"
                        iran_setup_auto_ipv6 $i "$auto_ipv6"
                    else
                        auto_ipv4="10.0.$(printf "%d" $i).1"
                        iran_setup_auto_ipv4 $i "$auto_ipv4"
                    fi
                fi
            done
            ;;
        2|4)
            echo "Choose IP configuration:"
            echo "1- Enter IP manually"
            echo "2- Set IP automatically"
            read -p "Enter your choice: " ip_choice

            if [ "$ip_choice" = "1" ]; then
                read -p "How many servers: " server_count
                last_number=$(find_last_tunnel_number)
                next_number=$((last_number + 1))
                for ((i=next_number;i<next_number+server_count;i++)); do
                    if [ "$sit_choice" = "2" ]; then
                        kharej_setup_ipv6 $i
                    else
                        kharej_setup_ipv4 $i
                    fi
                done
            else
                read -p "What is the server number? " server_number
                if [ "$sit_choice" = "2" ]; then
                    auto_ipv6="fd25:2895:dc$(printf "%02d" $server_number)::2"
                    kharej_setup_auto_ipv6 $server_number "$auto_ipv6"
                else
                    auto_ipv4="10.0.$(printf "%d" $server_number).2"
                    kharej_setup_auto_ipv4 $server_number "$auto_ipv4"
                fi
            fi
            ;;
    esac
}

iran_setup_ipv6() {
    echo -e "${YELLOW}Setting up IRAN server $1 (IPv6)${NC}"
    read -p "Enter IRAN IP: " iran_ip
    read -p "Enter Kharej IP: " kharej_ip
    read -p "Enter IPv6 Local: " ipv6_local
    
    cat > /etc/netplan/mramini-$1.yaml << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $ipv6_local::1/64
EOF
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply
    
    configure_obfs4
    start_obfs4
    
    cat > /root/connectors-$1.sh << EOF
ping $ipv6_local::2
EOF
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"
    
    echo "IRAN Server $1 setup complete."
    echo "Your IPv6: $ipv6_local::1"
}

iran_setup_ipv4() {
    echo -e "${YELLOW}Setting up IRAN server $1 (IPv4)${NC}"
    read -p "Enter IRAN IP: " iran_ip
    read -p "Enter Kharej IP: " kharej_ip
    read -p "Enter IPv4 Local: " ipv4_local
    
    cat > /etc/netplan/mramini-$1.yaml << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $ipv4_local/24
EOF
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply
    
    configure_obfs4
    start_obfs4
    
    cat > /root/connectors-$1.sh << EOF
ping ${ipv4_local%.*}.2
EOF
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"
    
    echo "IRAN Server $1 setup complete."
    echo "Your IPv4: $ipv4_local"
}

kharej_setup_ipv6() {
    echo -e "${YELLOW}Setting up Kharej server $1 (IPv6)${NC}"
    read -p "Enter IRAN IP: " iran_ip
    read -p "Enter Kharej IP: " kharej_ip
    read -p "Enter IPv6 Local: " ipv6_local
    
    cat > /etc/netplan/mramini-$1.yaml << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $kharej_ip
      remote: $iran_ip
      addresses:
        - $ipv6_local::2/64
EOF
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply
    
    configure_obfs4
    start_obfs4
    
    cat > /root/connectors-$1.sh << EOF
ping $ipv6_local::1
EOF
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"
    
    echo "Kharej Server $1 setup complete."
    echo "Your IPv6: $ipv6_local::2"
}

kharej_setup_ipv4() {
    echo -e "${YELLOW}Setting up Kharej server $1 (IPv4)${NC}"
    read -p "Enter IRAN IP: " iran_ip
    read -p "Enter Kharej IP: " kharej_ip
    read -p "Enter IPv4 Local: " ipv4_local
    
    cat > /etc/netplan/mramini-$1.yaml << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $kharej_ip
      remote: $iran_ip
      addresses:
        - $ipv4_local/24
EOF
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply
    
    configure_obfs4
    start_obfs4
    
    cat > /root/connectors-$1.sh << EOF
ping ${ipv4_local%.*}.1
EOF
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"
    
    echo "Kharej Server $1 setup complete."
    echo "Your IPv4: $ipv4_local"
}

iran_setup_auto_ipv6() {
    echo -e "${YELLOW}Setting up IRAN server $1 (Auto IPv6)${NC}"
    read -p "Enter IRAN IP: " iran_ip
    read -p "Enter Kharej IP: " kharej_ip
    
    cat > /etc/netplan/mramini-$1.yaml << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $2/64
EOF
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply
    
    configure_obfs4
    start_obfs4
    
    cat > /root/connectors-$1.sh << EOF
ping ${2%::1}::2
EOF
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"
    
    echo "IRAN Server $1 setup complete."
    echo "Your IPv6: $2"
}

iran_setup_auto_ipv4() {
    echo -e "${YELLOW}Setting up IRAN server $1 (Auto IPv4)${NC}"
    read -p "Enter IRAN IP: " iran_ip
    read -p "Enter Kharej IP: " kharej_ip
    
    cat > /etc/netplan/mramini-$1.yaml << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $2/24
EOF
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply
    
    configure_obfs4
    start_obfs4
    
    cat > /root/connectors-$1.sh << EOF
ping ${2%.*}.2
EOF
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"
    
    echo "IRAN Server $1 setup complete."
    echo "Your IPv4: $2"
}

kharej_setup_auto_ipv6() {
    echo -e "${YELLOW}Setting up Kharej server $1 (Auto IPv6)${NC}"
    read -p "Enter IRAN IP: " iran_ip
    read -p "Enter Kharej IP: " kharej_ip
    
    cat > /etc/netplan/mramini-$1.yaml << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $kharej_ip
      remote: $iran_ip
      addresses:
        - $2/64
EOF
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply
    
    configure_obfs4
    start_obfs4
    
    cat > /root/connectors-$1.sh << EOF
ping ${2%::2}::1
EOF
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"
    
    echo "Kharej Server $1 setup complete."
    echo "Your IPv6: $2"
}

kharej_setup_auto_ipv4() {
    echo -e "${YELLOW}Setting up Kharej server $1 (Auto IPv4)${NC}"
    read -p "Enter IRAN IP: " iran_ip
    read -p "Enter Kharej IP: " kharej_ip
    
    cat > /etc/netplan/mramini-$1.yaml << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$1:
      mode: sit
      local: $kharej_ip
      remote: $iran_ip
      addresses:
        - $2/24
EOF
    chmod 600 /etc/netplan/mramini-$1.yaml
    netplan apply
    
    configure_obfs4
    start_obfs4
    
    cat > /root/connectors-$1.sh << EOF
ping ${2%.*}.1
EOF
    chmod +x /root/connectors-$1.sh
    screen -dmS connectors_session_$1 bash -c "/root/connectors-$1.sh"
    
    echo "Kharej Server $1 setup complete."
    echo "Your IPv4: $2"
}

# Tunnel Management Functions
manage_tunnels() {
    while true; do
        clear
        echo "+-----------------------------------------------------------------------------+"
        echo "|                          Tunnel Management                                  |"
        echo "+-----------------------------------------------------------------------------+"
        
        echo -e "\n${GREEN}Existing VXLAN Tunnels:${NC}"
        if ip link show | grep -q vxlan; then
            ip link show | grep vxlan | awk '{print $2}' | cut -d: -f1
        else
            echo "No VXLAN tunnels found"
        fi
        
        echo -e "\n${GREEN}Existing SIT Tunnels:${NC}"
        if ls /etc/netplan/mramini-*.yaml >/dev/null 2>&1; then
            ls /etc/netplan/mramini-*.yaml | while read -r file; do
                echo "$(basename "$file" .yaml)"
            done
        else
            echo "No SIT tunnels found"
        fi
        
        echo -e "\n${GREEN}Options:${NC}"
        echo "1- Edit SIT Tunnel"
        echo "2- Delete SIT Tunnel"
        echo "3- Delete VXLAN Tunnel"
        echo "4- Show Tunnel Status"
        echo "0- Back to Main Menu"
        
        read -p "Enter your choice: " choice
        
        case $choice in
            1)
                read -p "Enter tunnel name to edit (e.g., mramini-1): " tunnel_name
                if [ -f "/etc/netplan/$tunnel_name.yaml" ]; then
                    read -p "Enter new IRAN IP: " iran_ip
                    read -p "Enter new Kharej IP: " kharej_ip
                    read -p "Enter new IPv6/IPv4 Local: " ip_local
                    
                    cat > "/etc/netplan/$tunnel_name.yaml" << EOF
network:
  version: 2
  tunnels:
    tunnel0858-$(echo $tunnel_name | cut -d'-' -f2):
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $ip_local/64
EOF
                    netplan apply
                    echo -e "${GREEN}Tunnel updated successfully!${NC}"
                else
                    echo -e "${RED}Tunnel not found!${NC}"
                fi
                ;;
            2)
                read -p "Enter tunnel name to delete (e.g., mramini-1): " tunnel_name
                if [ -f "/etc/netplan/$tunnel_name.yaml" ]; then
                    if [ -f "/root/connectors-$(echo $tunnel_name | cut -d'-' -f2).sh" ]; then
                        pkill -f "connectors-$(echo $tunnel_name | cut -d'-' -f2).sh"
                        rm "/root/connectors-$(echo $tunnel_name | cut -d'-' -f2).sh"
                    fi
                    rm "/etc/netplan/$tunnel_name.yaml"
                    netplan apply
                    echo -e "${GREEN}SIT Tunnel deleted successfully!${NC}"
                else
                    echo -e "${RED}Tunnel not found!${NC}"
                fi
                ;;
            3)
                echo "Available VXLAN interfaces:"
                ip link show | grep vxlan | awk '{print $2}' | cut -d: -f1
                read -p "Enter VXLAN interface name to delete: " vxlan_name
                if ip link show | grep -q "$vxlan_name"; then
                    ip link del "$vxlan_name"
                    echo -e "${GREEN}VXLAN interface deleted successfully!${NC}"
                else
                    echo -e "${RED}VXLAN interface not found!${NC}"
                fi
                ;;
            4)
                echo -e "\n${GREEN}Tunnel Status:${NC}"
                echo "VXLAN Tunnels:"
                ip link show | grep vxlan || echo "No VXLAN tunnels"
                echo -e "\nSIT Tunnels:"
                ls /etc/netplan/mramini-*.yaml 2>/dev/null || echo "No SIT tunnels"
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}Invalid choice!${NC}"
                ;;
        esac
        
        read -p "Press Enter to continue..."
    done
}

# HAProxy Management Functions
haproxy_menu() {
    while true; do
        clear
        echo "+-----------------------------------------------------------------------------+"
        echo "|                           HAProxy Management                                |"
        echo "+-----------------------------------------------------------------------------+"
        echo -e "| Created by : ${MAGENTA}MoriiStar ${NC}| Channel : ${RED}@ServerStar_ir ${NC}"
        echo "+-----------------------------------------------------------------------------+"
        echo -e "|${YELLOW}HAProxy Management:${NC}"
        echo "+-----------------------------------------------------------------------------+"
        echo -e "1- Install HAProxy"
        echo -e "2- Add IPs and Ports to Forward"
        echo -e "3- Clear Configurations"
        echo -e "4- Remove HAProxy Completely"
        echo -e "5- Show HAProxy Status"
        echo -e "0- Back to Main Menu"
        echo "+-----------------------------------------------------------------------------+"
        
        read -p "Select a Number: " haproxy_choice
        
        case $haproxy_choice in
            1) install_haproxy_standalone ;;
            2) add_ip_ports ;;
            3) clear_configs ;;
            4) remove_haproxy ;;
            5) show_haproxy_status ;;
            0) break ;;
            *) echo "Invalid option. Please try again." && sleep 1 ;;
        esac
    done
}

install_haproxy_standalone() {
    echo "Installing HAProxy..."
    sudo apt-get update
    sudo apt-get install -y haproxy
    echo "HAProxy installed."
    default_config
    read -p "Press Enter to continue..."
}

default_config() {
    local config_file="/etc/haproxy/haproxy.cfg"
    cat > $config_file << EOF
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
EOF
}

add_ip_ports() {
    read -p "Enter the IPs to forward to (use comma , to separate multiple IPs): " user_ips
    IFS=',' read -r -a ips_array <<< "$user_ips"
    read -p "Enter the ports (use comma , to separate): " user_ports
    IFS=',' read -r -a ports_array <<< "$user_ports"
    
    default_config
    generate_haproxy_config "${ports_array[*]}" "${ips_array[*]}"

    if haproxy -c -f /etc/haproxy/haproxy.cfg; then
        echo "Restarting HAProxy service..."
        systemctl restart haproxy
        systemctl enable haproxy
        echo "HAProxy configuration updated and service restarted."
    else
        echo "HAProxy configuration is invalid. Please check the configuration file."
    fi
    read -p "Press Enter to continue..."
}

generate_haproxy_config() {
    local ports=($1)
    local target_ips=($2)
    local config_file="/etc/haproxy/haproxy.cfg"

    echo "Generating HAProxy configuration..."

    for port in "${ports[@]}"; do
        cat >> $config_file << EOF

frontend frontend_$port
    bind *:$port
    default_backend backend_$port
    option tcpka

backend backend_$port
    option tcpka
EOF
        for i in "${!target_ips[@]}"; do
            if [ $i -eq 0 ]; then
                cat >> $config_file << EOF
    server server$(($i+1)) ${target_ips[$i]}:$port check maxconn 2048
EOF
            else
                cat >> $config_file << EOF
    server server$(($i+1)) ${target_ips[$i]}:$port check backup maxconn 2048
EOF
            fi
        done
    done

    echo "HAProxy configuration generated."
}

clear_configs() {
    local config_file="/etc/haproxy/haproxy.cfg"
    local backup_file="/etc/haproxy/haproxy.cfg.bak"
    
    echo "Creating a backup of the HAProxy configuration..."
    cp $config_file $backup_file

    echo "Clearing IP and port configurations from HAProxy configuration..."
    default_config
    echo "Stopping HAProxy service..."
    systemctl stop haproxy
    echo "HAProxy service stopped and configurations cleared."
    read -p "Press Enter to continue..."
}

remove_haproxy() {
    echo "Removing HAProxy..."
    sudo apt-get remove --purge -y haproxy
    sudo apt-get autoremove -y
    echo "HAProxy removed."
    read -p "Press Enter to continue..."
}

show_haproxy_status() {
    echo -e "\n${GREEN}HAProxy Status:${NC}"
    systemctl status haproxy --no-pager
    echo -e "\n${GREEN}HAProxy Configuration:${NC}"
    if [ -f "/etc/haproxy/haproxy.cfg" ]; then
        cat /etc/haproxy/haproxy.cfg
    else
        echo "No HAProxy configuration found."
    fi
    read -p "Press Enter to continue..."
}

install_haproxy_and_configure() {
    echo "[*] Installing and configuring HAProxy..."
    
    if ! command -v haproxy &> /dev/null; then
        sudo apt-get install -y haproxy
    fi

    local CONFIG_FILE="/etc/haproxy/haproxy.cfg"
    local BACKUP_FILE="/etc/haproxy/haproxy.cfg.bak"

    [ -f "$CONFIG_FILE" ] && cp "$CONFIG_FILE" "$BACKUP_FILE"

    cat > "$CONFIG_FILE" << EOF
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
EOF

    read -p "Enter target IP (destination server): " target_ip
    read -p "Enter ports (comma-separated): " user_ports

    IFS=',' read -ra ports <<< "$user_ports"

    for port in "${ports[@]}"; do
        port=$(echo "$port" | tr -d ' ')
        cat >> "$CONFIG_FILE" << EOF

frontend frontend_$port
    bind *:$port
    default_backend backend_$port
    option tcpka

backend backend_$port
    option tcpka
    server server1 $target_ip:$port check maxconn 2048
EOF
    done

    if haproxy -c -f "$CONFIG_FILE"; then
        echo "[*] Restarting HAProxy service..."
        systemctl restart haproxy
        systemctl enable haproxy
        echo -e "${GREEN}HAProxy configured and restarted successfully.${NC}"
    else
        echo -e "${RED}Warning: HAProxy configuration is invalid!${NC}"
    fi
}

# Cronjob Management Functions
cronjob_menu() {
    while true; do
        clear
        echo "+-----------------------------------------------------------------------------+"
        echo "|                         Cronjob Management                                  |"
        echo "+-----------------------------------------------------------------------------+"
        echo -e "| Created by : ${MAGENTA}MoriiStar ${NC}| Channel : ${RED}@ServerStar_ir ${NC}"
        echo "+-----------------------------------------------------------------------------+"
        echo -e "|${YELLOW}Cronjob Management:${NC}"
        echo "+-----------------------------------------------------------------------------+"
        echo -e "1- Add Tunnel Restart Cronjob"
        echo -e "2- Add HAProxy Restart Cronjob"
        echo -e "3- Add Custom Cronjob"
        echo -e "4- List Current Cronjobs"
        echo -e "5- Remove Cronjobs"
        echo -e "0- Back to Main Menu"
        echo "+-----------------------------------------------------------------------------+"
        
        read -p "Select a Number: " cron_choice
        
        case $cron_choice in
            1) add_tunnel_cronjob ;;
            2) add_haproxy_cronjob ;;
            3) add_custom_cronjob ;;
            4) list_cronjobs ;;
            5) remove_cronjobs ;;
            0) break ;;
            *) echo "Invalid option. Please try again." && sleep 1 ;;
        esac
    done
}

add_tunnel_cronjob() {
    while true; do
        read -p "How many hours between each tunnel restart? (1-24): " cron_hours
        if [[ $cron_hours =~ ^[0-9]+$ ]] && (( cron_hours >= 1 && cron_hours <= 24 )); then
            break
        else
            echo "Invalid input. Please enter a number between 1 and 24."
        fi
    done
    
    crontab -l 2>/dev/null | grep -v 'systemctl restart vxlan-tunnel' | grep -v 'netplan apply' > /tmp/cron_tmp || true
    echo "0 */$cron_hours * * * systemctl restart vxlan-tunnel >/dev/null 2>&1" >> /tmp/cron_tmp
    echo "0 */$cron_hours * * * netplan apply >/dev/null 2>&1" >> /tmp/cron_tmp
    crontab /tmp/cron_tmp
    rm /tmp/cron_tmp
    echo -e "${GREEN}Tunnel restart cronjob set successfully for every $cron_hours hour(s).${NC}"
    read -p "Press Enter to continue..."
}

add_haproxy_cronjob() {
    while true; do
        read -p "How many hours between each HAProxy restart? (1-24): " cron_hours
        if [[ $cron_hours =~ ^[0-9]+$ ]] && (( cron_hours >= 1 && cron_hours <= 24 )); then
            break
        else
            echo "Invalid input. Please enter a number between 1 and 24."
        fi
    done
    
    crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' > /tmp/cron_tmp || true
    echo "0 */$cron_hours * * * systemctl restart haproxy >/dev/null 2>&1" >> /tmp/cron_tmp
    crontab /tmp/cron_tmp
    rm /tmp/cron_tmp
    echo -e "${GREEN}HAProxy restart cronjob set successfully for every $cron_hours hour(s).${NC}"
    read -p "Press Enter to continue..."
}

add_custom_cronjob() {
    echo "Enter cronjob schedule (e.g., '0 2 * * *' for daily at 2 AM):"
    read -p "Schedule: " cron_schedule
    echo "Enter command to execute:"
    read -p "Command: " cron_command
    
    crontab -l 2>/dev/null > /tmp/cron_tmp || true
    echo "$cron_schedule $cron_command" >> /tmp/cron_tmp
    crontab /tmp/cron_tmp
    rm /tmp/cron_tmp
    echo -e "${GREEN}Custom cronjob added successfully.${NC}"
    read -p "Press Enter to continue..."
}

list_cronjobs() {
    echo -e "\n${GREEN}Current Cronjobs:${NC}"
    crontab -l 2>/dev/null || echo "No cronjobs found."
    read -p "Press Enter to continue..."
}

remove_cronjobs() {
    echo "Choose cronjobs to remove:"
    echo "1- Remove all tunnel-related cronjobs"
    echo "2- Remove all HAProxy-related cronjobs"
    echo "3- Remove all cronjobs"
    echo "4- Remove specific cronjob"
    read -p "Enter your choice: " remove_choice
    
    case $remove_choice in
        1)
            crontab -l 2>/dev/null | grep -v 'systemctl restart vxlan-tunnel' | grep -v 'netplan apply' > /tmp/cron_tmp || true
            crontab /tmp/cron_tmp
            rm /tmp/cron_tmp
            echo -e "${GREEN}Tunnel-related cronjobs removed.${NC}"
            ;;
        2)
            crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' > /tmp/cron_tmp || true
            crontab /tmp/cron_tmp
            rm /tmp/cron_tmp
            echo -e "${GREEN}HAProxy-related cronjobs removed.${NC}"
            ;;
        3)
            crontab -r 2>/dev/null || echo "No cronjobs to remove."
            echo -e "${GREEN}All cronjobs removed.${NC}"
            ;;
        4)
            echo "Current cronjobs:"
            crontab -l 2>/dev/null | nl
            read -p "Enter line number to remove: " line_num
            crontab -l 2>/dev/null | sed "${line_num}d" > /tmp/cron_tmp
            crontab /tmp/cron_tmp
            rm /tmp/cron_tmp
            echo -e "${GREEN}Cronjob removed.${NC}"
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
    read -p "Press Enter to continue..."
}

# BBR Installation
install_bbr() {
    echo "Running BBR script..."
    curl -fsSL https://raw.githubusercontent.com/MrAminiDev/NetOptix/main/scripts/bbr.sh -o /tmp/bbr.sh
    bash /tmp/bbr.sh
    rm /tmp/bbr.sh
    read -p "Press Enter to continue..."
}

# Uninstall Functions
uninstall_all_tunnels() {
    echo "[!] Deleting all tunnels and cleaning up..."
    
    # Remove VXLAN tunnels
    for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
        ip link del $i 2>/dev/null
    done
    
    # Remove SIT tunnels
    pkill screen
    for iface in $(ip link show | grep 'tunnel0858' | awk -F': ' '{print $2}' | cut -d'@' -f1); do
        echo -e "${YELLOW}Removing interface $iface...${NC}"
        ip link set $iface down
        ip link delete $iface
    done
    
    # Remove configuration files
    rm -f /usr/local/bin/vxlan_bridge.sh /etc/ping_vxlan.sh
    rm -f /etc/netplan/mramini*.yaml
    rm -f /root/connectors-*.sh
    
    # Remove systemd services
    systemctl disable --now vxlan-tunnel.service 2>/dev/null
    systemctl disable --now ping-monitor.service 2>/dev/null
    rm -f /etc/systemd/system/vxlan-tunnel.service
    rm -f /etc/systemd/system/ping-monitor.service
    rm -f /root/ping_monitor.sh
    
    # Remove HAProxy
    systemctl stop haproxy 2>/dev/null
    systemctl disable haproxy 2>/dev/null
    
    # Remove obfs4
    pkill obfs4proxy
    rm -rf /etc/obfs4
    
    # Apply network changes
    netplan apply
    systemctl restart systemd-networkd
    systemctl daemon-reload
    
    # Remove related cronjobs
    crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' | grep -v 'netplan apply' > /tmp/cron_tmp || true
    crontab /tmp/cron_tmp
    rm /tmp/cron_tmp
    
    echo -e "${GREEN}All tunnels and related services have been removed.${NC}"
    read -p "Press Enter to continue..."
}

# Network utilities
netplan_setup() {
    command -v netplan &> /dev/null || { 
        sudo apt update && sudo apt install -y netplan.io
    }
}

# Initialize required components
init() {
    install_jq
    install_obfs4
    sudo apt-get install -y iproute2 screen netplan.io
    netplan_setup
}

# Main execution
check_root
init

while true; do
    StarTunnel_menu
    read -p "Enter your choice [0-7]: " main_action
    case $main_action in
        1)
            install_vxlan_tunnel
            ;;
        2)
            install_sit_tunnel
            ;;
        3)
            manage_tunnels
            ;;
        4)
            haproxy_menu
            ;;
        5)
            cronjob_menu
            ;;
        6)
            install_bbr
            ;;
        7)
            uninstall_all_tunnels
            ;;
        0)
            echo -e "${GREEN}Exiting StarTunnel Enhanced...${NC}"
            echo -e "${MAGENTA}Thank you for using StarTunnel Enhanced!${NC}"
            echo -e "${YELLOW}Created by MoriiStar | @ServerStar_ir${NC}"
            exit 0
            ;;
        *)
            echo "[x] Invalid option. Try again."
            sleep 1
            ;;
    esac
done
