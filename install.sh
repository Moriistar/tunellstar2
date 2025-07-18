 #!/bin/bash

# ===============================================
# StarTunnel Pro - Enhanced Multi-Tunnel Script
# Version: 2.0.0
# Author: @ServerStar_ir
# ===============================================

# ---------------- INSTALL DEPENDENCIES ----------------
echo "[*] Installing prerequisites..."
sudo apt update -y >/dev/null 2>&1
sudo apt install -y iproute2 net-tools grep awk sudo iputils-ping jq curl haproxy iptables systemd >/dev/null 2>&1

# ---------------- COLORS ----------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
TURQUOISE='\033[38;5;45m'

# ---------------- GLOBAL VARIABLES ----------------
SCRIPT_DIR="/etc/startunnel"
CONFIG_FILE="$SCRIPT_DIR/tunnels.conf"
HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
SYSTEMD_DIR="/etc/systemd/system"

# Create script directory
mkdir -p "$SCRIPT_DIR"

# ---------------- FUNCTIONS ----------------

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Please run as root${NC}"
        exit 1
    fi
}

detect_ipv6() {
    local interface=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    local ipv6=$(ip -6 addr show $interface | grep -oP 'inet6 \K[^/]+' | grep -v '^fe80' | head -n1)
    echo "$ipv6"
}

save_tunnel_config() {
    local tunnel_id=$1
    local role=$2
    local local_ipv6=$3
    local remote_ipv6=$4
    local vni=$5
    local port=$6
    local local_ip=$7
    
    echo "TUNNEL_${tunnel_id}_ROLE=$role" >> "$CONFIG_FILE"
    echo "TUNNEL_${tunnel_id}_LOCAL_IPV6=$local_ipv6" >> "$CONFIG_FILE"
    echo "TUNNEL_${tunnel_id}_REMOTE_IPV6=$remote_ipv6" >> "$CONFIG_FILE"
    echo "TUNNEL_${tunnel_id}_VNI=$vni" >> "$CONFIG_FILE"
    echo "TUNNEL_${tunnel_id}_PORT=$port" >> "$CONFIG_FILE"
    echo "TUNNEL_${tunnel_id}_LOCAL_IP=$local_ip" >> "$CONFIG_FILE"
}

load_tunnel_configs() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
}

check_tunnel_status() {
    local tunnel_id=$1
    local vxlan_if="vxlan${tunnel_id}"
    
    if ip link show "$vxlan_if" >/dev/null 2>&1; then
        echo -e "${GREEN}Active${NC}"
    else
        echo -e "${RED}Inactive${NC}"
    fi
}

list_active_tunnels() {
    echo -e "${CYAN}=== Active Tunnels ===${NC}"
    echo -e "${YELLOW}ID\tInterface\tLocal IP\t\tRemote IP\tStatus${NC}"
    echo "----------------------------------------------------------------"
    
    for vxlan in $(ip -d link show | grep -o 'vxlan[0-9]\+' | sort -u); do
        local tunnel_id=${vxlan#vxlan}
        local local_ip=$(ip addr show "$vxlan" | grep -oP 'inet \K[^/]+' | head -n1)
        local remote_ip=$(ip -d link show "$vxlan" | grep -oP 'remote \K[^ ]+')
        local status=$(check_tunnel_status "$tunnel_id")
        
        echo -e "$tunnel_id\t$vxlan\t\t$local_ip\t$remote_ip\t$status"
    done
}

StarTunnel_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country' 2>/dev/null || echo "Unknown")
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp' 2>/dev/null || echo "Unknown")
    IPV6_ADDR=$(detect_ipv6)

    echo "+-----------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}    ╔═══╦════╦═══╦═══╗        ╔════╦╗─╔╦═╗─╔╦═══╦╗──╔╗${NC}"
    echo -e "${TURQUOISE}    ║╔═╗║╔╗╔╗║╔═╗║╔═╗║        ║╔╗╔╗║║─║║║╚╗║║╔══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ║╚══╬╝║║╚╣║─║║╚═╝║        ╚╝║║╚╣║─║║╔╗╚╝║╚══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ╚══╗║─║║─║╚═╝║╔╗╔╝        ──║║─║║─║║║╚╗║║╔══╣║─╔╣║─╔╗${NC}"
    echo -e "${TURQUOISE}    ║╚═╝║─║║─║╔═╗║║║╚╗        ──║║─║╚═╝║║─║║║╚══╣╚═╝║╚═╝║${NC}"
    echo -e "${TURQUOISE}    ╚═══╝─╚╝─╚╝─╚╩╝╚═╝        ──╚╝─╚═══╩╝─╚═╩═══╩═══╩═══╝${NC}" 
    echo "+-----------------------------------------------------------------------------+"
    echo -e "| Telegram Channel : ${RED}@ServerStar_ir ${NC}| Version : ${GREEN} 2.0.0 Pro ${NC} "
    echo "+-----------------------------------------------------------------------------+"      
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server IPv6       |${NC} ${IPV6_ADDR:-'Not Available'}"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW}Please choose an option:${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "1- Install Single Tunnel (IPv4 VXLAN)"
    echo -e "2- Install Multi-Tunnel (IPv6 VXLAN)"
    echo -e "3- Manage Existing Tunnels"
    echo -e "4- HAProxy Management"
    echo -e "5- Show Tunnel Status"
    echo -e "6- Install BBR"
    echo -e "7- Setup Monitoring & Cronjobs"
    echo -e "8- Uninstall All Tunnels"
    echo -e "9- Exit"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "\033[0m"
}

install_single_tunnel() {
    echo -e "${CYAN}=== Single Tunnel Installation ===${NC}"
    
    # Choose server role
    echo "Choose server role:"
    echo "1- Iran"
    echo "2- Kharej"
    read -p "Enter choice (1/2): " role_choice

    if [[ "$role_choice" == "1" ]]; then
        read -p "Enter IRAN IP: " IRAN_IP
        read -p "Enter Kharej IP: " KHAREJ_IP
        VXLAN_IP="30.0.0.1/24"
        REMOTE_IP=$KHAREJ_IP
        ROLE="iran"
    elif [[ "$role_choice" == "2" ]]; then
        read -p "Enter IRAN IP: " IRAN_IP
        read -p "Enter Kharej IP: " KHAREJ_IP
        VXLAN_IP="30.0.0.2/24"
        REMOTE_IP=$IRAN_IP
        ROLE="kharej"
    else
        echo -e "${RED}[!] Invalid role selected.${NC}"
        return 1
    fi

    # Port validation
    while true; do
        read -p "Tunnel port (1-64435): " DSTPORT
        if [[ $DSTPORT =~ ^[0-9]+$ ]] && (( DSTPORT >= 1 && DSTPORT <= 64435 )); then
            break
        else
            echo "Invalid port. Try again."
        fi
    done

    # HAProxy configuration
    while true; do
        read -p "Configure HAProxy for port forwarding? (y/n): " haproxy_choice
        case $haproxy_choice in
            [Yy]*) 
                setup_haproxy_single
                break
                ;;
            [Nn]*) 
                echo "Continuing without HAProxy..."
                break
                ;;
            *) 
                echo "Please answer y or n."
                ;;
        esac
    done

    # Setup tunnel
    local VNI=88
    local VXLAN_IF="vxlan${VNI}"
    local INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)

    echo "[+] Creating VXLAN interface..."
    ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning

    echo "[+] Assigning IP $VXLAN_IP to $VXLAN_IF"
    ip addr add $VXLAN_IP dev $VXLAN_IF
    ip link set $VXLAN_IF up

    echo "[+] Adding iptables rules"
    iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
    iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
    iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT

    create_systemd_service $VNI $REMOTE_IP $VXLAN_IP $INTERFACE $DSTPORT

    # Save configuration
    save_tunnel_config $VNI $ROLE $(hostname -I | awk '{print $1}') $REMOTE_IP $VNI $DSTPORT ${VXLAN_IP%/*}

    echo -e "${GREEN}[✓] Single tunnel setup completed successfully.${NC}"
    echo -e "${YELLOW}Tunnel IP: ${VXLAN_IP%/*}${NC}"
}

install_multi_tunnel() {
    echo -e "${CYAN}=== Multi-Tunnel IPv6 Installation ===${NC}"
    
    # Check IPv6 support
    local ipv6_addr=$(detect_ipv6)
    if [ -z "$ipv6_addr" ]; then
        echo -e "${RED}[!] IPv6 not detected. Please configure IPv6 first.${NC}"
        return 1
    fi

    echo -e "${GREEN}Detected IPv6: $ipv6_addr${NC}"

    # Choose server role
    echo "Choose server role:"
    echo "1- Iran"
    echo "2- Kharej"
    read -p "Enter choice (1/2): " role_choice

    if [[ "$role_choice" == "1" ]]; then
        read -p "Enter Iran IPv6: " LOCAL_IPV6
        read -p "Enter Kharej IPv6: " REMOTE_IPV6
        ROLE="iran"
        IP_BASE="172.16"
        IP_SUFFIX="1"
    elif [[ "$role_choice" == "2" ]]; then
        read -p "Enter Iran IPv6: " REMOTE_IPV6
        read -p "Enter Kharej IPv6: " LOCAL_IPV6
        ROLE="kharej"
        IP_BASE="172.16"
        IP_SUFFIX="2"
    else
        echo -e "${RED}[!] Invalid role selected.${NC}"
        return 1
    fi

    # Number of tunnels
    while true; do
        read -p "How many tunnels do you want to create? (1-10): " tunnel_count
        if [[ $tunnel_count =~ ^[0-9]+$ ]] && (( tunnel_count >= 1 && tunnel_count <= 10 )); then
            break
        else
            echo "Invalid number. Please enter 1-10."
        fi
    done

    # Create multiple tunnels
    for ((i=1; i<=tunnel_count; i++)); do
        local vni=$((4000 + i))
        local vxlan_if="vxlan${vni}"
        local local_ip="$IP_BASE.$i.$IP_SUFFIX/30"
        local port=443

        echo -e "${YELLOW}[+] Creating tunnel $i/$tunnel_count (VNI: $vni)${NC}"

        # Create VXLAN interface using IPv6
        ip -6 link add $vxlan_if type vxlan id $vni local $LOCAL_IPV6 remote $REMOTE_IPV6 dstport $port
        ip addr add $local_ip dev $vxlan_if
        ip link set dev $vxlan_if mtu 1430
        ip -6 link set $vxlan_if up

        # Firewall rules
        iptables -I INPUT 1 -p udp --dport $port -j ACCEPT
        ip6tables -I INPUT 1 -s $REMOTE_IPV6 -j ACCEPT

        # Save tunnel config
        save_tunnel_config $vni $ROLE $LOCAL_IPV6 $REMOTE_IPV6 $vni $port ${local_ip%/*}

        # Create systemd service for this tunnel
        create_systemd_service_ipv6 $vni $LOCAL_IPV6 $REMOTE_IPV6 $local_ip $port

        echo -e "${GREEN}[✓] Tunnel $i created: $local_ip${NC}"
    done

    echo -e "${GREEN}[✓] Multi-tunnel setup completed successfully.${NC}"
    echo -e "${YELLOW}Created $tunnel_count tunnels with IPv6 support.${NC}"
}

create_systemd_service() {
    local vni=$1
    local remote_ip=$2
    local vxlan_ip=$3
    local interface=$4
    local port=$5
    local vxlan_if="vxlan${vni}"

    cat > /usr/local/bin/vxlan_bridge_${vni}.sh << EOF
#!/bin/bash
ip link add $vxlan_if type vxlan id $vni local \$(hostname -I | awk '{print \$1}') remote $remote_ip dev $interface dstport $port nolearning
ip addr add $vxlan_ip dev $vxlan_if
ip link set $vxlan_if up
EOF

    chmod +x /usr/local/bin/vxlan_bridge_${vni}.sh

    cat > $SYSTEMD_DIR/vxlan-tunnel-${vni}.service << EOF
[Unit]
Description=VXLAN Tunnel Interface $vni
After=network.target

[Service]
ExecStart=/usr/local/bin/vxlan_bridge_${vni}.sh
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable vxlan-tunnel-${vni}.service
    systemctl start vxlan-tunnel-${vni}.service
}

create_systemd_service_ipv6() {
    local vni=$1
    local local_ipv6=$2
    local remote_ipv6=$3
    local local_ip=$4
    local port=$5
    local vxlan_if="vxlan${vni}"

    cat > /usr/local/bin/vxlan_bridge_${vni}.sh << EOF
#!/bin/bash
ip -6 link add $vxlan_if type vxlan id $vni local $local_ipv6 remote $remote_ipv6 dstport $port
ip addr add $local_ip dev $vxlan_if
ip link set dev $vxlan_if mtu 1430
ip -6 link set $vxlan_if up
EOF

    chmod +x /usr/local/bin/vxlan_bridge_${vni}.sh

    cat > $SYSTEMD_DIR/vxlan-tunnel-${vni}.service << EOF
[Unit]
Description=VXLAN Tunnel Interface $vni (IPv6)
After=network.target

[Service]
ExecStart=/usr/local/bin/vxlan_bridge_${vni}.sh
Type=oneshot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable vxlan-tunnel-${vni}.service
    systemctl start vxlan-tunnel-${vni}.service
}

manage_tunnels() {
    while true; do
        clear
        echo -e "${CYAN}=== Tunnel Management ===${NC}"
        list_active_tunnels
        echo
        echo "1- Start Tunnel"
        echo "2- Stop Tunnel"
        echo "3- Restart Tunnel"
        echo "4- Delete Tunnel"
        echo "5- Show Tunnel Details"
        echo "9- Back to Main Menu"
        echo
        read -p "Enter your choice: " choice

        case $choice in
            1) start_tunnel ;;
            2) stop_tunnel ;;
            3) restart_tunnel ;;
            4) delete_tunnel ;;
            5) show_tunnel_details ;;
            9) break ;;
            *) echo "Invalid option!" && sleep 1 ;;
        esac
    done
}

start_tunnel() {
    read -p "Enter tunnel ID to start: " tunnel_id
    local service_name="vxlan-tunnel-${tunnel_id}.service"
    
    if systemctl start "$service_name"; then
        echo -e "${GREEN}[✓] Tunnel $tunnel_id started successfully.${NC}"
    else
        echo -e "${RED}[!] Failed to start tunnel $tunnel_id.${NC}"
    fi
    read -p "Press Enter to continue..."
}

stop_tunnel() {
    read -p "Enter tunnel ID to stop: " tunnel_id
    local service_name="vxlan-tunnel-${tunnel_id}.service"
    
    if systemctl stop "$service_name"; then
        echo -e "${GREEN}[✓] Tunnel $tunnel_id stopped successfully.${NC}"
    else
        echo -e "${RED}[!] Failed to stop tunnel $tunnel_id.${NC}"
    fi
    read -p "Press Enter to continue..."
}

restart_tunnel() {
    read -p "Enter tunnel ID to restart: " tunnel_id
    local service_name="vxlan-tunnel-${tunnel_id}.service"
    
    if systemctl restart "$service_name"; then
        echo -e "${GREEN}[✓] Tunnel $tunnel_id restarted successfully.${NC}"
    else
        echo -e "${RED}[!] Failed to restart tunnel $tunnel_id.${NC}"
    fi
    read -p "Press Enter to continue..."
}

delete_tunnel() {
    read -p "Enter tunnel ID to delete: " tunnel_id
    local vxlan_if="vxlan${tunnel_id}"
    local service_name="vxlan-tunnel-${tunnel_id}.service"
    
    echo -e "${YELLOW}[!] This will permanently delete tunnel $tunnel_id${NC}"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        # Stop and disable service
        systemctl stop "$service_name" 2>/dev/null
        systemctl disable "$service_name" 2>/dev/null
        
        # Remove interface
        ip link del "$vxlan_if" 2>/dev/null
        
        # Remove files
        rm -f "/usr/local/bin/vxlan_bridge_${tunnel_id}.sh"
        rm -f "$SYSTEMD_DIR/$service_name"
        
        # Remove from config
        sed -i "/TUNNEL_${tunnel_id}_/d" "$CONFIG_FILE"
        
        systemctl daemon-reload
        echo -e "${GREEN}[✓] Tunnel $tunnel_id deleted successfully.${NC}"
    fi
    read -p "Press Enter to continue..."
}

show_tunnel_details() {
    read -p "Enter tunnel ID to show details: " tunnel_id
    local vxlan_if="vxlan${tunnel_id}"
    
    echo -e "${CYAN}=== Tunnel $tunnel_id Details ===${NC}"
    echo
    
    if ip link show "$vxlan_if" >/dev/null 2>&1; then
        echo -e "${GREEN}Status: Active${NC}"
        echo -e "${YELLOW}Interface Details:${NC}"
        ip -d link show "$vxlan_if"
        echo
        echo -e "${YELLOW}IP Configuration:${NC}"
        ip addr show "$vxlan_if"
        echo
        echo -e "${YELLOW}Service Status:${NC}"
        systemctl status "vxlan-tunnel-${tunnel_id}.service" --no-pager
    else
        echo -e "${RED}Status: Inactive${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

haproxy_menu() {
    while true; do
        clear
        echo -e "${CYAN}=== HAProxy Management ===${NC}"
        echo
        echo "1- Install HAProxy"
        echo "2- Configure Load Balancer"
        echo "3- Add Port Forwarding"
        echo "4- Show Current Configuration"
        echo "5- Clear Configuration"
        echo "6- Remove HAProxy"
        echo "9- Back to Main Menu"
        echo
        read -p "Enter your choice: " choice

        case $choice in
            1) install_haproxy ;;
            2) configure_load_balancer ;;
            3) add_port_forwarding ;;
            4) show_haproxy_config ;;
            5) clear_haproxy_config ;;
            6) remove_haproxy ;;
            9) break ;;
            *) echo "Invalid option!" && sleep 1 ;;
        esac
    done
}

install_haproxy() {
    echo -e "${YELLOW}[*] Installing HAProxy...${NC}"
    
    if ! command -v haproxy >/dev/null 2>&1; then
        apt-get update
        apt-get install -y haproxy
    fi
    
    create_default_haproxy_config
    systemctl enable haproxy
    systemctl start haproxy
    
    echo -e "${GREEN}[✓] HAProxy installed and started.${NC}"
    read -p "Press Enter to continue..."
}

create_default_haproxy_config() {
    cat > "$HAPROXY_CONFIG" << 'EOF'
global
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    maxconn 4096

defaults
    mode tcp
    option dontlognull
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    retries 3
    option tcpka

# Stats page
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats hide-version
EOF
}

configure_load_balancer() {
    echo -e "${YELLOW}[*] Configuring Load Balancer...${NC}"
    
    read -p "Enter frontend port: " frontend_port
    read -p "Enter backend servers (IP:PORT,IP:PORT,...): " backend_servers
    
    # Validate input
    if [[ ! $frontend_port =~ ^[0-9]+$ ]]; then
        echo -e "${RED}[!] Invalid port number.${NC}"
        return 1
    fi
    
    IFS=',' read -ra servers <<< "$backend_servers"
    
    # Add to HAProxy config
    cat >> "$HAPROXY_CONFIG" << EOF

frontend frontend_$frontend_port
    bind *:$frontend_port
    mode tcp
    default_backend backend_$frontend_port

backend backend_$frontend_port
    mode tcp
    balance roundrobin
EOF
    
    for i in "${!servers[@]}"; do
        local server="${servers[$i]}"
        echo "    server server$(($i+1)) $server check" >> "$HAPROXY_CONFIG"
    done
    
    # Validate and reload
    if haproxy -c -f "$HAPROXY_CONFIG"; then
        systemctl reload haproxy
        echo -e "${GREEN}[✓] Load balancer configured successfully.${NC}"
    else
        echo -e "${RED}[!] Configuration error. Check HAProxy config.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

add_port_forwarding() {
    echo -e "${YELLOW}[*] Adding Port Forwarding...${NC}"
    
    read -p "Enter source port: " source_port
    read -p "Enter destination IP: " dest_ip
    read -p "Enter destination port: " dest_port
    
    # Validate input
    if [[ ! $source_port =~ ^[0-9]+$ ]] || [[ ! $dest_port =~ ^[0-9]+$ ]]; then
        echo -e "${RED}[!] Invalid port number.${NC}"
        return 1
    fi
    
    # Add to HAProxy config
    cat >> "$HAPROXY_CONFIG" << EOF

frontend frontend_$source_port
    bind *:$source_port
    mode tcp
    default_backend backend_$source_port

backend backend_$source_port
    mode tcp
    server server1 $dest_ip:$dest_port check
EOF
    
    # Validate and reload
    if haproxy -c -f "$HAPROXY_CONFIG"; then
        systemctl reload haproxy
        echo -e "${GREEN}[✓] Port forwarding added successfully.${NC}"
    else
        echo -e "${RED}[!] Configuration error. Check HAProxy config.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

show_haproxy_config() {
    echo -e "${CYAN}=== Current HAProxy Configuration ===${NC}"
    echo
    if [ -f "$HAPROXY_CONFIG" ]; then
        cat "$HAPROXY_CONFIG"
    else
        echo -e "${RED}[!] HAProxy configuration file not found.${NC}"
    fi
    echo
    read -p "Press Enter to continue..."
}

clear_haproxy_config() {
    echo -e "${YELLOW}[!] This will clear all HAProxy configurations.${NC}"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        create_default_haproxy_config
        systemctl reload haproxy
        echo -e "${GREEN}[✓] HAProxy configuration cleared.${NC}"
    fi
    read -p "Press Enter to continue..."
}

remove_haproxy() {
    echo -e "${YELLOW}[!] This will completely remove HAProxy.${NC}"
    read -p "Are you sure? (y/N): " confirm
    
    if [[ $confirm =~ ^[Yy]$ ]]; then
        systemctl stop haproxy
        systemctl disable haproxy
        apt-get remove --purge -y haproxy
        apt-get autoremove -y
        rm -f "$HAPROXY_CONFIG"
        echo -e "${GREEN}[✓] HAProxy removed successfully.${NC}"
    fi
    read -p "Press Enter to continue..."
}

setup_haproxy_single() {
    echo -e "${YELLOW}[*] Setting up HAProxy for single tunnel...${NC}"
    
    if ! command -v haproxy >/dev/null 2>&1; then
        apt-get update
        apt-get install -y haproxy
    fi
    
    create_default_haproxy_config
    
    read -p "Enter ports to forward (comma-separated): " ports
    local local_ip=$(hostname -I | awk '{print $1}')
    
    IFS=',' read -ra port_array <<< "$ports"
    
    for port in "${port_array[@]}"; do
        port=$(echo "$port" | tr -d ' ')
        cat >> "$HAPROXY_CONFIG" << EOF

frontend frontend_$port
    bind *:$port
    mode tcp
    default_backend backend_$port

backend backend_$port
    mode tcp
    server server1 $local_ip:$port check
EOF
    done
    
    if haproxy -c -f "$HAPROXY_CONFIG"; then
        systemctl restart haproxy
        systemctl enable haproxy
        echo -e "${GREEN}[✓] HAProxy configured successfully.${NC}"
    else
        echo -e "${RED}[!] HAProxy configuration error.${NC}"
    fi
}

show_tunnel_status() {
    clear
    echo -e "${CYAN}=== Tunnel Status Overview ===${NC}"
    echo
    
    # System info
    echo -e "${YELLOW}System Information:${NC}"
    echo "Server IP: $(hostname -I | awk '{print $1}')"
    echo "IPv6 Address: $(detect_ipv6)"
    echo "Uptime: $(uptime -p)"
    echo
    
    # Active tunnels
    list_active_tunnels
    echo
    
    # HAProxy status
    echo -e "${YELLOW}HAProxy Status:${NC}"
    if systemctl is-active --quiet haproxy; then
        echo -e "${GREEN}Running${NC}"
        echo "Stats available at: http://$(hostname -I | awk '{print $1}'):8404/stats"
    else
        echo -e "${RED}Stopped${NC}"
    fi
    echo
    
    # Service status
    echo -e "${YELLOW}Service Status:${NC}"
    for service in $(systemctl list-units --type=service --state=running | grep vxlan-tunnel | awk '{print $1}'); do
        local tunnel_id=$(echo "$service" | grep -o '[0-9]\+')
        echo "Tunnel $tunnel_id: $(systemctl is-active $service)"
    done
    
    read -p "Press Enter to continue..."
}

install_bbr() {
    echo -e "${YELLOW}[*] Installing BBR...${NC}"
    curl -fsSL https://raw.githubusercontent.com/MrAminiDev/NetOptix/main/scripts/bbr.sh -o /tmp/bbr.sh
    bash /tmp/bbr.sh
    rm /tmp/bbr.sh
    echo -e "${GREEN}[✓] BBR installation completed.${NC}"
    read -p "Press Enter to continue..."
}

setup_monitoring() {
    echo -e "${CYAN}=== Monitoring & Cronjobs Setup ===${NC}"
    echo
    echo "1- Setup Tunnel Health Check"
    echo "2- Setup Service Restart Cronjob"
    echo "3- Setup Log Rotation"
    echo "4- Setup Backup Cronjob"
    echo "9- Back to Main Menu"
    echo
    read -p "Enter your choice: " choice

    case $choice in
        1) setup_health_check ;;
        2) setup_restart_cronjob ;;
        3) setup_log_rotation ;;
        4) setup_backup_cronjob ;;
        9) return ;;
        *) echo "Invalid option!" && sleep 1 ;;
    esac
}

setup_health_check() {
    echo -e "${YELLOW}[*] Setting up tunnel health check...${NC}"
    
    cat > /usr/local/bin/tunnel_health_check.sh << 'EOF'
#!/bin/bash

LOGFILE="/var/log/tunnel_health.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

echo "[$DATE] Starting tunnel health check" >> $LOGFILE

for service in $(systemctl list-units --type=service --state=running | grep vxlan-tunnel | awk '{print $1}'); do
    tunnel_id=$(echo "$service" | grep -o '[0-9]\+')
    vxlan_if="vxlan${tunnel_id}"
    
    if ! ip link show "$vxlan_if" >/dev/null 2>&1; then
        echo "[$DATE] Tunnel $tunnel_id is down, restarting..." >> $LOGFILE
        systemctl restart "$service"
    fi
done

echo "[$DATE] Health check completed" >> $LOGFILE
EOF
    
    chmod +x /usr/local/bin/tunnel_health_check.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/tunnel_health_check.sh") | crontab -
    
    echo -e "${GREEN}[✓] Health check setup completed.${NC}"
    read -p "Press Enter to continue..."
}

setup_restart_cronjob() {
    read -p "Enter restart interval in hours (1-24): " hours
    
    if [[ ! $hours =~ ^[0-9]+$ ]] || (( hours < 1 || hours > 24 )); then
        echo -e "${RED}[!] Invalid interval.${NC}"
        return 1
    fi
    
    # Remove existing cronjobs
    crontab -l 2>/dev/null | grep -v 'systemctl restart.*tunnel' | crontab -
    
    # Add new cronjob
    (crontab -l 2>/dev/null; echo "0 */$hours * * * systemctl restart haproxy >/dev/null 2>&1") | crontab -
    
    for service in $(systemctl list-units --type=service --state=running | grep vxlan-tunnel | awk '{print $1}'); do
        (crontab -l 2>/dev/null; echo "0 */$hours * * * systemctl restart $service >/dev/null 2>&1") | crontab -
    done
    
    echo -e "${GREEN}[✓] Restart cronjob setup completed.${NC}"
    read -p "Press Enter to continue..."
}

setup_log_rotation() {
    echo -e "${YELLOW}[*] Setting up log rotation...${NC}"
    
    cat > /etc/logrotate.d/startunnel << 'EOF'
/var/log/tunnel_health.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
    
    echo -e "${GREEN}[✓] Log rotation setup completed.${NC}"
    read -p "Press Enter to continue..."
}

setup_backup_cronjob() {
    echo -e "${YELLOW}[*] Setting up configuration backup...${NC}"
    
    cat > /usr/local/bin/backup_tunnel_config.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/root/startunnel_backups"
DATE=$(date '+%Y%m%d_%H%M%S')
BACKUP_FILE="$BACKUP_DIR/tunnel_config_$DATE.tar.gz"

mkdir -p "$BACKUP_DIR"

tar -czf "$BACKUP_FILE" \
    /etc/startunnel/ \
    /etc/haproxy/haproxy.cfg \
    /etc/systemd/system/vxlan-tunnel-*.service \
    /usr/local/bin/vxlan_bridge_*.sh \
    2>/dev/null

# Keep only last 7 backups
ls -t "$BACKUP_DIR"/tunnel_config_*.tar.gz | tail -n +8 | xargs -r rm

echo "Backup created: $BACKUP_FILE"
EOF
    
    chmod +x /usr/local/bin/backup_tunnel_config.sh
    
    # Add to crontab (daily at 2 AM)
    (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/backup_tunnel_config.sh") | crontab -
    
    echo -e "${GREEN}[✓] Backup cronjob setup completed.${NC}"
    read -p "Press Enter to continue..."
}

uninstall_all() {
    echo -e "${RED}[!] This will remove ALL tunnels and configurations.${NC}"
    read -p "Are you sure? Type 'YES' to confirm: " confirm
    
    if [[ "$confirm" == "YES" ]]; then
        echo -e "${YELLOW}[*] Removing all tunnels...${NC}"
        
        # Stop and remove all VXLAN tunnels
        for service in $(systemctl list-units --type=service | grep vxlan-tunnel | awk '{print $1}'); do
            systemctl stop "$service"
            systemctl disable "$service"
        done
        
        # Remove VXLAN interfaces
        for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
            ip link del "$i" 2>/dev/null
        done
        
        # Remove files
        rm -f /etc/systemd/system/vxlan-tunnel-*.service
        rm -f /usr/local/bin/vxlan_bridge_*.sh
        rm -f /usr/local/bin/tunnel_health_check.sh
        rm -f /usr/local/bin/backup_tunnel_config.sh
        rm -rf "$SCRIPT_DIR"
        
        # Remove HAProxy
        systemctl stop haproxy 2>/dev/null
        systemctl disable haproxy 2>/dev/null
        apt-get remove --purge -y haproxy 2>/dev/null
        apt-get autoremove -y 2>/dev/null
        
        # Clean crontab
        crontab -l 2>/dev/null | grep -v 'tunnel\|haproxy\|vxlan' | crontab -
        
        systemctl daemon-reload
        
        echo -e "${GREEN}[✓] All tunnels and configurations removed.${NC}"
    else
        echo -e "${YELLOW}[*] Operation cancelled.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# ---------------- MAIN SCRIPT ----------------

check_root

# Main menu loop
while true; do
    StarTunnel_menu
    read -p "Enter your choice [1-9]: " choice
    
    case $choice in
        1) install_single_tunnel ;;
        2) install_multi_tunnel ;;
        3) manage_tunnels ;;
        4) haproxy_menu ;;
        5) show_tunnel_status ;;
        6) install_bbr ;;
        7) setup_monitoring ;;
        8) uninstall_all ;;
        9) 
            echo -e "${GREEN}Thanks for using StarTunnel Pro!${NC}"
            exit 0
            ;;
        *) 
            echo -e "${RED}[!] Invalid option. Please try again.${NC}"
            sleep 1
            ;;
    esac
done
