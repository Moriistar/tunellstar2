#!/bin/bash

# ============================================================================
# StarTunnel v3.0 - Advanced VxLAN Tunnel Manager
# Developed by: Moriostar
# Channel: @ServerStar_ir
# Features: IPv4/IPv6 Support, Multi-tunnel, Load Balancing, HAProxy Integration
# ============================================================================

# ---------------- INSTALLATION CHECK ----------------
if [[ "$1" == "--install" ]]; then
    echo "[*] Installing StarTunnel..."
    
    # Install prerequisites
    sudo apt update -y >/dev/null 2>&1
    sudo apt install -y iproute2 net-tools grep awk sudo iputils-ping jq curl haproxy systemd bc >/dev/null 2>&1
    
    # Copy script to system path
    cp "$0" /usr/local/bin/panel-star
    chmod +x /usr/local/bin/panel-star
    
    # Create shortcut command
    cat <<'EOF' > /usr/local/bin/star
#!/bin/bash
/usr/local/bin/panel-star
EOF
    chmod +x /usr/local/bin/star
    
    echo "[✓] Installation completed!"
    echo "[✓] Use 'panel-star' or 'star' command to run StarTunnel"
    echo "[✓] Telegram: @ServerStar_ir"
    exit 0
fi

# ---------------- COLORS ----------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------------- GLOBAL VARIABLES ----------------
CONFIG_DIR="/etc/star-tunnel"
TUNNEL_CONFIG="$CONFIG_DIR/tunnels.json"
SERVICE_PREFIX="star-tunnel"
LOG_FILE="/var/log/star-tunnel.log"
VERSION="3.0"
UPDATE_URL="https://raw.githubusercontent.com/Moriistar/tunellstar/main/install.sh"

# Create config directory
mkdir -p "$CONFIG_DIR"

# ---------------- LOGGING ----------------
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# ---------------- IPv6 LOCAL GENERATOR ----------------
generate_ipv6_local() {
    local global_id
    local subnet_id=${1:-1}
    
    # Generate 40-bit random Global ID (RFC 4193)
    global_id=$(openssl rand -hex 5 | sed 's/\(..\)/\1:/g; s/:$//')
    
    # Create ULA prefix: fd + Global ID
    local ula_prefix="fd${global_id}:${subnet_id}"
    
    echo "${ula_prefix}::/64"
}

get_ipv6_local_ip() {
    local prefix=$1
    local host_part=$2
    
    # Remove /64 from prefix and add host part
    local base_prefix=${prefix%/*}
    echo "${base_prefix}::${host_part}"
}

# ---------------- UTILITY FUNCTIONS ----------------
detect_ip_version() {
    local ip=$1
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "ipv4"
    elif [[ $ip =~ ^[0-9a-fA-F:]+$ ]]; then
        echo "ipv6"
    else
        echo "unknown"
    fi
}

get_local_ip() {
    local version=$1
    if [[ "$version" == "ipv4" ]]; then
        hostname -I | awk '{print $1}'
    else
        ip -6 addr show scope global | grep -oP '(?<=inet6\s)[\da-f:]+' | head -1
    fi
}

check_tunnel_status() {
    local tunnel_name=$1
    systemctl is-active --quiet "${SERVICE_PREFIX}-${tunnel_name}.service" && echo "Active" || echo "Inactive"
}

# ---------------- HEADER FUNCTIONS ----------------
show_header() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" 2>/dev/null | jq -r '.country // "Unknown"')
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" 2>/dev/null | jq -r '.isp // "Unknown"')

    echo "+-----------------------------------------------------------------------------+"
TURQUOISE='\033[38;5;45m'
NC='\033[0m'
echo -e "${TURQUOISE}     _____ ______ ___     ____     ______ __  __ _   __ ______ __     __ ${NC}"
echo -e "${TURQUOISE}    / ___//_  __//   |   / __ \   /_  __// / / // | / // ____// /    / / ${NC}"
echo -e "${TURQUOISE}    \__ \  / /  / /| |  / /_/ /    / /  / / / //  |/ // __/  / /    / /  ${NC}"
echo -e "${TURQUOISE}   ___/ / / /  / ___ | / _, _/    / /  / /_/ // /|  // /___ / /___ / /___${NC}"
echo -e "${TURQUOISE}  /____/ /_/  /_/  |_|/_/ |_|    /_/   \____//_/ |_//_____//_____//_____/ ${NC}"
echo -e "${TURQUOISE}                                                                           ${NC}"
echo "+-----------------------------------------------------------------------------+"    echo "+-----------------------------------------------------------------------------+"
    echo -e "| Telegram: ${MAGENTA}@ServerStar_ir${NC} | Version: ${GREEN}${VERSION} Advanced${NC} | Status: ${CYAN}Enhanced${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${GREEN}Server Country    |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}Server IP         |${NC} $SERVER_IP"
    echo -e "|${GREEN}Server ISP        |${NC} $SERVER_ISP"
    echo "+-----------------------------------------------------------------------------+"
}

# ---------------- MAIN MENU ----------------
main_menu() {
    show_header
    echo -e "|${YELLOW}Main Menu - Select Option:${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "1${GREEN}►${NC} StarTunnel Management"
    echo -e "2${BLUE}►${NC} HAProxy Management"
    echo -e "3${CYAN}►${NC} Monitor & Statistics"
    echo -e "4${MAGENTA}►${NC} Advanced Settings"
    echo -e "5${YELLOW}►${NC} Install BBR"
    echo -e "6${RED}►${NC} System Update"
    echo -e "7${GREEN}►${NC} Exit"
    echo "+-----------------------------------------------------------------------------+"
}

# ============================================================================
# STARTUNNEL MANAGEMENT SECTION
# ============================================================================

startunnel_menu() {
    while true; do
        show_header
        echo -e "|${YELLOW}StarTunnel Management${NC}"
        echo "+-----------------------------------------------------------------------------+"
        echo -e "1${GREEN}►${NC} Create New Tunnel"
        echo -e "2${BLUE}►${NC} Manage Existing Tunnels"
        echo -e "3${CYAN}►${NC} Monitor Tunnels"
        echo -e "4${RED}►${NC} Uninstall All Tunnels"
        echo -e "5${YELLOW}►${NC} Back to Main Menu"
        echo "+-----------------------------------------------------------------------------+"
        
        read -p "Enter choice: " choice
        
        case $choice in
            1) create_tunnel ;;
            2) manage_tunnels ;;
            3) monitor_tunnels ;;
            4) uninstall_all_tunnels ;;
            5) return ;;
            *) echo "Invalid choice!" ;;
        esac
    done
}

create_tunnel() {
    echo -e "${GREEN}Creating New StarTunnel${NC}"
    echo "=========================="
    
    # Tunnel name
    read -p "Enter tunnel name: " tunnel_name
    if [[ -z "$tunnel_name" ]]; then
        tunnel_name="star-tunnel-$(date +%s)"
    fi
    
    # Server role selection
    echo ""
    echo "Select server role:"
    echo "1) Iran Server"
    echo "2) Kharej Server"
    read -p "Enter choice (1-2): " role_choice
    
    # IP version and local type selection
    echo ""
    echo "Select IP configuration:"
    echo "1) IPv4"
    echo "2) IPv6"
    echo "3) IPv4 Local"
    echo "4) IPv6 Local"
    echo "5) Auto-detect"
    read -p "Enter choice (1-5): " ip_version_choice
    
    case $ip_version_choice in
        1) ip_version="ipv4"; local_type="public" ;;
        2) ip_version="ipv6"; local_type="public" ;;
        3) ip_version="ipv4"; local_type="local" ;;
        4) ip_version="ipv6"; local_type="local" ;;
        5) ip_version="auto"; local_type="public" ;;
        *) ip_version="auto"; local_type="public" ;;
    esac
    
    # Handle local IP generation
    if [[ "$local_type" == "local" ]]; then
        if [[ "$ip_version" == "ipv4" ]]; then
            echo "Using IPv4 Local range: 10.0.0.0/8"
            if [[ "$role_choice" == "1" ]]; then
                iran_ip="10.0.1.1"
                read -p "Enter Kharej IPv4 Local (default: 10.0.1.2): " kharej_ip
                kharej_ip=${kharej_ip:-"10.0.1.2"}
            else
                kharej_ip="10.0.1.2"
                read -p "Enter Iran IPv4 Local (default: 10.0.1.1): " iran_ip
                iran_ip=${iran_ip:-"10.0.1.1"}
            fi
        else
            echo "Generating IPv6 Local addresses..."
            local ipv6_prefix=$(generate_ipv6_local)
            echo "Generated IPv6 Local prefix: $ipv6_prefix"
            
            if [[ "$role_choice" == "1" ]]; then
                iran_ip=$(get_ipv6_local_ip "$ipv6_prefix" "1")
                kharej_ip=$(get_ipv6_local_ip "$ipv6_prefix" "2")
                echo "Iran IPv6 Local: $iran_ip"
                echo "Kharej IPv6 Local: $kharej_ip"
            else
                iran_ip=$(get_ipv6_local_ip "$ipv6_prefix" "1")
                kharej_ip=$(get_ipv6_local_ip "$ipv6_prefix" "2")
                echo "Iran IPv6 Local: $iran_ip"
                echo "Kharej IPv6 Local: $kharej_ip"
            fi
        fi
    else
        # Get public IP addresses
        if [[ "$role_choice" == "1" ]]; then
            read -p "Enter Iran IP: " iran_ip
            read -p "Enter Kharej IP: " kharej_ip
        else
            read -p "Enter Iran IP: " iran_ip
            read -p "Enter Kharej IP: " kharej_ip
        fi
    fi
    
    # Set local variables based on role
    if [[ "$role_choice" == "1" ]]; then
        local_role="iran"
        local_ip=$iran_ip
        remote_ip=$kharej_ip
        vxlan_ip="30.0.0.1/24"
    else
        local_role="kharej"
        local_ip=$kharej_ip
        remote_ip=$iran_ip
        vxlan_ip="30.0.0.2/24"
    fi
    
    # Port selection
    while true; do
        read -p "Enter tunnel port (1-65535): " tunnel_port
        if [[ $tunnel_port =~ ^[0-9]+$ ]] && (( tunnel_port >= 1 && tunnel_port <= 65535 )); then
            break
        else
            echo "Invalid port. Please try again."
        fi
    done
    
    # VNI selection
    read -p "Enter VNI (default: 88): " vni
    vni=${vni:-88}
    
    # Multi-tunnel support
    echo ""
    read -p "Enable multi-tunnel support? (y/n): " multi_tunnel
    
    # HAProxy configuration
    echo ""
    read -p "Configure HAProxy for port forwarding? (y/n): " haproxy_choice
    
    # Create tunnel configuration
    create_tunnel_config "$tunnel_name" "$local_role" "$ip_version" "$local_type" "$local_ip" "$remote_ip" "$tunnel_port" "$vni" "$vxlan_ip" "$multi_tunnel" "$haproxy_choice"
    
    # Setup tunnel
    setup_tunnel "$tunnel_name"
    
    echo -e "${GREEN}StarTunnel '$tunnel_name' created successfully!${NC}"
    echo -e "${CYAN}Tunnel IP: $vxlan_ip${NC}"
    
    read -p "Press Enter to continue..."
}

create_tunnel_config() {
    local name=$1 role=$2 ip_ver=$3 local_type=$4 local_ip=$5 remote_ip=$6 port=$7 vni=$8 vxlan_ip=$9 multi_tunnel=${10} haproxy=${11}
    
    # Initialize tunnels.json if not exists
    if [[ ! -f "$TUNNEL_CONFIG" ]]; then
        echo '{}' > "$TUNNEL_CONFIG"
    fi
    
    # Add tunnel configuration
    jq --arg name "$name" --arg role "$role" --arg ip_ver "$ip_ver" --arg local_type "$local_type" \
       --arg local_ip "$local_ip" --arg remote_ip "$remote_ip" --arg port "$port" --arg vni "$vni" \
       --arg vxlan_ip "$vxlan_ip" --arg multi_tunnel "$multi_tunnel" --arg haproxy "$haproxy" \
       --arg status "active" --arg created "$(date -Iseconds)" \
       '.[$name] = {
           "role": $role,
           "ip_version": $ip_ver,
           "local_type": $local_type,
           "local_ip": $local_ip,
           "remote_ip": $remote_ip,
           "port": ($port | tonumber),
           "vni": ($vni | tonumber),
           "vxlan_ip": $vxlan_ip,
           "multi_tunnel": $multi_tunnel,
           "haproxy": $haproxy,
           "status": $status,
           "created": $created
       }' "$TUNNEL_CONFIG" > "$TUNNEL_CONFIG.tmp" && mv "$TUNNEL_CONFIG.tmp" "$TUNNEL_CONFIG"
}

setup_tunnel() {
    local tunnel_name=$1
    local config=$(jq -r ".\"$tunnel_name\"" "$TUNNEL_CONFIG")
    
    if [[ "$config" == "null" ]]; then
        echo "Tunnel configuration not found!"
        return 1
    fi
    
    # Extract configuration
    local role=$(echo "$config" | jq -r '.role')
    local ip_version=$(echo "$config" | jq -r '.ip_version')
    local local_type=$(echo "$config" | jq -r '.local_type')
    local local_ip=$(echo "$config" | jq -r '.local_ip')
    local remote_ip=$(echo "$config" | jq -r '.remote_ip')
    local port=$(echo "$config" | jq -r '.port')
    local vni=$(echo "$config" | jq -r '.vni')
    local vxlan_ip=$(echo "$config" | jq -r '.vxlan_ip')
    local multi_tunnel=$(echo "$config" | jq -r '.multi_tunnel')
    local haproxy=$(echo "$config" | jq -r '.haproxy')
    
    # Detect interface
    local interface=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    local vxlan_if="vxlan${vni}"
    
    # Create setup script
    cat <<EOF > "/usr/local/bin/setup_${tunnel_name}.sh"
#!/bin/bash

# Setup VXLAN tunnel: $tunnel_name
VNI=$vni
VXLAN_IF="$vxlan_if"
LOCAL_IP="$local_ip"
REMOTE_IP="$remote_ip"
PORT=$port
VXLAN_IP="$vxlan_ip"
INTERFACE="$interface"
LOCAL_TYPE="$local_type"

# Create VXLAN interface
if [[ "\$LOCAL_TYPE" == "local" ]]; then
    # For local IPs, use different approach
    ip link add \$VXLAN_IF type vxlan id \$VNI local \$LOCAL_IP remote \$REMOTE_IP dev \$INTERFACE dstport \$PORT nolearning
else
    ip link add \$VXLAN_IF type vxlan id \$VNI local \$LOCAL_IP remote \$REMOTE_IP dev \$INTERFACE dstport \$PORT nolearning
fi

ip addr add \$VXLAN_IP dev \$VXLAN_IF
ip link set \$VXLAN_IF up

# Add firewall rules
iptables -I INPUT 1 -p udp --dport \$PORT -j ACCEPT
iptables -I INPUT 1 -s \$REMOTE_IP -j ACCEPT
iptables -I INPUT 1 -s \${VXLAN_IP%/*} -j ACCEPT

# Enable IP forwarding if multi-tunnel
if [[ "$multi_tunnel" == "y" ]]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

echo "[$(date)] StarTunnel $tunnel_name started successfully" >> "$LOG_FILE"
EOF
    
    chmod +x "/usr/local/bin/setup_${tunnel_name}.sh"
    
    # Create systemd service
    cat <<EOF > "/etc/systemd/system/${SERVICE_PREFIX}-${tunnel_name}.service"
[Unit]
Description=StarTunnel - $tunnel_name
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/setup_${tunnel_name}.sh
ExecStop=/usr/local/bin/cleanup_${tunnel_name}.sh

[Install]
WantedBy=multi-user.target
EOF
    
    # Create cleanup script
    cat <<EOF > "/usr/local/bin/cleanup_${tunnel_name}.sh"
#!/bin/bash
ip link del vxlan${vni} 2>/dev/null || true
echo "[$(date)] StarTunnel $tunnel_name stopped" >> "$LOG_FILE"
EOF
    
    chmod +x "/usr/local/bin/cleanup_${tunnel_name}.sh"
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable "${SERVICE_PREFIX}-${tunnel_name}.service"
    systemctl start "${SERVICE_PREFIX}-${tunnel_name}.service"
    
    # Configure HAProxy if requested
    if [[ "$haproxy" == "y" ]]; then
        configure_tunnel_haproxy "$tunnel_name"
    fi
    
    log_message "StarTunnel $tunnel_name setup completed"
}

manage_tunnels() {
    while true; do
        show_header
        echo -e "|${YELLOW}StarTunnel Management${NC}"
        echo "+-----------------------------------------------------------------------------+"
        
        if [[ ! -f "$TUNNEL_CONFIG" ]] || [[ "$(jq 'keys | length' "$TUNNEL_CONFIG" 2>/dev/null)" == "0" ]]; then
            echo -e "${RED}No tunnels found!${NC}"
            read -p "Press Enter to return..."
            return
        fi
        
        echo -e "Active StarTunnels:"
        echo "+-----------------------------------------------------------------------------+"
        
        # List tunnels
        local counter=1
        jq -r 'keys[]' "$TUNNEL_CONFIG" 2>/dev/null | while read tunnel; do
            local status=$(check_tunnel_status "$tunnel")
            local config=$(jq -r ".\"$tunnel\"" "$TUNNEL_CONFIG")
            local role=$(echo "$config" | jq -r '.role')
            local vxlan_ip=$(echo "$config" | jq -r '.vxlan_ip')
            local local_type=$(echo "$config" | jq -r '.local_type')
            
            if [[ "$status" == "Active" ]]; then
                echo -e "$counter) ${GREEN}$tunnel${NC} [$role/$local_type] - $vxlan_ip (${GREEN}$status${NC})"
            else
                echo -e "$counter) ${RED}$tunnel${NC} [$role/$local_type] - $vxlan_ip (${RED}$status${NC})"
            fi
            ((counter++))
        done
        
        echo "+-----------------------------------------------------------------------------+"
        echo -e "1${GREEN}►${NC} Start/Stop Tunnel"
        echo -e "2${BLUE}►${NC} Delete Tunnel"
        echo -e "3${CYAN}►${NC} View Tunnel Details"
        echo -e "4${YELLOW}►${NC} Back"
        echo "+-----------------------------------------------------------------------------+"
        
        read -p "Enter choice: " manage_choice
        
        case $manage_choice in
            1) toggle_tunnel ;;
            2) delete_tunnel ;;
            3) view_tunnel_details ;;
            4) return ;;
            *) echo "Invalid choice!" ;;
        esac
    done
}

toggle_tunnel() {
    echo "Available tunnels:"
    jq -r 'keys[]' "$TUNNEL_CONFIG" 2>/dev/null | nl
    read -p "Enter tunnel name: " tunnel_name
    
    if ! jq -e ".\"$tunnel_name\"" "$TUNNEL_CONFIG" >/dev/null 2>&1; then
        echo -e "${RED}Tunnel not found!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    local status=$(check_tunnel_status "$tunnel_name")
    
    if [[ "$status" == "Active" ]]; then
        systemctl stop "${SERVICE_PREFIX}-${tunnel_name}.service"
        echo -e "${YELLOW}StarTunnel '$tunnel_name' stopped.${NC}"
    else
        systemctl start "${SERVICE_PREFIX}-${tunnel_name}.service"
        echo -e "${GREEN}StarTunnel '$tunnel_name' started.${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

delete_tunnel() {
    echo "Available tunnels:"
    jq -r 'keys[]' "$TUNNEL_CONFIG" 2>/dev/null | nl
    read -p "Enter tunnel name to delete: " tunnel_name
    
    if ! jq -e ".\"$tunnel_name\"" "$TUNNEL_CONFIG" >/dev/null 2>&1; then
        echo -e "${RED}Tunnel not found!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    read -p "Are you sure you want to delete tunnel '$tunnel_name'? (y/N): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        # Stop and disable service
        systemctl stop "${SERVICE_PREFIX}-${tunnel_name}.service" 2>/dev/null
        systemctl disable "${SERVICE_PREFIX}-${tunnel_name}.service" 2>/dev/null
        
        # Remove files
        rm -f "/etc/systemd/system/${SERVICE_PREFIX}-${tunnel_name}.service"
        rm -f "/usr/local/bin/setup_${tunnel_name}.sh"
        rm -f "/usr/local/bin/cleanup_${tunnel_name}.sh"
        
        # Remove from configuration
        jq "del(.\"$tunnel_name\")" "$TUNNEL_CONFIG" > "$TUNNEL_CONFIG.tmp" && mv "$TUNNEL_CONFIG.tmp" "$TUNNEL_CONFIG"
        
        systemctl daemon-reload
        
        echo -e "${GREEN}StarTunnel '$tunnel_name' deleted successfully!${NC}"
        log_message "StarTunnel $tunnel_name deleted"
    else
        echo "Operation cancelled."
    fi
    
    read -p "Press Enter to continue..."
}

view_tunnel_details() {
    echo "Available tunnels:"
    jq -r 'keys[]' "$TUNNEL_CONFIG" 2>/dev/null | nl
    read -p "Enter tunnel name: " tunnel_name
    
    if ! jq -e ".\"$tunnel_name\"" "$TUNNEL_CONFIG" >/dev/null 2>&1; then
        echo -e "${RED}Tunnel not found!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    local config=$(jq -r ".\"$tunnel_name\"" "$TUNNEL_CONFIG")
    local status=$(check_tunnel_status "$tunnel_name")
    
    echo -e "\n${CYAN}StarTunnel Details: $tunnel_name${NC}"
    echo "===================================="
    echo "Role: $(echo "$config" | jq -r '.role')"
    echo "IP Version: $(echo "$config" | jq -r '.ip_version')"
    echo "Local Type: $(echo "$config" | jq -r '.local_type')"
    echo "Local IP: $(echo "$config" | jq -r '.local_ip')"
    echo "Remote IP: $(echo "$config" | jq -r '.remote_ip')"
    echo "Port: $(echo "$config" | jq -r '.port')"
    echo "VNI: $(echo "$config" | jq -r '.vni')"
    echo "VXLAN IP: $(echo "$config" | jq -r '.vxlan_ip')"
    echo "Multi-tunnel: $(echo "$config" | jq -r '.multi_tunnel')"
    echo "HAProxy: $(echo "$config" | jq -r '.haproxy')"
    echo "Status: $status"
    echo "Created: $(echo "$config" | jq -r '.created')"
    
    read -p "Press Enter to continue..."
}

monitor_tunnels() {
    while true; do
        show_header
        echo -e "|${YELLOW}StarTunnel Monitoring${NC}"
        echo "+-----------------------------------------------------------------------------+"
        
        if [[ ! -f "$TUNNEL_CONFIG" ]] || [[ "$(jq 'keys | length' "$TUNNEL_CONFIG" 2>/dev/null)" == "0" ]]; then
            echo -e "${RED}No tunnels found!${NC}"
            read -p "Press Enter to return..."
            return
        fi
        
        # Show tunnel statistics
        echo -e "${CYAN}StarTunnel Status Overview:${NC}"
        echo "+-----------------------------------------------------------------------------+"
        printf "%-15s %-10s %-15s %-10s %-10s %-10s\n" "NAME" "STATUS" "VXLAN_IP" "PORT" "VNI" "TYPE"
        echo "+-----------------------------------------------------------------------------+"
        
        jq -r 'keys[]' "$TUNNEL_CONFIG" 2>/dev/null | while read tunnel; do
            local status=$(check_tunnel_status "$tunnel")
            local config=$(jq -r ".\"$tunnel\"" "$TUNNEL_CONFIG")
            local vxlan_ip=$(echo "$config" | jq -r '.vxlan_ip' | cut -d'/' -f1)
            local port=$(echo "$config" | jq -r '.port')
            local vni=$(echo "$config" | jq -r '.vni')
            local local_type=$(echo "$config" | jq -r '.local_type')
            
            if [[ "$status" == "Active" ]]; then
                printf "%-15s ${GREEN}%-10s${NC} %-15s %-10s %-10s %-10s\n" "$tunnel" "$status" "$vxlan_ip" "$port" "$vni" "$local_type"
            else
                printf "%-15s ${RED}%-10s${NC} %-15s %-10s %-10s %-10s\n" "$tunnel" "$status" "$vxlan_ip" "$port" "$vni" "$local_type"
            fi
        done
        
        echo "+-----------------------------------------------------------------------------+"
        echo -e "1${GREEN}►${NC} Real-time Monitoring"
        echo -e "2${BLUE}►${NC} View Logs"
        echo -e "3${CYAN}►${NC} Network Statistics"
        echo -e "4${YELLOW}►${NC} Back"
        echo "+-----------------------------------------------------------------------------+"
        
        read -p "Enter choice: " monitor_choice
        
        case $monitor_choice in
            1) realtime_monitoring ;;
            2) view_logs ;;
            3) network_stats ;;
            4) return ;;
            *) echo "Invalid choice!" ;;
        esac
    done
}

realtime_monitoring() {
    echo -e "${CYAN}Real-time Monitoring (Press Ctrl+C to stop)${NC}"
    echo "============================================="
    
    while true; do
        clear
        echo -e "${CYAN}StarTunnel - Real-time Status${NC}"
        echo "$(date)"
        echo "============================================="
        
        jq -r 'keys[]' "$TUNNEL_CONFIG" 2>/dev/null | while read tunnel; do
            local status=$(check_tunnel_status "$tunnel")
            local config=$(jq -r ".\"$tunnel\"" "$TUNNEL_CONFIG")
            local vxlan_ip=$(echo "$config" | jq -r '.vxlan_ip' | cut -d'/' -f1)
            local vni=$(echo "$config" | jq -r '.vni')
            
            echo -e "Tunnel: ${YELLOW}$tunnel${NC}"
            echo -e "Status: $([[ "$status" == "Active" ]] && echo -e "${GREEN}$status${NC}" || echo -e "${RED}$status${NC}")"
            echo -e "VXLAN IP: $vxlan_ip"
            
            if [[ "$status" == "Active" ]]; then
                # Check if interface exists and get stats
                if ip link show "vxlan${vni}" >/dev/null 2>&1; then
                    local stats=$(ip -s link show "vxlan${vni}" | grep -A2 "RX:")
                    echo -e "Interface: ${GREEN}UP${NC}"
                    echo "$stats"
                else
                    echo -e "Interface: ${RED}DOWN${NC}"
                fi
            fi
            echo "---------------------------------------------"
        done
        
        sleep 3
    done
}

view_logs() {
    echo -e "${CYAN}StarTunnel Logs${NC}"
    echo "================"
    
    if [[ -f "$LOG_FILE" ]]; then
        echo "Recent log entries:"
        tail -n 50 "$LOG_FILE"
    else
        echo "No log file found."
    fi
    
    read -p "Press Enter to continue..."
}

network_stats() {
    echo -e "${CYAN}Network Statistics${NC}"
    echo "=================="
    
    # Show VXLAN interfaces
    echo -e "\n${YELLOW}VXLAN Interfaces:${NC}"
    ip -d link show type vxlan 2>/dev/null | grep -E "vxlan|inet" || echo "No VXLAN interfaces found"
    
    # Show routing table
    echo -e "\n${YELLOW}Routing Table:${NC}"
    ip route | grep -E "30\.0\.0\." || echo "No tunnel routes found"
    
    # Show iptables rules
    echo -e "\n${YELLOW}Firewall Rules:${NC}"
    iptables -L INPUT | grep -E "ACCEPT|udp|30\.0\.0\." || echo "No specific tunnel rules found"
    
    read -p "Press Enter to continue..."
}

uninstall_all_tunnels() {
    echo -e "${RED}WARNING: This will remove all StarTunnels and configurations!${NC}"
    read -p "Are you sure? Type 'YES' to confirm: " confirm
    
    if [[ "$confirm" == "YES" ]]; then
        echo "Removing all StarTunnels..."
        
        # Stop and remove all services
        if [[ -f "$TUNNEL_CONFIG" ]]; then
            jq -r 'keys[]' "$TUNNEL_CONFIG" 2>/dev/null | while read tunnel; do
                systemctl stop "${SERVICE_PREFIX}-${tunnel}.service" 2>/dev/null
                systemctl disable "${SERVICE_PREFIX}-${tunnel}.service" 2>/dev/null
                rm -f "/etc/systemd/system/${SERVICE_PREFIX}-${tunnel}.service"
                rm -f "/usr/local/bin/setup_${tunnel}.sh"
                rm -f "/usr/local/bin/cleanup_${tunnel}.sh"
            done
        fi
        
        # Remove VXLAN interfaces
        for vxlan in $(ip link show type vxlan | grep -o 'vxlan[0-9]\+'); do
            ip link del "$vxlan" 2>/dev/null
        done
        
        # Remove configuration
        rm -rf "$CONFIG_DIR"
        rm -f "$LOG_FILE"
        
        systemctl daemon-reload
        
        echo -e "${GREEN}All StarTunnels removed successfully!${NC}"
    else
        echo "Operation cancelled."
    fi
    
    read -p "Press Enter to continue..."
}

configure_tunnel_haproxy() {
    local tunnel_name=$1
    
    echo "Configuring HAProxy for StarTunnel: $tunnel_name"
    read -p "Enter ports for forwarding (comma-separated): " ports
    
    local config=$(jq -r ".\"$tunnel_name\"" "$TUNNEL_CONFIG")
    local vxlan_ip=$(echo "$config" | jq -r '.vxlan_ip' | cut -d'/' -f1)
    
    # Use the integrated HAProxy configuration
    configure_haproxy_ports "$ports" "$vxlan_ip"
}

# ============================================================================
# HAPROXY MANAGEMENT SECTION
# ============================================================================

haproxy_menu() {
    while true; do
        show_header
        echo "+----------------------------------------------------------------------------+"
        echo "| ##  ##    ###    ######   ######    #####   ###  ##  ###  ###              |"
        echo "| ##  ##   ## ##    ##  ##   ##  ##  ### ###  ###  ##   ##  ##               |"
        echo "| ##  ##  ##   ##   ##  ##   ##  ##  ##   ##   #####     ####                |"
        echo "| ######  ##   ##   #####    #####   ##   ##    ###       ##                 |"
        echo "| ##  ##  #######   ##       ## ##   ##   ##   #####      ##  TG CHANNEL     |"
        echo "| ##  ##  ##   ##   ##       ## ##   ### ###  ##  ###     ## @ServerStar_ir  |"
        echo "| ##  ##  ##   ##  ####     #### ##   #####   ##  ###    ####                |"
        echo "+----------------------------------------------------------------------------+"
        echo "|Select an option:"
        echo "|1) Install HAProxy"
        echo "|2) Add IPs and Ports to Forward"
        echo "|3) Clear Configurations"
        echo "|4) Remove HAProxy Completely"
        echo "|5) HAProxy Status"
        echo "|9) Back to Main Menu"
        echo "+----------------------------------------------------------------------------+"

        read -p "Select a Number : " choice

        case $choice in
            1) install_haproxy ;;
            2) add_ip_ports ;;
            3) clear_configs ;;
            4) remove_haproxy ;;
            5) haproxy_status ;;
            9) return ;;
            *) echo "Invalid option. Please try again." ;;
        esac
    done
}

check_haproxy_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        return 1
    fi
    return 0
}

install_haproxy() {
    if ! check_haproxy_root; then return; fi
    
    echo "Installing HAProxy..."
    sudo apt-get update >/dev/null 2>&1
    sudo apt-get install -y haproxy >/dev/null 2>&1
    echo "HAProxy installed."
    default_haproxy_config
    
    read -p "Press Enter to continue..."
}

default_haproxy_config() {
    local config_file="/etc/haproxy/haproxy.cfg"
    
    cat <<EOL > $config_file
global
    # log /dev/log    local0
    # log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    # log     global
    mode    tcp
    # option  tcplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

# Statistics page
listen stats
    bind *:8080
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
EOL
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
    balance roundrobin
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

add_ip_ports() {
    if ! check_haproxy_root; then return; fi
    
    read -p "Enter the IPs to forward to (use comma , to separate multiple IPs): " user_ips
    IFS=',' read -r -a ips_array <<< "$user_ips"
    read -p "Enter the ports (use comma , to separate): " user_ports
    IFS=',' read -r -a ports_array <<< "$user_ports"
    generate_haproxy_config "${ports_array[*]}" "${ips_array[*]}"

    if haproxy -c -f /etc/haproxy/haproxy.cfg; then
        echo "Restarting HAProxy service..."
        service haproxy restart
        echo "HAProxy configuration updated and service restarted."
        echo -e "${CYAN}Statistics available at: http://$(hostname -I | awk '{print $1}'):8080/stats${NC}"
    else
        echo "HAProxy configuration is invalid. Please check the configuration file."
    fi
    
    read -p "Press Enter to continue..."
}

configure_haproxy_ports() {
    local ports=$1
    local target_ip=$2
    local config_file="/etc/haproxy/haproxy.cfg"
    local backup_file="/etc/haproxy/haproxy.cfg.bak"

    # Create backup
    cp $config_file $backup_file

    # Add configurations
    IFS=',' read -ra port_array <<< "$ports"
    for port in "${port_array[@]}"; do
        port=$(echo "$port" | tr -d ' ')
        cat <<EOL >> $config_file

frontend frontend_$port
    bind *:$port
    default_backend backend_$port

backend backend_$port
    balance roundrobin
    server star_tunnel $target_ip:$port check
EOL
    done

    # Validate and restart HAProxy
    if haproxy -c -f $config_file; then
        systemctl restart haproxy
        systemctl enable haproxy
        echo -e "${GREEN}HAProxy configured successfully for StarTunnel!${NC}"
        echo -e "${CYAN}Statistics available at: http://$(hostname -I | awk '{print $1}'):8080/stats${NC}"
    else
        echo -e "${RED}HAProxy configuration failed!${NC}"
        cp $backup_file $config_file
    fi
}

clear_configs() {
    if ! check_haproxy_root; then return; fi
    
    local config_file="/etc/haproxy/haproxy.cfg"
    local backup_file="/etc/haproxy/haproxy.cfg.bak"
    
    echo "Creating a backup of the HAProxy configuration..."
    cp $config_file $backup_file

    if [ $? -ne 0 ]; then
        echo "Failed to create a backup. Aborting."
        read -p "Press Enter to continue..."
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

remove_haproxy() {
    if ! check_haproxy_root; then return; fi
    
    echo "Removing HAProxy..."
    sudo apt-get remove --purge -y haproxy >/dev/null 2>&1
    sudo apt-get autoremove -y >/dev/null 2>&1
    echo "HAProxy removed."
    
    read -p "Press Enter to continue..."
}

haproxy_status() {
    echo -e "${CYAN}HAProxy Status${NC}"
    echo "=============="
    
    if systemctl is-active --quiet haproxy; then
        echo -e "Service Status: ${GREEN}Active${NC}"
        echo -e "Statistics: http://$(hostname -I | awk '{print $1}'):8080/stats"
        
        # Show current configuration summary
        echo -e "\n${YELLOW}Current Configuration:${NC}"
        if [[ -f "/etc/haproxy/haproxy.cfg" ]]; then
            grep -E "frontend|backend|server" /etc/haproxy/haproxy.cfg | head -20
        fi
    else
        echo -e "Service Status: ${RED}Inactive${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

# ============================================================================
# ADVANCED SETTINGS SECTION
# ============================================================================

advanced_settings() {
    while true; do
        show_header
        echo -e "|${YELLOW}Advanced Settings${NC}"
        echo "+-----------------------------------------------------------------------------+"
        echo -e "1${GREEN}►${NC} Backup Configuration"
        echo -e "2${BLUE}►${NC} Restore Configuration"
        echo -e "3${CYAN}►${NC} System Optimization"
        echo -e "4${MAGENTA}►${NC} Auto Update Settings"
        echo -e "5${YELLOW}►${NC} Back to Main Menu"
        echo "+-----------------------------------------------------------------------------+"
        
        read -p "Enter choice: " advanced_choice
        
        case $advanced_choice in
            1) backup_config ;;
            2) restore_config ;;
            3) system_optimization ;;
            4) auto_update_settings ;;
            5) return ;;
            *) echo "Invalid choice!" ;;
        esac
    done
}

backup_config() {
    local backup_file="/root/star-tunnel-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    echo "Creating backup..."
    tar -czf "$backup_file" -C / \
        etc/star-tunnel \
        usr/local/bin/setup_*.sh \
        usr/local/bin/cleanup_*.sh \
        etc/systemd/system/star-tunnel-*.service \
        etc/haproxy/haproxy.cfg \
        var/log/star-tunnel.log 2>/dev/null
    
    echo -e "${GREEN}Backup created: $backup_file${NC}"
    read -p "Press Enter to continue..."
}

restore_config() {
    echo "Available backup files:"
    ls -la /root/star-tunnel-backup-*.tar.gz 2>/dev/null || echo "No backup files found"
    
    read -p "Enter backup file path: " backup_file
    
    if [[ -f "$backup_file" ]]; then
        echo "Restoring configuration..."
        tar -xzf "$backup_file" -C /
        systemctl daemon-reload
        
        # Restart services
        if [[ -f "$TUNNEL_CONFIG" ]]; then
            jq -r 'keys[]' "$TUNNEL_CONFIG" 2>/dev/null | while read tunnel; do
                systemctl restart "${SERVICE_PREFIX}-${tunnel}.service"
            done
        fi
        
        echo -e "${GREEN}Configuration restored successfully!${NC}"
    else
        echo -e "${RED}Backup file not found!${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

system_optimization() {
    echo -e "${CYAN}System Optimization${NC}"
    echo "==================="
    
    echo "1) Network Parameters"
    echo "2) Firewall Configuration"
    echo "3) Performance Tuning"
    echo "4) All Optimizations"
    
    read -p "Enter choice: " opt_choice
    
    case $opt_choice in
        1|4) optimize_network ;;
    esac
    
    if [[ "$opt_choice" == "2" || "$opt_choice" == "4" ]]; then
        echo "Configuring firewall..."
        # Add basic firewall rules
        iptables -I INPUT -i lo -j ACCEPT
        iptables -I INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        echo -e "${GREEN}Firewall configured!${NC}"
    fi
    
    if [[ "$opt_choice" == "3" || "$opt_choice" == "4" ]]; then
        echo "Applying performance tuning..."
        # Performance optimizations
        echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
        echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
        sysctl -p
        echo -e "${GREEN}Performance tuning applied!${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

optimize_network() {
    echo "Optimizing network parameters..."
    cat <<EOF >> /etc/sysctl.conf
# StarTunnel Optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p
    echo -e "${GREEN}Network parameters optimized!${NC}"
}

auto_update_settings() {
    echo -e "${CYAN}Auto Update Settings${NC}"
    echo "===================="
    
    echo "1) Check for Updates"
    echo "2) Enable Auto Update"
    echo "3) Disable Auto Update"
    echo "4) Manual Update"
    
    read -p "Enter choice: " update_choice
    
    case $update_choice in
        1) check_updates ;;
        2) enable_auto_update ;;
        3) disable_auto_update ;;
        4) manual_update ;;
    esac
    
    read -p "Press Enter to continue..."
}

check_updates() {
    echo "Checking for updates..."
    
    # Get current version
    local current_version="$VERSION"
    
    # Check remote version (this would need to be implemented)
    echo "Current version: $current_version"
    echo "Checking remote version..."
    
    # Placeholder for update checking logic
    echo -e "${GREEN}You are running the latest version.${NC}"
}

enable_auto_update() {
    echo "Enabling auto updates..."
    
    # Create auto-update cron job
    cat <<EOF > /etc/cron.daily/star-tunnel-update
#!/bin/bash
curl -fsSL "$UPDATE_URL" | bash --install
EOF
    
    chmod +x /etc/cron.daily/star-tunnel-update
    echo -e "${GREEN}Auto updates enabled!${NC}"
}

disable_auto_update() {
    echo "Disabling auto updates..."
    rm -f /etc/cron.daily/star-tunnel-update
    echo -e "${YELLOW}Auto updates disabled!${NC}"
}

manual_update() {
    echo "Updating StarTunnel manually..."
    
    if curl -fsSL "$UPDATE_URL" -o "/tmp/star-tunnel-update.sh"; then
        chmod +x "/tmp/star-tunnel-update.sh"
        
        read -p "Update downloaded. Install now? (y/N): " confirm
        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
            bash "/tmp/star-tunnel-update.sh" --install
        fi
        
        rm -f "/tmp/star-tunnel-update.sh"
    else
        echo -e "${RED}Failed to download update!${NC}"
    fi
}

# ============================================================================
# BBR INSTALLATION
# ============================================================================

install_bbr() {
    echo "Installing BBR..."
    
    # Check if BBR is already enabled
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}BBR is already enabled!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Enabling BBR..."
    echo 'net.core.default_qdisc=fq' >> /etc/sysctl.conf
    echo 'net.ipv4.tcp_congestion_control=bbr' >> /etc/sysctl.conf
    sysctl -p
    
    echo -e "${GREEN}BBR enabled successfully!${NC}"
    echo "Verifying BBR status..."
    sysctl net.ipv4.tcp_congestion_control
    
    read -p "Press Enter to continue..."
}

# ============================================================================
# SYSTEM UPDATE
# ============================================================================

system_update() {
    echo -e "${CYAN}System Update${NC}"
    echo "=============="
    
    echo "1) Update StarTunnel"
    echo "2) Update System Packages"
    echo "3) Full System Update"
    
    read -p "Enter choice: " update_choice
    
    case $update_choice in
        1) manual_update ;;
        2) 
            echo "Updating system packages..."
            apt update && apt upgrade -y
            echo -e "${GREEN}System packages updated!${NC}"
            ;;
        3)
            echo "Performing full system update..."
            apt update && apt upgrade -y
            manual_update
            echo -e "${GREEN}Full system update completed!${NC}"
            ;;
    esac
    
    read -p "Press Enter to continue..."
}

# ============================================================================
# MAIN PROGRAM
# ============================================================================

main() {
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
    
    # Create initial log entry
    log_message "StarTunnel v${VERSION} started"
    
    # Main menu loop
    while true; do
        main_menu
        read -p "Enter your choice [1-7]: " choice
        
        case $choice in
            1) startunnel_menu ;;
            2) haproxy_menu ;;
            3) monitor_tunnels ;;
            4) advanced_settings ;;
            5) install_bbr ;;
            6) system_update ;;
            7) 
                echo -e "${GREEN}Thank you for using StarTunnel v${VERSION}!${NC}"
                echo -e "${CYAN}Telegram: @ServerStar_ir${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 1
                ;;
        esac
    done
}

# Run main program or handle installation
if [[ "$1" == "--install" ]]; then
    # Installation mode
    exit 0
else
    # Normal execution
    main "$@"
fi
