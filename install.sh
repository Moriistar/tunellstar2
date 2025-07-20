 #!/bin/bash

# ==================== StarTunnel Panel ====================
# سازنده: MoriiStar
# کانال: @ServerStar_ir
# نسخه: 1.0.2 Beta
# ==================== StarTunnel Panel ====================

# تنظیم رنگ‌ها
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
TURQUOISE='\033[38;5;45m'
NC='\033[0m'

# بررسی دسترسی روت
[[ $EUID -ne 0 ]] && echo -e "${RED}خطا: ${NC}لطفاً با دسترسی روت اجرا کنید\n" && exit 1

# نصب وابستگی‌های مورد نیاز
install_dependencies() {
    echo "[*] به‌روزرسانی لیست بسته‌ها..."
    apt update -y
    
    echo "[*] نصب بسته‌های مورد نیاز..."
    apt install -y iproute2 net-tools grep gawk sudo iputils-ping jq curl haproxy iptables screen netplan.io obfs4proxy
    
    echo -e "${GREEN}[✓] همه وابستگی‌ها نصب شدند${NC}"
}

# بررسی وضعیت تونل
check_tunnel_status() {
    if ip link show | grep -q 'vxlan\|tunnel0858' || [ -f "/etc/netplan/mramini-1.yaml" ]; then
        echo -e "${GREEN}فعال${NC}"
    else
        echo -e "${RED}غیرفعال${NC}"
    fi
}

# منوی اصلی StarTunnel
StarTunnel_menu() {
    clear
    SERVER_IP=$(hostname -I | awk '{print $1}')
    SERVER_COUNTRY=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.country // "نامشخص"' 2>/dev/null)
    SERVER_ISP=$(curl -sS "http://ip-api.com/json/$SERVER_IP" | jq -r '.isp // "نامشخص"' 2>/dev/null)
    TUNNEL_STATUS=$(check_tunnel_status)

    echo "+-----------------------------------------------------------------------------+"
    echo -e "${TURQUOISE}    ╔═══╦════╦═══╦═══╗        ╔════╦╗─╔╦═╗─╔╦═══╦╗──╔╗${NC}"
    echo -e "${TURQUOISE}    ║╔═╗║╔╗╔╗║╔═╗║╔═╗║        ║╔╗╔╗║║─║║║╚╗║║╔══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ║╚══╬╝║║╚╣║─║║╚═╝║        ╚╝║║╚╣║─║║╔╗╚╝║╚══╣║──║║${NC}"
    echo -e "${TURQUOISE}    ╚══╗║─║║─║╚═╝║╔╗╔╝        ──║║─║║─║║║╚╗║║╔══╣║─╔╣║─╔╗${NC}"
    echo -e "${TURQUOISE}    ║╚═╝║─║║─║╔═╗║║║╚╗        ──║║─║╚═╝║║─║║║╚══╣╚═╝║╚═╝║${NC}"
    echo -e "${TURQUOISE}    ╚═══╝─╚╝─╚╝─╚╩╝╚═╝        ──╚╝─╚═══╩╝─╚═╩═══╩═══╩═══╝${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "| کانال تلگرام: ${RED}@ServerStar_ir ${NC}| نسخه: ${GREEN} 1.0.2 Beta ${NC}"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${GREEN}کشور سرور        |${NC} $SERVER_COUNTRY"
    echo -e "|${GREEN}آی‌پی سرور         |${NC} $SERVER_IP"
    echo -e "|${GREEN}ارائه‌دهنده        |${NC} $SERVER_ISP"
    echo -e "|${GREEN}وضعیت تونل        |${NC} $TUNNEL_STATUS"
    echo "+-----------------------------------------------------------------------------+"
    echo -e "|${YELLOW}یک گزینه انتخاب کنید:${NC}"
    echo "+-----------------------------------------------------------------------------+"
}

# نصب BBR
install_bbr() {
    echo "اجرای اسکریپت BBR..."
    curl -fsSL https://raw.githubusercontent.com/MrAminiDev/NetOptix/main/scripts/bbr.sh -o /tmp/bbr.sh
    bash /tmp/bbr.sh
    rm /tmp/bbr.sh
    echo -e "${GREEN}BBR با موفقیت نصب شد${NC}"
}

# ===== ماژول VXLAN =====

setup_vxlan_tunnel() {
    echo "=== تنظیم تونل VXLAN ==="
    
    VNI=88
    VXLAN_IF="vxlan${VNI}"
    
    echo "نقش سرور را انتخاب کنید:"
    echo "1- ایران"
    echo "2- خارج"
    read -p "انتخاب کنید (1/2): " role_choice
    
    if [[ "$role_choice" == "1" ]]; then
        read -p "آی‌پی ایران: " IRAN_IP
        read -p "آی‌پی خارج: " KHAREJ_IP
        
        while true; do
            read -p "پورت تونل (1-64435): " DSTPORT
            if [[ $DSTPORT =~ ^[0-9]+$ ]] && (( DSTPORT >= 1 && DSTPORT <= 64435 )); then
                break
            else
                echo "پورت نامعتبر. دوباره تلاش کنید."
            fi
        done
        
        read -p "آیا port forwarding خودکار انجام شود؟ [1-بله, 2-خیر]: " haproxy_choice
        
        VXLAN_IP="30.0.0.1/24"
        REMOTE_IP=$KHAREJ_IP
        
    elif [[ "$role_choice" == "2" ]]; then
        read -p "آی‌پی ایران: " IRAN_IP
        read -p "آی‌پی خارج: " KHAREJ_IP
        
        while true; do
            read -p "پورت تونل (1-64435): " DSTPORT
            if [[ $DSTPORT =~ ^[0-9]+$ ]] && (( DSTPORT >= 1 && DSTPORT <= 64435 )); then
                break
            else
                echo "پورت نامعتبر. دوباره تلاش کنید."
            fi
        done
        
        VXLAN_IP="30.0.0.2/24"
        REMOTE_IP=$IRAN_IP
        
    else
        echo "انتخاب نامعتبر."
        return
    fi
    
    # تشخیص interface اصلی
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n1)
    echo "Interface اصلی: $INTERFACE"
    
    # ایجاد VXLAN interface
    echo "[+] ایجاد interface VXLAN..."
    ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
    
    echo "[+] تخصیص IP $VXLAN_IP به $VXLAN_IF"
    ip addr add $VXLAN_IP dev $VXLAN_IF
    ip link set $VXLAN_IF up
    
    # تنظیم iptables
    echo "[+] تنظیم قوانین iptables"
    iptables -I INPUT 1 -p udp --dport $DSTPORT -j ACCEPT
    iptables -I INPUT 1 -s $REMOTE_IP -j ACCEPT
    iptables -I INPUT 1 -s ${VXLAN_IP%/*} -j ACCEPT
    
    # ایجاد سرویس systemd
    cat <<EOF > /usr/local/bin/vxlan_bridge.sh
#!/bin/bash
ip link add $VXLAN_IF type vxlan id $VNI local $(hostname -I | awk '{print $1}') remote $REMOTE_IP dev $INTERFACE dstport $DSTPORT nolearning
ip addr add $VXLAN_IP dev $VXLAN_IF
ip link set $VXLAN_IF up
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
    
    echo -e "${GREEN}[✓] تونل VXLAN با موفقیت تنظیم شد${NC}"
    echo -e "آی‌پی شما: ${VXLAN_IP%/*}"
    
    # نصب HAProxy در صورت درخواست
    if [[ "$haproxy_choice" == "1" ]]; then
        setup_haproxy
    fi
}

# ===== ماژول IPv6 Tunnel =====

configure_obfs4() {
    local obfs4_dir="/etc/obfs4"
    mkdir -p "$obfs4_dir"
    
    if [ ! -f "$obfs4_dir/obfs4_cert" ] || [ ! -f "$obfs4_dir/obfs4_key" ]; then
        echo -e "${YELLOW}تولید گواهی obfs4...${NC}"
        openssl genpkey -algorithm RSA -out "$obfs4_dir/obfs4_key" -pkeyopt rsa_keygen_bits:2048
        openssl req -new -x509 -key "$obfs4_dir/obfs4_key" -out "$obfs4_dir/obfs4_cert" -days 365 -subj "/CN=obfs4"
        echo -e "${GREEN}گواهی obfs4 تولید شد${NC}"
    fi
}

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

setup_ipv6_tunnel() {
    echo "=== تنظیم تونل IPv6 ==="
    echo "1- ایران"
    echo "2- خارج"
    echo "3- ایران (IPv4 محلی)"
    echo "4- خارج (IPv4 محلی)"
    read -p "انتخاب کنید: " setup_type
    
    case $setup_type in
        1|3)
            read -p "تعداد سرور: " server_count
            last_number=$(find_last_tunnel_number)
            next_number=$((last_number + 1))
            
            echo "1- وارد کردن IP دستی"
            echo "2- تنظیم IP خودکار"
            read -p "انتخاب کنید: " ip_choice
            
            for ((i=next_number;i<next_number+server_count;i++)); do
                if [ "$setup_type" == "1" ]; then
                    setup_iran_ipv6 $i $ip_choice
                else
                    setup_iran_ipv4 $i $ip_choice
                fi
            done
            ;;
        2|4)
            echo "1- وارد کردن IP دستی"
            echo "2- تنظیم IP خودکار"
            read -p "انتخاب کنید: " ip_choice
            
            if [ "$ip_choice" = "1" ]; then
                read -p "تعداد سرور: " server_count
                last_number=$(find_last_tunnel_number)
                next_number=$((last_number + 1))
                for ((i=next_number;i<next_number+server_count;i++)); do
                    if [ "$setup_type" == "2" ]; then
                        setup_kharej_ipv6 $i
                    else
                        setup_kharej_ipv4 $i
                    fi
                done
            else
                read -p "شماره سرور: " server_number
                if [ "$setup_type" == "2" ]; then
                    auto_ipv6="fd25:2895:dc$(printf "%02d" $server_number)::2"
                    setup_kharej_ipv6_auto $server_number "$auto_ipv6"
                else
                    auto_ipv4="10.0.$(printf "%d" $server_number).2"
                    setup_kharej_ipv4_auto $server_number "$auto_ipv4"
                fi
            fi
            ;;
    esac
}

setup_iran_ipv6() {
    local tunnel_num=$1
    local ip_choice=$2
    
    echo -e "${YELLOW}تنظیم سرور ایران $tunnel_num${NC}"
    read -p "آی‌پی ایران: " iran_ip
    read -p "آی‌پی خارج: " kharej_ip
    
    if [ "$ip_choice" == "1" ]; then
        read -p "IPv6 محلی: " ipv6_local
        local full_ipv6="$ipv6_local::1"
    else
        local auto_ipv6="fd25:2895:dc$(printf "%02d" $tunnel_num)::1"
        local full_ipv6="$auto_ipv6"
    fi
    
    cat <<EOL > /etc/netplan/mramini-$tunnel_num.yaml
network:
  version: 2
  tunnels:
    tunnel0858-$tunnel_num:
      mode: sit
      local: $iran_ip
      remote: $kharej_ip
      addresses:
        - $full_ipv6/64
EOL
    
    chmod 600 /etc/netplan/mramini-$tunnel_num.yaml
    netplan apply 2>/dev/null
    
    configure_obfs4
    
    # ایجاد اسکریپت اتصال
    cat <<EOL > /root/connectors-$tunnel_num.sh
#!/bin/bash
while true; do
    ping -c 1 ${full_ipv6%::1}::2 >/dev/null 2>&1
    sleep 30
done
EOL
    
    chmod +x /root/connectors-$tunnel_num.sh
    screen -dmS connectors_session_$tunnel_num bash -c "/root/connectors-$tunnel_num.sh"
    
    echo -e "${GREEN}سرور ایران $tunnel_num تنظیم شد${NC}"
    echo -e "IPv6 شما: $full_ipv6"
}

# ===== ماژول HAProxy =====

setup_haproxy() {
    echo "=== تنظیم HAProxy ==="
    
    # نصب HAProxy در صورت عدم وجود
    if ! command -v haproxy >/dev/null 2>&1; then
        echo "نصب HAProxy..."
        apt update && apt install -y haproxy
    fi
    
    local config_file="/etc/haproxy/haproxy.cfg"
    local backup_file="/etc/haproxy/haproxy.cfg.bak"
    
    # پشتیبان‌گیری از تنظیمات قبلی
    [ -f "$config_file" ] && cp "$config_file" "$backup_file"
    
    # ایجاد تنظیمات پایه
    cat <<EOL > "$config_file"
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

    read -p "پورت‌ها را وارد کنید (با کاما جدا کنید): " user_ports
    local local_ip=$(hostname -I | awk '{print $1}')
    
    IFS=',' read -ra ports <<< "$user_ports"
    
    for port in "${ports[@]}"; do
        cat <<EOL >> "$config_file"

frontend frontend_$port
    bind *:$port
    default_backend backend_$port
    option tcpka

backend backend_$port
    option tcpka
    server server1 $local_ip:$port check maxconn 2048
EOL
    done
    
    # بررسی تنظیمات و راه‌اندازی
    if haproxy -c -f "$config_file"; then
        systemctl restart haproxy
        systemctl enable haproxy
        echo -e "${GREEN}HAProxy با موفقیت تنظیم شد${NC}"
    else
        echo -e "${YELLOW}هشدار: تنظیمات HAProxy نامعتبر است${NC}"
    fi
}

manage_haproxy() {
    while true; do
        clear
        echo "+----------------------------------------------------------------------------+"
        echo "|                              مدیریت HAProxy                                |"
        echo "+----------------------------------------------------------------------------+"
        echo "|1) نصب HAProxy"
        echo "|2) افزودن IP و پورت برای فوروارد"
        echo "|3) پاک کردن تنظیمات"
        echo "|4) حذف کامل HAProxy"
        echo "|0) بازگشت"
        echo "+----------------------------------------------------------------------------+"
        
        read -p "انتخاب کنید: " choice
        
        case $choice in
            1)
                apt update && apt install -y haproxy
                echo -e "${GREEN}HAProxy نصب شد${NC}"
                ;;
            2)
                setup_haproxy
                ;;
            3)
                systemctl stop haproxy
                echo -e "${GREEN}تنظیمات پاک شد${NC}"
                ;;
            4)
                apt remove --purge -y haproxy
                apt autoremove -y
                echo -e "${GREEN}HAProxy حذف شد${NC}"
                ;;
            0)
                break
                ;;
            *)
                echo "گزینه نامعتبر"
                ;;
        esac
        read -p "Enter برای ادامه..."
    done
}

# حذف تونل‌ها
uninstall_tunnels() {
    echo "[!] حذف همه تونل‌ها..."
    
    # حذف VXLAN interfaces
    for i in $(ip -d link show | grep -o 'vxlan[0-9]\+'); do
        ip link del $i 2>/dev/null
    done
    
    # حذف IPv6 tunnels
    for iface in $(ip link show | grep 'tunnel0858' | awk -F': ' '{print $2}' | cut -d'@' -f1); do
        ip link set $iface down
        ip link delete $iface 2>/dev/null
    done
    
    # حذف فایل‌های تنظیمات
    rm -f /usr/local/bin/vxlan_bridge.sh /etc/ping_vxlan.sh
    rm -f /etc/netplan/mramini*.yaml
    rm -f /root/connectors-*.sh
    
    # حذف سرویس‌ها
    systemctl disable --now vxlan-tunnel.service 2>/dev/null
    rm -f /etc/systemd/system/vxlan-tunnel.service
    
    # پاک کردن screen sessions
    pkill screen
    
    systemctl daemon-reload
    netplan apply 2>/dev/null
    
    echo -e "${GREEN}[+] همه تونل‌ها حذف شدند${NC}"
}

# مدیریت cronjob
manage_cronjob() {
    while true; do
        clear
        echo "+-----------------------------+"
        echo "|      تنظیمات Cronjob        |"
        echo "+-----------------------------+"
        echo "1- نصب cronjob"
        echo "2- ویرایش cronjob"
        echo "3- حذف cronjob"
        echo "4- بازگشت"
        
        read -p "انتخاب کنید [1-4]: " cron_action
        case $cron_action in
            1)
                read -p "هر چند ساعت restart شود؟ (1-24): " cron_hours
                if [[ $cron_hours =~ ^[0-9]+$ ]] && (( cron_hours >= 1 && cron_hours <= 24 )); then
                    crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
                    echo "0 */$cron_hours * * * systemctl restart haproxy >/dev/null 2>&1" >> /tmp/cron_tmp
                    echo "0 */$cron_hours * * * systemctl restart vxlan-tunnel >/dev/null 2>&1" >> /tmp/cron_tmp
                    crontab /tmp/cron_tmp
                    rm /tmp/cron_tmp
                    echo -e "${GREEN}Cronjob تنظیم شد${NC}"
                fi
                ;;
            2|3)
                crontab -l 2>/dev/null | grep -v 'systemctl restart haproxy' | grep -v 'systemctl restart vxlan-tunnel' > /tmp/cron_tmp || true
                crontab /tmp/cron_tmp
                rm /tmp/cron_tmp
                echo -e "${GREEN}عملیات انجام شد${NC}"
                ;;
            4)
                break
                ;;
        esac
        read -p "Enter برای ادامه..."
    done
}

# منوی اصلی
main_menu() {
    while true; do
        StarTunnel_menu
        echo "1- تنظیم تونل VXLAN"
        echo "2- تنظیم تونل IPv6"
        echo "3- مدیریت HAProxy"
        echo "4- حذف تونل‌ها"
        echo "5- نصب BBR"
        echo "6- تنظیمات Cronjob"
        echo "0- خروج"
        echo "+-----------------------------------------------------------------------------+"
        
        read -p "انتخاب کنید [0-6]: " main_choice
        
        case $main_choice in
            0)
                echo -e "${GREEN}خروج...${NC}"
                exit 0
                ;;
            1)
                setup_vxlan_tunnel
                ;;
            2)
                setup_ipv6_tunnel
                ;;
            3)
                manage_haproxy
                ;;
            4)
                uninstall_tunnels
                ;;
            5)
                install_bbr
                ;;
            6)
                manage_cronjob
                ;;
            *)
                echo -e "${RED}گزینه نامعتبر${NC}"
                sleep 1
                ;;
        esac
        
        read -p "Enter برای بازگشت به منو..."
    done
}

# اجرای اصلی
install_dependencies
main_menu
