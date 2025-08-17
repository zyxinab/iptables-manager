#!/bin/bash

###################
# 颜色定义
###################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # 无颜色

###################
# 全局变量
###################
FORWARD_RULES_FILE="/etc/iptables-forward-rules.conf"
BACKUP_DIR="/root/iptables_backups"
BACKUP_FILE="${BACKUP_DIR}/iptables_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
SYSCTL_CONF="/etc/sysctl.conf"
OS_TYPE="unknown"
IS_ALPINE=false

###################
# 辅助函数
###################
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误：此脚本需要root权限运行${NC}"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/alpine-release ]; then
        OS_TYPE="alpine"
        IS_ALPINE=true
        echo -e "${CYAN}检测到Alpine系统${NC}"
    elif [ -f /etc/debian_version ]; then
        OS_TYPE="debian"
        echo -e "${CYAN}检测到Debian系系统${NC}"
    elif [ -f /etc/redhat-release ]; then
        OS_TYPE="redhat"
        echo -e "${CYAN}检测到RedHat系系统${NC}"
    else
        OS_TYPE="other"
        echo -e "${YELLOW}未能精确识别系统类型，将使用通用配置${NC}"
    fi
}

print_banner() {
    clear
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}                        IPTables 端口转发管理工具                           ${NC}"
    echo -e "${CYAN}                   原作者: 路飞  改编：ZYXin  版本: 1.0                      ${NC}"
    echo -e "${CYAN}                      支持: IPv4/IPv6 & TCP/UDP                          ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

backup_rules() {
    mkdir -p "$BACKUP_DIR"
    # 创建临时文件保存 iptables 规则
    temp_v4_rules="/tmp/iptables_rules.v4"
    temp_v6_rules="/tmp/iptables_rules.v6"
    iptables-save > "$temp_v4_rules"
    ip6tables-save > "$temp_v6_rules" 2>/dev/null

    # 确保转发规则文件存在
    if [ ! -f "$FORWARD_RULES_FILE" ]; then
        touch "$FORWARD_RULES_FILE"
    fi

    # 创建 tar.gz 压缩包，包含 iptables 规则和转发规则文件
    tar -czf "$BACKUP_FILE" -C /tmp iptables_rules.v4 iptables_rules.v6 -C /etc iptables-forward-rules.conf

    # 删除临时规则文件
    rm -f "$temp_v4_rules" "$temp_v6_rules"

    echo -e "${GREEN}规则已备份到: $BACKUP_FILE${NC}"
}

check_dependencies() {
    # 检查并安装依赖
    if $IS_ALPINE; then
        # Alpine使用apk包管理器
        if ! command -v socat &> /dev/null; then
            echo -e "${YELLOW}正在安装socat...${NC}"
            apk add --no-cache socat
        fi
        
        # 确保iptables和ip6tables可用
        if ! command -v ip6tables &> /dev/null; then
            echo -e "${YELLOW}正在安装ip6tables...${NC}"
            apk add --no-cache ip6tables
        fi
    else
        # Debian/Ubuntu系统
        if command -v apt-get &> /dev/null; then
            if ! command -v socat &> /dev/null; then
                echo -e "${YELLOW}正在安装socat...${NC}"
                apt-get update && apt-get install -y socat
            fi
        # RHEL/CentOS系统
        elif command -v yum &> /dev/null; then
            if ! command -v socat &> /dev/null; then
                echo -e "${YELLOW}正在安装socat...${NC}"
                yum install -y socat
            fi
        fi
    fi

    echo -e "${GREEN}所有依赖检查完成${NC}"
}

###################
# 功能函数
###################
enable_ip_forward() {
    # 创建临时文件
    local tmp_sysctl="/tmp/sysctl_temp.conf"

    # 基础网络优化参数（包括IPv6支持）
    cat > "$tmp_sysctl" << EOF
# 启用IP转发
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# BBR优化
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 内存优化
vm.swappiness = 1

# TCP缓冲区优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 212992 16777216
net.ipv4.tcp_wmem = 4096 212992 16777216

# 连接跟踪优化
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120

# IPv6优化
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
EOF

    # 备份和更新sysctl配置
    if [ -f "$SYSCTL_CONF" ]; then
        cp "$SYSCTL_CONF" "${SYSCTL_CONF}.bak"
        grep -v -F -f <(grep -v '^#' "$tmp_sysctl" | cut -d= -f1 | tr -d ' ') "$SYSCTL_CONF" > "${SYSCTL_CONF}.tmp"
        mv "${SYSCTL_CONF}.tmp" "$SYSCTL_CONF"
    fi

    # 添加新的配置
    cat "$tmp_sysctl" >> "$SYSCTL_CONF"

    # 应用配置
    sysctl -p "$SYSCTL_CONF"

    # 清理临时文件
    rm -f "$tmp_sysctl"

    # 创建开机自启动脚本
    create_startup_script

    echo -e "${GREEN}IP转发已启用、系统参数已优化，并已创建开机自启动脚本${NC}"
}

add_forward_rule() {
    echo -e "${YELLOW}请选择转发协议：${NC}"
    echo "1. TCP"
    echo "2. UDP"
    echo "3. TCP+UDP"
    read -p "> " protocol_choice
    
    case $protocol_choice in
        1) protocol="tcp" ;;
        2) protocol="udp" ;;
        3) protocol="both" ;;
        *) 
            echo -e "${RED}无效选择，默认使用TCP+UDP${NC}"
            protocol="both"
            ;;
    esac

    echo -e "${YELLOW}请选择源地址IP版本：${NC}"
    echo "1. 仅IPv4"
    echo "2. 仅IPv6"
    echo "3. 双栈(IPv4+IPv6)"
    read -p "> " src_ip_version
    
    echo -e "${YELLOW}请输入源端口：${NC}"
    read -p "> " src_port

    echo -e "${YELLOW}请选择目标地址IP版本：${NC}"
    echo "1. IPv4"
    echo "2. IPv6"
    read -p "> " dst_ip_version
    
    if [ "$dst_ip_version" == "1" ]; then
        ip_version="ipv4"
        echo -e "${YELLOW}请输入目标IPv4地址：${NC}"
    else
        ip_version="ipv6"
        echo -e "${YELLOW}请输入目标IPv6地址：${NC}"
    fi
    read -p "> " target_ip

    echo -e "${YELLOW}请输入目标端口：${NC}"
    read -p "> " target_port

    # 验证输入
    if [[ ! $src_port =~ ^[0-9]+$ ]] || [[ ! $target_port =~ ^[0-9]+$ ]]; then
        echo -e "${RED}无效的端口格式${NC}"
        return 1
    fi

    # 验证IP地址格式
    if [ "$ip_version" == "ipv4" ] && ! [[ $target_ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo -e "${RED}无效的IPv4地址格式${NC}"
        return 1
    fi
    
    if [ "$ip_version" == "ipv6" ] && ! [[ $target_ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
        echo -e "${RED}无效的IPv6地址格式${NC}"
        return 1
    fi

    # 检查端口是否已被使用
    if grep -q "^$src_port " "$FORWARD_RULES_FILE" 2>/dev/null; then
        echo -e "${RED}源端口 $src_port 已被使用${NC}"
        return 1
    fi

    # 添加到配置文件
    mkdir -p "$(dirname "$FORWARD_RULES_FILE")"
    echo "$src_port $target_ip $target_port $protocol $ip_version $src_ip_version" >> "$FORWARD_RULES_FILE"

    # 添加iptables规则
    apply_forward_rule "$src_port" "$target_ip" "$target_port" "$protocol" "$ip_version" "$src_ip_version"

    echo -e "${GREEN}转发规则添加成功${NC}"
    
    # 添加规则后立即进行优化
    echo -e "${YELLOW}正在优化转发规则...${NC}"
    optimize_rules
    
    sleep 1
}

apply_forward_rule() {
    local src_port=$1
    local target_ip=$2
    local target_port=$3
    local protocol=$4
    local ip_version=$5
    local src_ip_version=$6

    # 处理源IP版本
    local source_versions=()
    case $src_ip_version in
        1) source_versions=("ipv4") ;;
        2) source_versions=("ipv6") ;;
        3) source_versions=("ipv4" "ipv6") ;;
        *) source_versions=("ipv4" "ipv6") ;;
    esac

    # 目标IP版本的iptables命令
    local ip_cmd=""
    [ "$ip_version" == "ipv4" ] && ip_cmd="iptables" || ip_cmd="ip6tables"

    # 处理协议
    local protocols=()
    case $protocol in
        "tcp") protocols=("tcp") ;;
        "udp") protocols=("udp") ;;
        "both") protocols=("tcp" "udp") ;;
    esac

    # 为每个源IP版本和协议应用规则
    for src_version in "${source_versions[@]}"; do
        local src_cmd=""
        [ "$src_version" == "ipv4" ] && src_cmd="iptables" || src_cmd="ip6tables"

        for proto in "${protocols[@]}"; do
            # 如果源和目标IP版本不同，需要使用SOCAT转发
            if [ "$src_version" != "$ip_version" ]; then
                setup_socat_forward "$src_port" "$target_ip" "$target_port" "$proto"
            else
                $src_cmd -t nat -A PREROUTING -p $proto --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}"
                $src_cmd -t nat -A POSTROUTING -p $proto -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
                $src_cmd -A FORWARD -p $proto -d "${target_ip}" --dport "${target_port}" -j ACCEPT
                $src_cmd -A FORWARD -p $proto -s "${target_ip}" --sport "${target_port}" -j ACCEPT
            fi
        done
    done
}

setup_socat_forward() {
    local src_port=$1
    local target_ip=$2
    local target_port=$3
    local proto=$4
    
    # 检查socat是否已安装
    if ! command -v socat &> /dev/null; then
        echo -e "${YELLOW}socat未安装，正在安装...${NC}"
        check_dependencies
    fi
    
    # 创建socat服务目录
    mkdir -p /etc/socat-forwards

    # 根据协议确定socat参数
    local socat_proto="TCP"
    if [ "$proto" == "udp" ]; then
        socat_proto="UDP"
    fi

    # 创建socat服务文件
    local service_name="socat-forward-${src_port}-${proto}"
    local service_file=""
    
    if $IS_ALPINE; then
        # Alpine使用OpenRC服务管理
        service_file="/etc/init.d/${service_name}"
        
        cat > "$service_file" << EOF
#!/sbin/openrc-run

name="${service_name}"
description="SOCAT forward from port ${src_port} to ${target_ip}:${target_port} (${proto})"
command="/usr/bin/socat"
command_args="${socat_proto}4-LISTEN:${src_port},fork,reuseaddr ${socat_proto}6:[${target_ip}]:${target_port}"
pidfile="/run/${service_name}.pid"
command_background="yes"

depend() {
    need net
    after firewall
}
EOF
        chmod +x "$service_file"
        rc-update add "$service_name" default
        rc-service "$service_name" start
        
    else
        # 其他系统使用systemd
        service_file="/etc/systemd/system/${service_name}.service"
        
        cat > "$service_file" << EOF
[Unit]
Description=SOCAT forward from port ${src_port} to ${target_ip}:${target_port} (${proto})
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat ${socat_proto}4-LISTEN:${src_port},fork,reuseaddr ${socat_proto}6:[${target_ip}]:${target_port}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "$service_name"
        systemctl start "$service_name"
    fi
    
    echo -e "${GREEN}已创建并启动socat转发服务: ${src_port} -> ${target_ip}:${target_port} (${proto})${NC}"
}

delete_forward_rule() {
    if [ ! -f "$FORWARD_RULES_FILE" ]; then
        echo -e "${RED}没有可删除的规则${NC}"
        sleep 1
        return
    fi

    echo -e "${YELLOW}请选择要删除的规则编号：${NC}"
    awk '{printf NR ". %s -> %s:%s (%s/%s/%s)\n", $1, $2, $3, $4, $5, $6}' "$FORWARD_RULES_FILE"
    read -p "> " rule_num

    if [[ ! $rule_num =~ ^[0-9]+$ ]]; then
        echo -e "${RED}无效的输入${NC}"
        sleep 1
        return
    fi

    local rule
    rule=$(sed -n "${rule_num}p" "$FORWARD_RULES_FILE")
    if [ -n "$rule" ]; then
        read -r src_port target_ip target_port protocol ip_version src_ip_version <<< "$rule"
        
        echo -e "${YELLOW}正在清除与此规则相关的所有配置...${NC}"
        
        # 根据目标IP版本确定iptables命令
        local ip_cmd=""
        [ "$ip_version" == "ipv4" ] && ip_cmd="iptables" || ip_cmd="ip6tables"
        
        # 源IP版本
        local source_versions=()
        case $src_ip_version in
            1) source_versions=("ipv4") ;;
            2) source_versions=("ipv6") ;;
            3) source_versions=("ipv4" "ipv6") ;;
            *) source_versions=("ipv4" "ipv6") ;;
        esac
        
        # 处理协议
        local protocols=()
        case $protocol in
            "tcp") protocols=("tcp") ;;
            "udp") protocols=("udp") ;;
            "both") protocols=("tcp" "udp") ;;
        esac

        # 清除iptables规则
        for src_version in "${source_versions[@]}"; do
            local src_cmd=""
            [ "$src_version" == "ipv4" ] && src_cmd="iptables" || src_cmd="ip6tables"
            
            for proto in "${protocols[@]}"; do
                # 清除 PREROUTING 链规则
                $src_cmd -t nat -D PREROUTING -p $proto --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}" 2>/dev/null
                
                # 清除 POSTROUTING 链规则
                $src_cmd -t nat -D POSTROUTING -p $proto -d "${target_ip}" --dport "${target_port}" -j MASQUERADE 2>/dev/null
                
                # 清除 FORWARD 链规则
                $src_cmd -D FORWARD -p $proto -d "${target_ip}" --dport "${target_port}" -j ACCEPT 2>/dev/null
                $src_cmd -D FORWARD -p $proto -s "${target_ip}" --sport "${target_port}" -j ACCEPT 2>/dev/null
            done
        done

        # 如果源和目标IP版本不同，停止并删除socat服务
        if [ "$src_ip_version" != "$ip_version" ]; then
            for proto in "${protocols[@]}"; do
                local service_name="socat-forward-${src_port}-${proto}"
                
                if $IS_ALPINE; then
                    # Alpine系统停止服务
                    rc-service "$service_name" stop 2>/dev/null
                    rc-update del "$service_name" default 2>/dev/null
                    rm -f "/etc/init.d/${service_name}" 2>/dev/null
                else
                    # 其他系统停止服务
                    systemctl stop "$service_name" 2>/dev/null
                    systemctl disable "$service_name" 2>/dev/null
                    rm -f "/etc/systemd/system/${service_name}.service" 2>/dev/null
                    systemctl daemon-reload 2>/dev/null
                fi
                
                echo -e "${GREEN}已停止并删除socat转发服务: ${service_name}${NC}"
            done
        fi

        # 从配置文件中删除规则
        sed -i "${rule_num}d" "$FORWARD_RULES_FILE"

        echo -e "${GREEN}规则已成功删除${NC}"
    else
        echo -e "${RED}无效的规则编号${NC}"
    fi
    sleep 1
}

save_rules() {
    mkdir -p "$BACKUP_DIR"

    # 创建临时文件保存 iptables 规则
    temp_rules="/tmp/iptables_rules.v4"
    iptables-save > "$temp_rules"

    # 确保转发规则文件存在
    if [ ! -f "$FORWARD_RULES_FILE" ]; then
        touch "$FORWARD_RULES_FILE"
    fi

    # 创建 tar.gz 压缩包，包含 iptables 规则和转发规则文件
    tar -czf "$BACKUP_FILE" -C /tmp iptables_rules.v4 -C /etc iptables-forward-rules.conf

    # 删除临时规则文件
    rm -f "$temp_rules"

    echo -e "${GREEN}规则已备份到: $BACKUP_FILE${NC}"
    sleep 1
}

create_startup_script() {
    # 创建启动脚本目录
    mkdir -p /usr/local/bin

    # 创建启动脚本
    cat > /usr/local/bin/iptables-forward.sh << 'EOF'
#!/bin/bash

# 启用IP转发
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
sysctl -p

# 恢复转发规则
FORWARD_RULES_FILE="/etc/iptables-forward-rules.conf"
if [ -f "$FORWARD_RULES_FILE" ]; then
    while read -r src_port target_ip target_port protocol ip_version src_ip_version; do
        # 处理源IP版本
        source_versions=()
        case $src_ip_version in
            1) source_versions=("ipv4") ;;
            2) source_versions=("ipv6") ;;
            3) source_versions=("ipv4" "ipv6") ;;
            *) source_versions=("ipv4" "ipv6") ;;
        esac

        # 目标IP版本的iptables命令
        ip_cmd=""
        [ "$ip_version" == "ipv4" ] && ip_cmd="iptables" || ip_cmd="ip6tables"

        # 处理协议
        protocols=()
        case $protocol in
            "tcp") protocols=("tcp") ;;
            "udp") protocols=("udp") ;;
            "both") protocols=("tcp" "udp") ;;
        esac

        # 为每个源IP版本和协议应用规则
        for src_version in "${source_versions[@]}"; do
            src_cmd=""
            [ "$src_version" == "ipv4" ] && src_cmd="iptables" || src_cmd="ip6tables"

            for proto in "${protocols[@]}"; do
                # 如果源和目标IP版本相同，使用iptables
                if [ "$src_version" == "$ip_version" ]; then
                    $src_cmd -t nat -A PREROUTING -p $proto --dport "$src_port" -j DNAT --to-destination "${target_ip}:${target_port}"
                    $src_cmd -t nat -A POSTROUTING -p $proto -d "${target_ip}" --dport "${target_port}" -j MASQUERADE
                    $src_cmd -A FORWARD -p $proto -d "${target_ip}" --dport "${target_port}" -j ACCEPT
                    $src_cmd -A FORWARD -p $proto -s "${target_ip}" --sport "${target_port}" -j ACCEPT
                fi
            done
        done
    done < "$FORWARD_RULES_FILE"
fi

# 允许已建立的连接
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
EOF

    chmod +x /usr/local/bin/iptables-forward.sh

    # 根据系统类型添加开机启动
    if $IS_ALPINE; then
        # Alpine使用OpenRC
        cat > /etc/init.d/iptables-forward << 'EOF'
#!/sbin/openrc-run

name="iptables-forward"
description="IPTables Forward Rules"
command="/usr/local/bin/iptables-forward.sh"
command_background="no"

depend() {
    need net
    after firewall
}
EOF
        chmod +x /etc/init.d/iptables-forward
        rc-update add iptables-forward default
        echo -e "${GREEN}已创建并启用OpenRC服务${NC}"
        
    elif [ -d /etc/systemd/system ]; then
        # Debian/Ubuntu/CentOS等使用systemd系统
        cat > /etc/systemd/system/iptables-forward.service << EOF
[Unit]
Description=IPTables Forward Rules
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/iptables-forward.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable iptables-forward.service
        echo -e "${GREEN}已创建并启用systemd服务${NC}"

    elif [ -f /etc/crontab ]; then
        # 其他Linux系统使用crontab
        echo "@reboot root /usr/local/bin/iptables-forward.sh" >> /etc/crontab
        echo -e "${GREEN}已添加到crontab开机任务${NC}"

    else
        # 其他Linux系统
        if [ -f /etc/rc.local ]; then
            sed -i '/exit 0/i\/usr/local/bin/iptables-forward.sh' /etc/rc.local
        else
            cat > /etc/rc.local << EOF
#!/bin/bash
/usr/local/bin/iptables-forward.sh
exit 0
EOF
            chmod +x /etc/rc.local
        fi
        echo -e "${GREEN}已添加到rc.local${NC}"
    fi

    echo -e "${GREEN}开机自启动脚本创建成功！${NC}"
    echo -e "${CYAN}脚本位置：/usr/local/bin/iptables-forward.sh${NC}"
}

optimize_rules() {
    echo -e "${YELLOW}开始优化规则...${NC}"
    
    # 为IPv4和IPv6分别优化
    for version in "ipv4" "ipv6"; do
        local ip_cmd=""
        [ "$version" == "ipv4" ] && ip_cmd="iptables" || ip_cmd="ip6tables"
        
        # 1. 保存当前所有目标IP
        local target_ips=()
        if [ -f "$FORWARD_RULES_FILE" ]; then
            if [ "$version" == "ipv4" ]; then
                target_ips=($(awk '$5 == "ipv4" {print $2}' "$FORWARD_RULES_FILE" | sort -u))
            else
                target_ips=($(awk '$5 == "ipv6" {print $2}' "$FORWARD_RULES_FILE" | sort -u))
            fi
        fi

        for target_ip in "${target_ips[@]}"; do
            echo -e "${CYAN}正在优化 ${target_ip} 相关规则...${NC}"
            
            # 2. 删除重复的单端口FORWARD规则
            $ip_cmd -D FORWARD -p tcp -d "${target_ip}" --dport 443 -j ACCEPT 2>/dev/null
            $ip_cmd -D FORWARD -p tcp -s "${target_ip}" --sport 443 -j ACCEPT 2>/dev/null
            $ip_cmd -D FORWARD -p udp -d "${target_ip}" --dport 443 -j ACCEPT 2>/dev/null
            $ip_cmd -D FORWARD -p udp -s "${target_ip}" --sport 443 -j ACCEPT 2>/dev/null
            
            # 3. 确保只有一条multiport规则
            $ip_cmd -D FORWARD -p tcp -d "${target_ip}" -m multiport --dports 80,443 -j ACCEPT 2>/dev/null
            $ip_cmd -D FORWARD -p tcp -s "${target_ip}" -m multiport --sports 80,443 -j ACCEPT 2>/dev/null
            $ip_cmd -D FORWARD -p udp -d "${target_ip}" -m multiport --dports 80,443 -j ACCEPT 2>/dev/null
            $ip_cmd -D FORWARD -p udp -s "${target_ip}" -m multiport --sports 80,443 -j ACCEPT 2>/dev/null
            
            # 4. 添加优化后的规则
            $ip_cmd -A FORWARD -p tcp -d "${target_ip}" -m multiport --dports 80,443 -j ACCEPT
            $ip_cmd -A FORWARD -p tcp -s "${target_ip}" -m multiport --sports 80,443 -j ACCEPT
            $ip_cmd -A FORWARD -p udp -d "${target_ip}" -m multiport --dports 80,443 -j ACCEPT
            $ip_cmd -A FORWARD -p udp -s "${target_ip}" -m multiport --sports 80,443 -j ACCEPT
            
            # 5. 优化NAT规则
            # 删除多余的MASQUERADE规则
            $ip_cmd -t nat -D POSTROUTING -p tcp -d "${target_ip}" --dport 443 -j MASQUERADE 2>/dev/null
            $ip_cmd -t nat -D POSTROUTING -p udp -d "${target_ip}" --dport 443 -j MASQUERADE 2>/dev/null
            
            # 确保SNAT规则正确（如果存在）
            if [ "$version" == "ipv4" ]; then
                local public_ip=$(curl -s ifconfig.me)
                if [ -n "$public_ip" ]; then
                    $ip_cmd -t nat -D POSTROUTING -p tcp -d "${target_ip}" -j SNAT --to-source "$public_ip" 2>/dev/null
                    $ip_cmd -t nat -A POSTROUTING -p tcp -d "${target_ip}" -j SNAT --to-source "$public_ip"
                    $ip_cmd -t nat -D POSTROUTING -p udp -d "${target_ip}" -j SNAT --to-source "$public_ip" 2>/dev/null
                    $ip_cmd -t nat -A POSTROUTING -p udp -d "${target_ip}" -j SNAT --to-source "$public_ip"
                fi
            fi
        done
    done
    
    echo -e "${GREEN}规则优化完成！${NC}"
    
    # 显示优化后的规则
    echo -e "\n${CYAN}优化后的规则：${NC}"
    check_forward_status
}

check_forward_status() {
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                           系统状态                              │${NC}"
    echo -e "${CYAN}├──────────────────┬──────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│  IPv4转发状态    │${NC} $(cat /proc/sys/net/ipv4/ip_forward)                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│  IPv6转发状态    │${NC} $(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "未启用")                                        ${CYAN}│${NC}"
    echo -e "${CYAN}│    当前连接数    │${NC} $(netstat -nat | grep ESTABLISHED | wc -l)                                       ${CYAN}│${NC}"
    echo -e "${CYAN}│    系统类型      │${NC} $OS_TYPE                                       ${CYAN}│${NC}"
    echo -e "${CYAN}└──────────────────┴──────────────────────────────────────────────┘${NC}"
    echo ""

    # 显示当前转发规则
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                        当前转发规则                             │${NC}"
    echo -e "${CYAN}├─────┬───────┬───────────────────┬─────────┬─────────┬──────────┤${NC}"
    echo -e "${CYAN}│ 序号│源端口 │     目标IP        │ 目标端口│ 协议    │ IP版本   │${NC}"
    echo -e "${CYAN}├─────┼───────┼───────────────────┼─────────┼─────────┼──────────┤${NC}"
    if [ -f "$FORWARD_RULES_FILE" ]; then
        local rule_count=0
        while read -r src_port target_ip target_port protocol ip_version src_ip_version; do
            rule_count=$((rule_count+1))
            
            # 格式化协议显示
            local proto_display=""
            case $protocol in
                "tcp") proto_display="TCP" ;;
                "udp") proto_display="UDP" ;;
                "both") proto_display="TCP+UDP" ;;
            esac
            
            # 格式化源IP版本显示
            local src_version_display=""
            case $src_ip_version in
                1) src_version_display="IPv4" ;;
                2) src_version_display="IPv6" ;;
                3) src_version_display="双栈" ;;
                *) src_version_display="双栈" ;;
            esac
            
            printf "${CYAN}│${NC} %-3d ${CYAN}│${NC} %-5s ${CYAN}│${NC} %-17s ${CYAN}│${NC} %-7s ${CYAN}│${NC} %-7s ${CYAN}│${NC} %-8s ${CYAN}│${NC}\n" \
                "$rule_count" "$src_port" "$target_ip" "$target_port" "$proto_display" "$src_version_display"
        done < "$FORWARD_RULES_FILE"
        
        if [ $rule_count -eq 0 ]; then
            echo -e "${CYAN}│${NC} 暂无转发规则                                                  ${CYAN}│${NC}"
        fi
    else
        echo -e "${CYAN}│${NC} 暂无转发规则                                                  ${CYAN}│${NC}"
    fi
    echo -e "${CYAN}└─────┴───────┴───────────────────┴─────────┴─────────┴──────────┘${NC}"
    echo ""

    # 显示socat转发服务状态
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│                     SOCAT转发服务状态                           │${NC}"
    echo -e "${CYAN}├─────────────────┬───────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│     服务名      │                 状态                          │${NC}"
    echo -e "${CYAN}├─────────────────┼───────────────────────────────────────────────┤${NC}"
    
    # 检查socat服务
    local socat_services=()
    if $IS_ALPINE; then
        # Alpine使用OpenRC
        socat_services=($(ls /etc/init.d/socat-forward-* 2>/dev/null | sed 's|/etc/init.d/||'))
        for service in "${socat_services[@]}"; do
            local status=$(rc-service "$service" status 2>/dev/null | grep -o "status: .*" || echo "未运行")
            printf "${CYAN}│${NC} %-15s ${CYAN}│${NC} %-45s ${CYAN}│${NC}\n" "$service" "$status"
        done
    else
        # 其他系统使用systemd
        socat_services=($(ls /etc/systemd/system/socat-forward-*.service 2>/dev/null | sed 's|/etc/systemd/system/||' | sed 's|.service||'))
        for service in "${socat_services[@]}"; do
            local status=$(systemctl status "$service" 2>/dev/null | grep "Active:" | sed 's/^ *Active: //' || echo "未运行")
            printf "${CYAN}│${NC} %-15s ${CYAN}│${NC} %-45s ${CYAN}│${NC}\n" "$service" "$status"
        done
    fi
    
    if [ ${#socat_services[@]} -eq 0 ]; then
        echo -e "${CYAN}│${NC} 暂无SOCAT转发服务                                             ${CYAN}│${NC}"
    fi
    
    echo -e "${CYAN}└─────────────────┴───────────────────────────────────────────────┘${NC}"
}

manage_forward_rules() {
    while true; do
        clear
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${CYAN}                           转发规则管理                                   ${NC}"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}请选择操作：${NC}"
        echo "1. 添加新的转发规则"
        echo "2. 删除转发规则"
        echo "0. 返回主菜单"

        echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}请选择操作 [0-2]:${NC}"
        read -p "> " sub_choice

        case $sub_choice in
            1)
                add_forward_rule
                read -p "按回车继续..."
                ;;
            2)
                delete_forward_rule
                read -p "按回车继续..."
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}无效的选择${NC}"
                sleep 1
                ;;
        esac
    done
}

###################
# 主菜单
###################
show_menu() {
    while true; do
        print_banner
        echo -e "${YELLOW}请选择操作：${NC}"
        echo "1. 启用IP转发并优化和自启"
        echo "2. 转发规则管理"
        echo "3. 保存当前规则"
        echo "4. 查询转发规则"
        echo "5. 恢复之前的规则"
        echo "6. 检查系统和依赖"
        echo "0. 退出"

        echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}请选择操作 [0-6]:${NC}"
        read -p "> " choice

        case $choice in
            1)
                enable_ip_forward
                read -p "按回车继续..."
                ;;
            2)
                manage_forward_rules
                ;;
            3)
                save_rules
                read -p "按回车继续..."
                ;;
            4)
                check_forward_status
                read -p "按回车继续..."
                ;;
            5)
                restore_rules
                read -p "按回车继续..."
                ;;
            6)
                detect_os
                check_dependencies
                read -p "按回车继续..."
                ;;
            0)
                exit 0
                ;;
            *)
                echo -e "${RED}无效的选择${NC}"
                sleep 1
                ;;
        esac
    done
}

###################
# 主程序
###################
check_root
detect_os
check_dependencies
show_menu
