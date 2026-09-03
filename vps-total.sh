#!/usr/bin/env bash
# ============================================================
#  VPS 综合管理脚本 (系统加固 + DNAT 端口转发) 修复增强版
#  用法: bash vps-total.sh
# ============================================================

set -u
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}请用 root 运行此脚本${NC}"
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo -e "${YELLOW}警告：本脚本依赖 apt-get，仅支持 Debian/Ubuntu 系列发行版。${NC}"
    exit 1
fi

validate_port() {
    local port="${1:-}"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    return 0
}

validate_proto() {
    local proto="${1:-}"
    if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
        return 1
    fi
    return 0
}

validate_ip() {
    local ip="${1:-}"
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r a b c d <<< "$ip"
        if (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )); then
            return 0
        fi
    fi
    return 1
}

validate_pubkey() {
    local key="${1:-}"
    case "$key" in
        ssh-*|ecdsa-*|sk-*|ed25519-*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

get_ssh_port() {
    local port
    port=$(sshd -T 2>/dev/null | awk '/^port /{print $2}' | head -n 1)
    if [ -z "$port" ]; then
        echo "22"
    else
        echo "$port"
    fi
}

ufw_available() {
    command -v ufw >/dev/null 2>&1
}

# 精确删除指定端口的 UFW 规则 (倒序删除，防止编号变动)
ufw_delete_port_rules() {
    local port="$1"
    local proto="${2:-}"
    local rules_to_delete
    if [ -n "$proto" ]; then
        rules_to_delete=$(ufw status numbered 2>/dev/null | grep -E "^\\[ *[0-9]+\\] +$port/$proto " | awk -F'[][]' '{print $2}' | grep -E '^[0-9]+$' | sort -rn || true)
    else
        rules_to_delete=$(ufw status numbered 2>/dev/null | grep -E "^\\[ *[0-9]+\\] +$port(/| )" | awk -F'[][]' '{print $2}' | grep -E '^[0-9]+$' | sort -rn || true)
    fi

    if [ -n "$rules_to_delete" ]; then
        for r_num in $rules_to_delete; do
            ufw --force delete "$r_num" >/dev/null 2>&1 || true
        done
    fi
}

# 安全启用 UFW，防止锁死 SSH
safe_enable_ufw() {
    local ssh_p
    ssh_p=$(get_ssh_port)
    ufw allow "$ssh_p/tcp" comment 'SSH-safety' >/dev/null 2>&1 || true
    if [ -n "${SSH_CONNECTION:-}" ]; then
        local curr_ip
        curr_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
        if validate_ip "$curr_ip"; then
            ufw allow from "$curr_ip" to any port "$ssh_p" proto tcp comment 'current-ssh-safety' >/dev/null 2>&1 || true
        fi
    fi
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
    ufw --force enable
}

# ============================================================
# 模块一：系统加固
# ============================================================

hardening() {
    echo -e "${YELLOW}开始执行系统加固...${NC}"
    (
        set -euo pipefail

        NEWPORT="${SSH_PORT:-44644}"
        if ! validate_port "$NEWPORT"; then
            echo "错误: SSH 端口 $NEWPORT 无效，必须是 1-65535 的数字"
            exit 1
        fi

        PUBKEYS="${PUBKEYS:-}"
        SSH_WHITELIST="${SSH_WHITELIST:-}"
        PUBLIC_PORTS="${PUBLIC_PORTS:-}"

        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq 2>/dev/null || apt-get update
        apt-get install -y ca-certificates
        command -v curl >/dev/null || apt-get install -y curl
        command -v wget >/dev/null || apt-get install -y wget

        apt-get full-upgrade -y
        ARCH=$(dpkg --print-architecture)
        if [ "$ARCH" = "amd64" ] || [ "$ARCH" = "arm64" ]; then
            apt-get install -y "linux-image-$ARCH" || true
        fi

        apt-get install -y curl wget git htop net-tools traceroute ca-certificates \
                           fail2ban earlyoom unattended-upgrades iptables-persistent

        mkdir -p /root/.ssh && chmod 700 /root/.ssh
        touch /root/.ssh/authorized_keys 2>/dev/null

        if [ -n "$PUBKEYS" ]; then
            IFS=',' read -ra _keys <<< "$PUBKEYS"
            for _k in "${_keys[@]}"; do
                _k="$(echo "$_k" | xargs)"
                [ -z "$_k" ] && continue
                if validate_pubkey "$_k"; then
                    grep -qF "$_k" /root/.ssh/authorized_keys 2>/dev/null || echo "$_k" >> /root/.ssh/authorized_keys
                else
                    echo "警告: 忽略无效公钥: $_k"
                fi
            done
        fi

        if [ -s /root/.ssh/authorized_keys ]; then
            HAS_KEY=1
        else
            HAS_KEY=0
            echo "警告: 未检测到公钥，将保留密码登录"
        fi
        chmod 600 /root/.ssh/authorized_keys

        SSHD=/etc/ssh/sshd_config
        [ -f "$SSHD" ] && cp "$SSHD" "$SSHD.bak.$(date +%F_%T)"

        sed -i -E '/^[[:space:]]*#?[[:space:]]*Port[[:space:]]+/d' "$SSHD"
        printf 'Port %s\n' "$NEWPORT" >> "$SSHD"

        # drop-in 目录写入权威配置
        if [ -d /etc/ssh/sshd_config.d ]; then
            cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port $NEWPORT
EOF
            if [ "$HAS_KEY" -eq 1 ]; then
                cat >> /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
EOF
            fi
        fi

        if [ "$HAS_KEY" -eq 1 ]; then
            sed -i -E '/^[[:space:]]*#?[[:space:]]*(PubkeyAuthentication|PasswordAuthentication|PermitRootLogin|ChallengeResponseAuthentication|KbdInteractiveAuthentication|UsePAM)[[:space:]]+/d' "$SSHD"
            cat >> "$SSHD" <<EOF
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
EOF
        fi

        if sshd -t; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd
        else
            echo "SSH 配置测试失败，未重启服务，请检查配置文件"
            exit 1
        fi

        apt-get install -y ufw
        ufw default deny incoming 2>/dev/null || true
        ufw default allow outgoing 2>/dev/null || true

        # 清理旧 SSH 端口规则
        ufw_delete_port_rules "$NEWPORT" "tcp"

        if [ -n "$SSH_WHITELIST" ]; then
            for _ip in $SSH_WHITELIST; do
                if validate_ip "$_ip"; then
                    if ! ufw status | grep -q "ALLOW.*$_ip.*$NEWPORT/tcp"; then
                        ufw allow from "$_ip" to any port "$NEWPORT" proto tcp comment "ssh-whitelist-$_ip"
                    fi
                else
                    echo "警告: 无效白名单 IP 忽略: $_ip"
                fi
            done
            if [ -n "${SSH_CONNECTION:-}" ]; then
                CURRENT_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
                if validate_ip "$CURRENT_IP" && ! ufw status | grep -q "ALLOW.*$CURRENT_IP.*$NEWPORT/tcp"; then
                    ufw allow from "$CURRENT_IP" to any port "$NEWPORT" proto tcp comment 'current-ssh-session'
                fi
            fi
        else
            ufw allow "$NEWPORT/tcp" comment 'SSH'
        fi

        ufw --force enable
        ufw reload

        if [ -n "$PUBLIC_PORTS" ]; then
            for _p in $PUBLIC_PORTS; do
                if validate_port "$_p" && ! ufw status | grep -q "ALLOW.*$_p/tcp"; then
                    ufw allow "$_p/tcp" comment public-svc
                fi
            done
        fi

        cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port    = $NEWPORT
backend = systemd
EOF
        systemctl enable --now fail2ban 2>/dev/null || systemctl restart fail2ban

        systemctl enable --now earlyoom 2>/dev/null || true
        grep -q 'Update-Package-Lists' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || {
            printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' \
                > /etc/apt/apt.conf.d/20auto-upgrades
        }
        systemctl enable --now apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true

        echo "系统加固完成。"
        echo "注意：UFW 已启用，请检查并放行业务端口。"
        echo "请务必新开终端测试登录：ssh -p $NEWPORT root@<IP>"
    )
    local ret=$?
    if [ $ret -eq 0 ]; then
        echo -e "${GREEN}加固执行完毕。${NC}"
    else
        echo -e "${RED}加固过程中出现错误，请检查输出。${NC}"
    fi
    return $ret
}

check_hardening() {
    echo -e "${YELLOW}开始检查加固状态...${NC}"
    SSHD_PORT=$(get_ssh_port)
    echo "当前 SSH 端口: $SSHD_PORT"
    if ss -tlnp 2>/dev/null | grep -q ":22 "; then
        echo -e "${RED}[失败]${NC} 22 端口仍在监听"
    else
        echo -e "${GREEN}[通过]${NC} 22 端口未监听"
    fi
    PASS_AUTH=$(sshd -T 2>/dev/null | awk '/^passwordauthentication /{print $2}' | head -n 1)
    ROOT_LOGIN=$(sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2}' | head -n 1)
    PUBKEY_AUTH=$(sshd -T 2>/dev/null | awk '/^pubkeyauthentication /{print $2}' | head -n 1)
    if [ "$PASS_AUTH" = "no" ]; then
        echo -e "${GREEN}[通过]${NC} PasswordAuthentication 已关闭"
    else
        echo -e "${RED}[失败]${NC} PasswordAuthentication 仍为 $PASS_AUTH"
    fi
    if [ "$ROOT_LOGIN" = "prohibit-password" ] || [ "$ROOT_LOGIN" = "without-password" ] || [ "$ROOT_LOGIN" = "no" ]; then
        echo -e "${GREEN}[通过]${NC} PermitRootLogin 已限制 ($ROOT_LOGIN)"
    else
        echo -e "${YELLOW}[警告]${NC} PermitRootLogin 为 $ROOT_LOGIN"
    fi
    if [ "$PUBKEY_AUTH" = "yes" ]; then
        echo -e "${GREEN}[通过]${NC} PubkeyAuthentication 已启用"
    else
        echo -e "${YELLOW}[警告]${NC} PubkeyAuthentication 为 $PUBKEY_AUTH"
    fi
    
    if ufw_available; then
        if ufw status | grep -q "active"; then
            echo -e "${GREEN}[通过]${NC} UFW 已启用"
            echo "当前规则:"
            ufw status | grep -E '^[0-9]|^Status|^To' | sed 's/^/  /'
        else
            echo -e "${RED}[失败]${NC} UFW 未启用"
        fi
    else
        echo -e "${YELLOW}[警告]${NC} UFW 未安装"
    fi
    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}[通过]${NC} fail2ban 服务运行中"
    else
        echo -e "${YELLOW}[警告]${NC} fail2ban 未运行或未安装"
    fi
    if systemctl is-active --quiet earlyoom; then
        echo -e "${GREEN}[通过]${NC} earlyoom 服务运行中"
    else
        echo -e "${YELLOW}[警告]${NC} earlyoom 未运行或未安装"
    fi
}

add_pubkey_disable_pass() {
    echo -e "${YELLOW}添加公钥并关闭密码登录${NC}"
    echo -e "请粘贴您的 SSH 公钥（一行，以 ssh- 或 ecdsa- 等开头），然后按回车："
    read -r PUBKEY
    if [ -z "$PUBKEY" ]; then
        echo -e "${RED}未输入公钥，操作取消。${NC}"
        return
    fi
    if ! validate_pubkey "$PUBKEY"; then
        echo -e "${RED}公钥格式无效，操作取消。${NC}"
        return
    fi
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys
    if grep -qF "$PUBKEY" /root/.ssh/authorized_keys; then
        echo "公钥已存在，跳过添加。"
    else
        echo "$PUBKEY" >> /root/.ssh/authorized_keys
        echo "公钥已添加。"
    fi
    chmod 600 /root/.ssh/authorized_keys

    local CURRENT_PORT
    CURRENT_PORT=$(get_ssh_port)

    SSHD=/etc/ssh/sshd_config
    [ -f "$SSHD" ] && cp "$SSHD" "$SSHD.bak.$(date +%F_%T)"
    
    sed -i -E '/^[[:space:]]*#?[[:space:]]*(PubkeyAuthentication|PasswordAuthentication|PermitRootLogin|ChallengeResponseAuthentication|KbdInteractiveAuthentication|UsePAM)[[:space:]]+/d' "$SSHD"
    cat >> "$SSHD" <<EOF
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
EOF

    # 保持原端口设置与 PAM，避免覆盖丢失 Port 配置
    if [ -d /etc/ssh/sshd_config.d ]; then
        cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port $CURRENT_PORT
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
EOF
    fi

    if sshd -t; then
        systemctl restart ssh 2>/dev/null || systemctl restart sshd
        echo -e "${GREEN}密码登录已关闭，公钥认证已启用。当前端口: $CURRENT_PORT${NC}"
        echo "请立即在新终端测试密钥登录，确保可连接。"
    else
        echo -e "${RED}SSH 配置测试失败，未重启服务，请检查配置文件。${NC}"
        return 1
    fi
}

set_ssh_whitelist() {
    echo -e "${YELLOW}设置 SSH IP 白名单${NC}"
    if ! ufw_available; then
        echo -e "${RED}错误：UFW 未安装。${NC}"
        return
    fi
    if ! ufw status | grep -q "active"; then
        echo -e "${YELLOW}警告：UFW 未启用。是否现在安全启用？(y/N)${NC}"
        read -r enable_ufw
        if [[ "$enable_ufw" =~ ^[Yy]$ ]]; then
            safe_enable_ufw
        else
            echo "已取消。"
            return
        fi
    fi
    local SSH_PORT
    SSH_PORT=$(get_ssh_port)
    echo -e "当前 SSH 端口: $SSH_PORT"
    echo -e "请输入允许访问 SSH 的 IP 地址（可多个，用空格分隔）："
    read -r IPS
    if [ -z "$IPS" ]; then
        echo -e "${RED}未输入 IP，操作取消。${NC}"
        return
    fi

    echo -e "${RED}警告：此操作将删除当前 SSH 端口的全局放行规则，仅允许白名单访问。${NC}"
    CURRENT_IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
    echo -e "${YELLOW}当前连接 IP: ${CURRENT_IP:-未知}，将强制放行防失联。${NC}"
    read -p "确认继续？(y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消。"
        return
    fi

    # 清理该 SSH 端口已有的全部规则（包括全局开放与旧白名单）
    ufw_delete_port_rules "$SSH_PORT" "tcp"

    for ip in $IPS; do
        if validate_ip "$ip"; then
            if ! ufw status | grep -q "ALLOW.*$ip.*$SSH_PORT/tcp"; then
                ufw allow from "$ip" to any port "$SSH_PORT" proto tcp comment "ssh-whitelist-$ip"
                echo "已添加白名单 IP: $ip"
            else
                echo "白名单 IP $ip 已存在，跳过"
            fi
        else
            echo "无效 IP: $ip，跳过"
        fi
    done

    # 强制保障当前会话 IP 防失联
    if [ -n "$CURRENT_IP" ] && validate_ip "$CURRENT_IP"; then
        if ! ufw status | grep -q "ALLOW.*$CURRENT_IP.*$SSH_PORT/tcp"; then
            ufw allow from "$CURRENT_IP" to any port "$SSH_PORT" proto tcp comment 'current-ssh-session'
            echo "已保障放行当前会话 IP: $CURRENT_IP"
        fi
    fi

    ufw reload
    echo -e "${GREEN}SSH 白名单设置完成。${NC}"
}

open_ports() {
    echo -e "${YELLOW}开放端口 (UFW)${NC}"
    if ! ufw_available; then
        echo -e "${RED}错误：UFW 未安装。${NC}"
        return
    fi
    if ! ufw status | grep -q "active"; then
        echo -e "${YELLOW}警告：UFW 未启用。是否现在安全启用？(y/N)${NC}"
        read -r enable_ufw
        if [[ "$enable_ufw" =~ ^[Yy]$ ]]; then
            safe_enable_ufw
        else
            echo "已取消。"
            return
        fi
    fi
    echo -e "请输入要开放的端口号（空格分隔，例如 80 443）："
    read -r PORTS
    if [ -z "$PORTS" ]; then
        echo -e "${RED}未输入端口，操作取消。${NC}"
        return
    fi
    for p in $PORTS; do
        if validate_port "$p"; then
            if ! ufw status | grep -q "ALLOW.*$p/tcp"; then
                ufw allow "$p/tcp" comment "open-$p" || true
                echo "已开放 TCP 端口 $p"
            else
                echo "端口 $p 已开放，跳过"
            fi
        else
            echo "无效端口: $p，跳过"
        fi
    done
    ufw reload
}

close_ports() {
    echo -e "${YELLOW}关闭端口 (UFW)${NC}"
    if ! ufw_available; then
        echo -e "${RED}错误：UFW 未安装。${NC}"
        return
    fi
    if ! ufw status | grep -q "active"; then
        echo -e "${YELLOW}警告：UFW 未启用。${NC}"
        return
    fi
    local SSH_PORT
    SSH_PORT=$(get_ssh_port)
    echo "当前 UFW 规则:"
    ufw status numbered
    echo -e "请输入要删除的规则编号（多个用空格分隔，倒序输入更佳），或输入 0 取消："
    read -r RULES
    if [ -z "$RULES" ] || [ "$RULES" = "0" ]; then
        echo "操作取消。"
        return
    fi
    echo -e "${YELLOW}将要删除以下规则：${NC}"
    for num in $RULES; do
        if [[ "$num" =~ ^[0-9]+$ ]]; then
            local rule_line
            rule_line=$(ufw status numbered | grep -E "^\[ *$num\]" || true)
            echo "$rule_line"
            if echo "$rule_line" | grep -q "$SSH_PORT"; then
                echo -e "${RED}[警示] 编号 $num 疑似包含当前 SSH 端口 ($SSH_PORT)，误删可能导致 SSH 失去连接！${NC}"
            fi
        fi
    done
    read -p "确认删除？(y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消删除。"
        return
    fi
    sorted_rules=$(echo "$RULES" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -rn | uniq)
    for num in $sorted_rules; do
        ufw --force delete "$num"
        echo "已删除规则 $num"
    done
    ufw reload
}

# ============================================================
# 模块二：DNAT 转发
# ============================================================

precheck_forwarding() {
    echo -e "${YELLOW}===== 预检查转发条件 =====${NC}"

    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "${YELLOW}[警告] 安装 iptables...${NC}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq && apt-get install -y iptables
    fi

    if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
        echo -e "${YELLOW}[警告] 开启 IP 转发...${NC}"
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
        sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
        echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
        echo -e "${GREEN}[完成] IP 转发已启用并持久化${NC}"
    else
        echo -e "${GREEN}[通过] IP 转发已启用${NC}"
    fi

    if ufw_available && ufw status | grep -q "active"; then
        echo -e "${YELLOW}[信息] 检测到 UFW 防火墙${NC}"
        if grep -q '^DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw; then
            echo -e "${YELLOW}[警告] UFW 转发策略为 DROP，正在修改为 ACCEPT...${NC}"
            sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
            ufw reload
            echo -e "${GREEN}[完成] UFW 转发策略已更新并重载${NC}"
        else
            echo -e "${GREEN}[通过] UFW 转发策略已允许转发${NC}"
        fi
    else
        FORWARD_POLICY=$(iptables -L FORWARD | awk '/Chain FORWARD/{print $4}' | tr -d ')' || true)
        if [ "$FORWARD_POLICY" != "ACCEPT" ]; then
            echo -e "${YELLOW}[警告] FORWARD 链默认策略为 $FORWARD_POLICY，改为 ACCEPT...${NC}"
            iptables -P FORWARD ACCEPT
        fi
        echo -e "${GREEN}[通过] iptables FORWARD 策略已置为 ACCEPT${NC}"
    fi

    if ! command -v netfilter-persistent >/dev/null 2>&1; then
        echo -e "${YELLOW}[警告] 安装 iptables-persistent...${NC}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq && apt-get install -y iptables-persistent
    fi

    echo -e "${GREEN}===== 预检查完成 =====${NC}"
}

check_A_success() {
    local B_IP=$1 PROTO=$2
    shift 2
    local mappings=("$@")
    echo -e "${YELLOW}===== 验证 DNAT 转发配置 =====${NC}"

    local all_ok=true

    if [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ]; then
        echo -e "${GREEN}[通过] IP 转发已启用${NC}"
    else
        echo -e "${RED}[失败] IP 转发未启用${NC}"
        all_ok=false
    fi

    local nat_rules
    nat_rules=$(iptables-save -t nat)

    for mapping in "${mappings[@]}"; do
        A_PORT="${mapping%%:*}"
        B_PORT="${mapping##*:}"

        if echo "$nat_rules" | grep -qE -- "-A PREROUTING -p $PROTO -m $PROTO --dport $A_PORT -j DNAT --to-destination $B_IP(:$B_PORT)?"; then
            echo -e "${GREEN}[通过] PREROUTING 规则正常: $A_PORT -> $B_IP:$B_PORT${NC}"
        else
            echo -e "${RED}[失败] PREROUTING 缺失: $A_PORT -> $B_IP:$B_PORT${NC}"
            all_ok=false
        fi

        if echo "$nat_rules" | grep -qE -- "-A POSTROUTING -d $B_IP(/32)? -p $PROTO -m $PROTO --dport $B_PORT -j MASQUERADE"; then
            echo -e "${GREEN}[通过] POSTROUTING MASQUERADE 规则正常${NC}"
        else
            echo -e "${RED}[失败] POSTROUTING MASQUERADE 缺失${NC}"
            all_ok=false
        fi

        if iptables -C FORWARD -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j ACCEPT 2>/dev/null; then
            echo -e "${GREEN}[通过] FORWARD 链正向放行规则正常${NC}"
        else
            echo -e "${RED}[失败] FORWARD 链放行缺失${NC}"
            all_ok=false
        fi
    done

    if [ "$all_ok" = true ]; then
        echo -e "${GREEN}===== 验证通过：所有 DNAT 转发规则配置成功 =====${NC}"
    else
        echo -e "${RED}===== 验证未完全通过，请检查上述失败项 =====${NC}"
    fi
}

configure_A() {
    echo -e "${YELLOW}===== 配置 DNAT 转发 (A 机) =====${NC}"
    precheck_forwarding

    read -p "请输入目标 B 机 IP 地址: " B_IP
    if ! validate_ip "$B_IP"; then
        echo -e "${RED}无效 IP 地址: $B_IP${NC}"
        return
    fi

    read -p "请输入协议 PROTO (tcp/udp, 默认 tcp): " PROTO
    PROTO=${PROTO:-tcp}
    if ! validate_proto "$PROTO"; then
        echo -e "${RED}无效协议: $PROTO (仅支持 tcp 或 udp)${NC}"
        return
    fi

    echo -e "${YELLOW}请输入转发规则，格式: A端口[:B端口] ...${NC}"
    echo -e "  例 1: 8443 2053 (同端口转发)"
    echo -e "  例 2: 8080:80 8443:443 (异端口映射)"
    read -p "转发规则列表: " RULES_INPUT
    if [ -z "$RULES_INPUT" ]; then
        echo -e "${RED}未输入任何规则，操作取消。${NC}"
        return
    fi

    declare -a MAPPINGS=()
    for item in $RULES_INPUT; do
        if [[ "$item" == *:* ]]; then
            A_PORT="${item%%:*}"
            B_PORT="${item##*:}"
        else
            A_PORT="$item"
            B_PORT="$item"
        fi

        if ! validate_port "$A_PORT" || ! validate_port "$B_PORT"; then
            echo -e "${RED}无效端口映射: $item，已忽略${NC}"
            continue
        fi
        MAPPINGS+=("$A_PORT:$B_PORT")
    done

    if [ ${#MAPPINGS[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的转发规则，操作取消。${NC}"
        return
    fi

    echo -e "${YELLOW}开始应用 DNAT 规则...${NC}"

    iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # 深度清理该 A_PORT 上已存在的所有旧 PREROUTING 规则，避免旧规则拦截覆盖
    for mapping in "${MAPPINGS[@]}"; do
        A_PORT="${mapping%%:*}"
        B_PORT="${mapping##*:}"

        while true; do
            local rule_num
            rule_num=$(iptables -t nat -L PREROUTING --line-numbers -n 2>/dev/null | grep -E "dpt:$A_PORT( |$)" | awk '{print $1}' | head -n 1)
            [ -z "$rule_num" ] && break
            iptables -t nat -D PREROUTING "$rule_num" 2>/dev/null || break
        done

        iptables -t nat -D POSTROUTING -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j ACCEPT 2>/dev/null || true
    done

    for mapping in "${MAPPINGS[@]}"; do
        A_PORT="${mapping%%:*}"
        B_PORT="${mapping##*:}"

        if ! iptables -t nat -C PREROUTING -p "$PROTO" --dport "$A_PORT" -j DNAT --to-destination "$B_IP:$B_PORT" 2>/dev/null; then
            iptables -t nat -A PREROUTING -p "$PROTO" --dport "$A_PORT" -j DNAT --to-destination "$B_IP:$B_PORT"
        fi
        if ! iptables -t nat -C POSTROUTING -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE
        fi
        if ! iptables -C FORWARD -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j ACCEPT 2>/dev/null; then
            iptables -I FORWARD 2 -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j ACCEPT
        fi
        echo "已添加: $A_PORT -> $B_IP:$B_PORT ($PROTO)"
    done

    if ufw_available && ufw status | grep -q "active"; then
        for mapping in "${MAPPINGS[@]}"; do
            A_PORT="${mapping%%:*}"
            if ! ufw status | grep -q "ALLOW.*$A_PORT/$PROTO"; then
                ufw allow "$A_PORT/$PROTO" comment "DNAT-Inbound" || true
            fi
        done
    fi

    echo "持久化保存 iptables 规则..."
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    systemctl enable netfilter-persistent.service 2>/dev/null || true
    systemctl restart netfilter-persistent.service 2>/dev/null || true

    check_A_success "$B_IP" "$PROTO" "${MAPPINGS[@]}"
}

configure_B() {
    echo -e "${YELLOW}===== 配置目标服务节点放行 (B 机) =====${NC}"

    if ! command -v ufw >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        command -v iptables >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y iptables; }
        command -v netfilter-persistent >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y iptables-persistent; }
    fi

    read -p "请输入 A 机中转公网 IP 地址: " A_IP
    if ! validate_ip "$A_IP"; then
        echo -e "${RED}无效 IP 地址: $A_IP${NC}"
        return
    fi

    read -p "请输入本机需要放行的端口（空格分隔，例如 80 443）: " B_PORTS_INPUT
    if [ -z "$B_PORTS_INPUT" ]; then
        echo -e "${RED}未输入端口，操作取消。${NC}"
        return
    fi
    
    read -ra B_PORTS <<< "$B_PORTS_INPUT"

    valid_ports=()
    for p in "${B_PORTS[@]}"; do
        if validate_port "$p"; then
            valid_ports+=("$p")
        else
            echo -e "${RED}无效端口: $p，已忽略${NC}"
        fi
    done
    if [ ${#valid_ports[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口，操作取消。${NC}"
        return
    fi

    read -p "请输入协议 PROTO (tcp/udp, 默认 tcp): " PROTO
    PROTO=${PROTO:-tcp}
    if ! validate_proto "$PROTO"; then
        echo -e "${RED}无效协议: $PROTO${NC}"
        return
    fi

    echo -e "${YELLOW}开始配置 B 机入站放行...${NC}"

    if ufw_available && ufw status | grep -q "active"; then
        for p in "${valid_ports[@]}"; do
            if ! ufw status | grep -qE "ALLOW.*$A_IP.*$p/$PROTO"; then
                ufw allow from "$A_IP" to any port "$p" proto "$PROTO" comment "from-A-DNAT" || true
            fi
        done
        ufw reload
    else
        for p in "${valid_ports[@]}"; do
            if ! iptables -C INPUT -p "$PROTO" -s "$A_IP" --dport "$p" -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p "$PROTO" -s "$A_IP" --dport "$p" -j ACCEPT
            fi
        done
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        systemctl enable netfilter-persistent.service 2>/dev/null || true
        systemctl restart netfilter-persistent.service 2>/dev/null || true
    fi

    check_B_success "$A_IP" "$PROTO" "${valid_ports[@]}"
}

check_B_success() {
    local A_IP=$1 PROTO=$2
    shift 2
    local B_PORTS=("$@")
    echo -e "${YELLOW}===== 验证 B 机放行配置 =====${NC}"

    local all_ok=true

    for port in "${B_PORTS[@]}"; do
        if ufw_available && ufw status | grep -q "active"; then
            if ufw status | grep -E "${port}/${PROTO}.*ALLOW.*${A_IP}"; then
                echo -e "${GREEN}[通过] UFW 规则正常放行来自 $A_IP 的 $port/$PROTO${NC}"
            else
                echo -e "${RED}[失败] UFW 规则未命中: $port/$PROTO${NC}"
                all_ok=false
            fi
        else
            if iptables -C INPUT -p "$PROTO" -s "$A_IP" --dport "$port" -j ACCEPT 2>/dev/null; then
                echo -e "${GREEN}[通过] iptables INPUT 正常放行: $port/$PROTO${NC}"
            else
                echo -e "${RED}[失败] iptables INPUT 未命中: $port/$PROTO${NC}"
                all_ok=false
            fi
        fi
    done

    for port in "${B_PORTS[@]}"; do
        if [ "$PROTO" = "tcp" ]; then
            if ss -tlnp 2>/dev/null | grep -q ":$port "; then
                echo -e "${GREEN}[通过] TCP 端口 $port 处于监听状态${NC}"
            else
                echo -e "${YELLOW}[提示] TCP 端口 $port 当前未监听，请确认后端服务已启动${NC}"
            fi
        else
            if ss -ulnp 2>/dev/null | grep -q ":$port "; then
                echo -e "${GREEN}[通过] UDP 端口 $port 处于监听状态${NC}"
            else
                echo -e "${YELLOW}[提示] UDP 端口 $port 当前未监听，请确认后端服务已启动${NC}"
            fi
        fi
    done

    if [ "$all_ok" = true ]; then
        echo -e "${GREEN}===== 验证通过：B 机放行规则生效 =====${NC}"
        echo "提示：若服务商有外层云安全组，也需同步放行来自 $A_IP 的入站流量。"
    else
        echo -e "${RED}===== 验证未完全通过，请检查上述失败项 =====${NC}"
    fi
}

check_forwarding_effectiveness() {
    echo -e "${YELLOW}===== 检查本机 DNAT 转发有效性 =====${NC}"

    if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
        echo -e "${RED}[失败] 系统未启用 IP 转发${NC}"
        return 1
    fi

    local DNAT_LINES
    DNAT_LINES=$(iptables-save -t nat | grep -- "-A PREROUTING .* -j DNAT" || true)
    if [ -z "$DNAT_LINES" ]; then
        echo -e "${RED}[失败] 未在 PREROUTING 链检测到 DNAT 规则${NC}"
        return 1
    fi

    echo -e "${GREEN}[通过] 发现 DNAT 规则：${NC}"
    echo "$DNAT_LINES"

    echo -e "${YELLOW}正在检测至目标节点端口的链路可用性...${NC}"
    local overall_success=true

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        
        local b_ip b_port
        b_ip=$(echo "$line" | sed -n 's/.*--to-destination \([0-9.]*\).*/\1/p' | cut -d':' -f1)
        b_port=$(echo "$line" | sed -n 's/.*--to-destination [0-9.]*:\([0-9]*\).*/\1/p')
        
        if [ -z "$b_port" ]; then
            b_port=$(echo "$line" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
        fi

        if [ -z "$b_ip" ] || [ -z "$b_port" ]; then
            continue
        fi

        local proto_used
        proto_used=$(echo "$line" | sed -n 's/.*-p \([a-z0-9]*\).*/\1/p')
        proto_used=${proto_used:-tcp}

        if [ "$proto_used" = "udp" ]; then
            echo -e "${YELLOW}[跳过] UDP 规则 ($b_ip:$b_port)，不支持 TCP 握手探针。${NC}"
            continue
        fi

        if timeout 3 bash -c "echo > /dev/tcp/$b_ip/$b_port" 2>/dev/null; then
            echo -e "${GREEN}[通过] 到 $b_ip:$b_port 的网络可达${NC}"
        elif command -v nc >/dev/null 2>&1 && nc -z -w 3 "$b_ip" "$b_port" >/dev/null 2>&1; then
            echo -e "${GREEN}[通过] 到 $b_ip:$b_port 的网络可达${NC}"
        else
            echo -e "${RED}[失败] 无法连通 $b_ip:$b_port，请排查 B 机防火墙/安全组或监听状态${NC}"
            overall_success=false
        fi
    done <<< "$DNAT_LINES"

    if [ "$overall_success" = true ]; then
        echo -e "${GREEN}===== 检查完成：转发链路正常 =====${NC}"
    else
        echo -e "${RED}===== 检查完成：存在异常连接项 =====${NC}"
    fi
}

delete_forwarding_rule() {
    echo -e "${YELLOW}===== 删除指定端口转发规则 =====${NC}"
    local DNAT_LINES
    DNAT_LINES=$(iptables-save -t nat | grep -- "-A PREROUTING .* -j DNAT" || true)
    if [ -z "$DNAT_LINES" ]; then
        echo -e "${YELLOW}当前未检测到任何 DNAT 转发规则。${NC}"
        return
    fi
    echo "当前正在生效的 DNAT 规则："
    iptables -t nat -L PREROUTING --line-numbers -n -v | grep -E "DNAT|Chain"
    echo ""
    read -p "请输入要删除的 A 机监听端口 (例如 2054): " DEL_PORT
    if ! validate_port "$DEL_PORT"; then
        echo -e "${RED}无效端口号: $DEL_PORT${NC}"
        return
    fi
    local count=0
    while true; do
        local rule_num
        rule_num=$(iptables -t nat -L PREROUTING --line-numbers -n 2>/dev/null | grep -E "dpt:$DEL_PORT( |$)" | awk '{print $1}' | head -n 1)
        [ -z "$rule_num" ] && break
        iptables -t nat -D PREROUTING "$rule_num" 2>/dev/null || break
        count=$((count + 1))
    done
    if [ "$count" -gt 0 ]; then
        echo "持久化保存 iptables 规则..."
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
        systemctl restart netfilter-persistent.service 2>/dev/null || true
        echo -e "${GREEN}[成功] 已清除 A 机端口 $DEL_PORT 的 $count 条 PREROUTING 规则并已持久化。${NC}"
    else
        echo -e "${YELLOW}未找到端口 $DEL_PORT 对应的 PREROUTING 规则。${NC}"
    fi
}

# ---------- 主菜单 ----------
while true; do
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}    VPS 综合管理脚本 (加固 + 转发 修复版) ${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "  [系统加固]"
    echo -e "  1. 系统加固 (一键更新+端口+密钥+Fail2ban)"
    echo -e "  2. 检查加固状态"
    echo -e "  3. 添加公钥并关闭密码登录"
    echo -e "  4. 设置 SSH IP 白名单"
    echo -e "  5. 开放端口 (UFW)"
    echo -e "  6. 关闭端口 (UFW)"
    echo -e "  [端口转发]"
    echo -e "  7. 配置 DNAT 转发节点 (A 机)"
    echo -e "  8. 配置目标服务节点放行 (B 机)"
    echo -e "  9. 检查转发是否生效"
    echo -e "  10. 删除指定端口转发规则"
    echo -e "  0. 退出"
    echo -e "${BLUE}========================================${NC}"
    echo -ne "请输入数字选择操作: "
    if ! read -r choice; then
        echo -e "\n${GREEN}检测到输入流关闭，退出脚本。${NC}"
        exit 0
    fi
    case "${choice:-}" in
        1) hardening ;;
        2) check_hardening ;;
        3) add_pubkey_disable_pass ;;
        4) set_ssh_whitelist ;;
        5) open_ports ;;
        6) close_ports ;;
        7) configure_A ;;
        8) configure_B ;;
        9) check_forwarding_effectiveness ;;
        10) delete_forwarding_rule ;;
        0) echo -e "${GREEN}退出脚本。${NC}"; exit 0 ;;
        *) echo -e "${RED}无效选择，请重新输入。${NC}"; sleep 1; continue ;;
    esac
    read -rp "按回车键返回菜单..." || exit 0
done
