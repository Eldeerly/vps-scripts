#!/usr/bin/env bash
# ============================================================
#  VPS 综合管理脚本 (中转 / 落地 通用重构版)
#  - 架构解耦：彻底解决 ufw 与 iptables-persistent 互斥卸载问题
#  - 双端适用：支持纯中转机、纯落地机及双角色混合机器
#  - 防火墙隔离：UFW 专注保护 INPUT 链，内核专注 FORWARD 转发
#  - 原子化运维：中转规则增删联动 NAT/FORWARD/持久化
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
    echo -e "${RED}请用 root 权限运行此脚本${NC}"
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo -e "${YELLOW}警告：本脚本依赖 apt-get，仅支持 Debian / Ubuntu 系列发行版。${NC}"
    exit 1
fi

# ============================================================
# 通用校验与辅助工具函数
# ============================================================

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
    hash -r 2>/dev/null || true
    command -v ufw >/dev/null 2>&1 && [ -x "$(command -v ufw)" ]
}

# 精确删除指定端口的 UFW 规则 (倒序删除，防止编号变动)
# 精确删除指定端口的 UFW 规则 (显式清理全网规则 + 倒序删除具体规则)
ufw_delete_port_rules() {
    local port="$1"
    local proto="${2:-}"

    # 1. 显式清除全网放行 (Anywhere) 规则 (双栈 IPv4/IPv6 均能彻底清除)
    if [ -n "$proto" ]; then
        ufw delete allow "$port/$proto" >/dev/null 2>&1 || true
    fi
    ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
    ufw delete allow "$port" >/dev/null 2>&1 || true

    # 2. 倒序删除剩余包含该端口的所有规则 (覆盖白名单规则、自定义注释规则等)
    local rules_to_delete
    if [ -n "$proto" ]; then
        rules_to_delete=$(ufw status numbered 2>/dev/null | grep -E "^\[ *[0-9]+\] +$port(/$proto| )" | awk -F'[][]' '{print $2}' | grep -E '^[0-9]+$' | sort -rn || true)
    else
        rules_to_delete=$(ufw status numbered 2>/dev/null | grep -E "^\[ *[0-9]+\] +$port(/| )" | awk -F'[][]' '{print $2}' | grep -E '^[0-9]+$' | sort -rn || true)
    fi

    if [ -n "$rules_to_delete" ]; then
        for r_num in $rules_to_delete; do
            ufw --force delete "$r_num" >/dev/null 2>&1 || true
        done
    fi
}

# 安全启用 UFW，防止锁死 SSH (杜绝反向注入全网放行)
safe_enable_ufw() {
    local ssh_p
    ssh_p=$(get_ssh_port)
    local curr_ip=""
    if [ -n "${SSH_CONNECTION:-}" ]; then
        curr_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    fi

    # 优先放行当前管理终端 IP，杜绝盲目放行 Anywhere 导致穿透白名单
    if [ -n "$curr_ip" ] && validate_ip "$curr_ip"; then
        if ! ufw status 2>/dev/null | grep -qE "ALLOW.*$curr_ip.*$ssh_p"; then
            ufw allow from "$curr_ip" to any port "$ssh_p" proto tcp comment 'current-ssh-safety' >/dev/null 2>&1 || true
        fi
    else
        # 仅在无管理会话 IP 且没有任何该端口规则时，才兜底放行
        if ! ufw status 2>/dev/null | grep -qE "$ssh_p(/tcp| )"; then
            ufw allow "$ssh_p/tcp" comment 'SSH-safety' >/dev/null 2>&1 || true
        fi
    fi
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
    ufw --force enable
}

# ============================================================
# 自定义持久化服务 (替代易发生包冲突的 iptables-persistent)
# ============================================================

ensure_persistence_service() {
    mkdir -p /etc/iptables
    if [ ! -f /etc/systemd/system/vps-iptables-rules.service ]; then
        cat << 'EOF' > /etc/systemd/system/vps-iptables-rules.service
[Unit]
Description=VPS iptables NAT and Forwarding Rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'if [ -f /etc/iptables/rules.v4 ]; then /sbin/iptables-restore -n /etc/iptables/rules.v4; fi; if [ -f /etc/iptables/rules.v6 ]; then /sbin/ip6tables-restore -n /etc/iptables/rules.v6; fi'
ExecReload=/bin/sh -c 'if [ -f /etc/iptables/rules.v4 ]; then /sbin/iptables-restore -n /etc/iptables/rules.v4; fi; if [ -f /etc/iptables/rules.v6 ]; then /sbin/ip6tables-restore -n /etc/iptables/rules.v6; fi'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable vps-iptables-rules.service 2>/dev/null || true
    fi
}

save_iptables_rules() {
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    ensure_persistence_service
    systemctl restart vps-iptables-rules.service 2>/dev/null || true
}

# ============================================================
# 模块一：通用安全加固 (中转机 / 落地机通用)
# ============================================================

hardening() {
    echo -e "${YELLOW}===== 开始执行系统安全加固 =====${NC}"

    local NEWPORT="${SSH_PORT:-}"
    if [ -z "$NEWPORT" ]; then
        read -p "请输入新的 SSH 端口 (默认 44644): " NEWPORT
        NEWPORT="${NEWPORT:-44644}"
    fi
    if ! validate_port "$NEWPORT"; then
        echo -e "${RED}错误: SSH 端口 $NEWPORT 无效，必须是 1-65535 的数字${NC}"
        return 1
    fi

    local PUBKEYS_INPUT="${PUBKEYS:-}"
    if [ -z "$PUBKEYS_INPUT" ] && [ ! -s /root/.ssh/authorized_keys ]; then
        echo -e "未检测到现有公钥，请输入您的 SSH 公钥 (直接回车保留密码登录):"
        read -r PUBKEYS_INPUT
    fi

    local WHITELIST_INPUT="${SSH_WHITELIST:-}"
    if [ -z "$WHITELIST_INPUT" ]; then
        echo -e "是否配置 SSH 限制白名单 IP？(留空则允许全网访问该 SSH 端口):"
        read -r WHITELIST_INPUT
    fi

    (
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq 2>/dev/null || apt-get update
        apt-get install -y ca-certificates curl wget git htop net-tools traceroute ufw fail2ban earlyoom unattended-upgrades python3-systemd

        ARCH=$(dpkg --print-architecture)
        if [ "$ARCH" = "amd64" ] || [ "$ARCH" = "arm64" ]; then
            apt-get install -y "linux-image-$ARCH" || true
        fi

        mkdir -p /root/.ssh && chmod 700 /root/.ssh
        touch /root/.ssh/authorized_keys 2>/dev/null

        if [ -n "$PUBKEYS_INPUT" ]; then
            IFS=',' read -ra _keys <<< "$PUBKEYS_INPUT"
            for _k in "${_keys[@]}"; do
                _k="$(echo "$_k" | xargs)"
                [ -z "$_k" ] && continue
                if validate_pubkey "$_k"; then
                    grep -qF "$_k" /root/.ssh/authorized_keys 2>/dev/null || echo "$_k" >> /root/.ssh/authorized_keys
                else
                    echo -e "${YELLOW}警告: 忽略无效公钥: $_k${NC}"
                fi
            done
        fi

        local HAS_KEY=0
        if [ -s /root/.ssh/authorized_keys ]; then
            HAS_KEY=1
        else
            echo -e "${YELLOW}警告: 未检测到公钥，将保留密码登录${NC}"
        fi
        chmod 600 /root/.ssh/authorized_keys

        SSHD=/etc/ssh/sshd_config
        [ -f "$SSHD" ] && cp "$SSHD" "$SSHD.bak.$(date +%F_%T)"

        sed -i -E '/^[[:space:]]*#?[[:space:]]*Port[[:space:]]+/d' "$SSHD"
        printf 'Port %s\n' "$NEWPORT" >> "$SSHD"

        mkdir -p /etc/ssh/sshd_config.d
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
            echo -e "${RED}SSH 配置测试失败，未重启服务，请检查配置文件${NC}"
            exit 1
        fi

        # 配置 UFW 防火墙
        ufw default deny incoming 2>/dev/null || true
        ufw default allow outgoing 2>/dev/null || true
        ufw_delete_port_rules "$NEWPORT" "tcp"

        if [ -n "$WHITELIST_INPUT" ]; then
            for _ip in $WHITELIST_INPUT; do
                if validate_ip "$_ip"; then
                    if ! ufw status | grep -q "ALLOW.*$_ip.*$NEWPORT/tcp"; then
                        ufw allow from "$_ip" to any port "$NEWPORT" proto tcp comment "ssh-whitelist-$_ip"
                    fi
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

        # 配置 Fail2ban
        mkdir -p /etc/fail2ban
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

        echo "系统安全加固完成。"
        echo "注意：当前 SSH 端口为 $NEWPORT"
        echo "请务必新开终端测试登录：ssh -p $NEWPORT root@<IP>"
    )
}

check_hardening() {
    echo -e "${YELLOW}===== 检查本机安全加固状态 =====${NC}"
    local SSHD_PORT
    SSHD_PORT=$(get_ssh_port)
    echo "当前识别的 SSH 端口: $SSHD_PORT"
    
    if ss -tlnp 2>/dev/null | grep -qE ":$SSHD_PORT "; then
        echo -e "${GREEN}[通过]${NC} SSH 服务已在端口 $SSHD_PORT 正常监听"
    else
        echo -e "${RED}[失败]${NC} 端口 $SSHD_PORT 未处于监听状态，请核查 sshd 状态"
    fi

    if ss -tlnp 2>/dev/null | grep -q ":22 " && [ "$SSHD_PORT" != "22" ]; then
        echo -e "${RED}[警告]${NC} 默认 22 端口仍在监听"
    else
        echo -e "${GREEN}[通过]${NC} 默认 22 端口已关闭或已被替换"
    fi

    local PASS_AUTH ROOT_LOGIN PUBKEY_AUTH
    PASS_AUTH=$(sshd -T 2>/dev/null | awk '/^passwordauthentication /{print $2}' | head -n 1)
    ROOT_LOGIN=$(sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2}' | head -n 1)
    PUBKEY_AUTH=$(sshd -T 2>/dev/null | awk '/^pubkeyauthentication /{print $2}' | head -n 1)

    if [ "$PASS_AUTH" = "no" ]; then
        echo -e "${GREEN}[通过]${NC} PasswordAuthentication 已关闭 (密码登录已禁用)"
    else
        echo -e "${YELLOW}[提示]${NC} PasswordAuthentication 为 $PASS_AUTH"
    fi

    if [ "$ROOT_LOGIN" = "prohibit-password" ] || [ "$ROOT_LOGIN" = "without-password" ] || [ "$ROOT_LOGIN" = "no" ]; then
        echo -e "${GREEN}[通过]${NC} PermitRootLogin 已限制 ($ROOT_LOGIN)"
    else
        echo -e "${YELLOW}[提示]${NC} PermitRootLogin 为 $ROOT_LOGIN"
    fi

    if [ "$PUBKEY_AUTH" = "yes" ]; then
        echo -e "${GREEN}[通过]${NC} PubkeyAuthentication 已启用"
    else
        echo -e "${YELLOW}[警告]${NC} PubkeyAuthentication 为 $PUBKEY_AUTH"
    fi
    
    if ufw_available; then
        if ufw status | grep -q "active"; then
            echo -e "${GREEN}[通过]${NC} UFW 防火墙处于激活状态"
            echo "--- 当前 UFW 规则汇总 ---"
            ufw status numbered 2>/dev/null | sed 's/^/  /'
        else
            echo -e "${YELLOW}[提示]${NC} UFW 防火墙未激活 (若为纯中转机属正常现象)"
        fi
    else
        echo -e "${YELLOW}[提示]${NC} UFW 未安装"
    fi

    if systemctl is-active --quiet fail2ban; then
        echo -e "${GREEN}[通过]${NC} fail2ban 服务正常运行中"
    else
        echo -e "${YELLOW}[提示]${NC} fail2ban 未运行"
    fi
}

add_pubkey_disable_pass() {
    echo -e "${YELLOW}===== 添加公钥并关闭密码登录 =====${NC}"
    echo -e "请粘贴您的 SSH 公钥（一行，以 ssh- 或 ecdsa- 或 ed25519- 等开头）："
    read -r PUBKEY
    if [ -z "$PUBKEY" ] || ! validate_pubkey "$PUBKEY"; then
        echo -e "${RED}未输入公钥或公钥格式无效，操作取消。${NC}"
        return 1
    fi

    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys
    if grep -qF "$PUBKEY" /root/.ssh/authorized_keys; then
        echo "公钥已存在，无需重复追加。"
    else
        echo "$PUBKEY" >> /root/.ssh/authorized_keys
        echo "公钥已添加至 ~/.ssh/authorized_keys。"
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

    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
Port $CURRENT_PORT
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin prohibit-password
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
EOF

    if sshd -t; then
        systemctl restart ssh 2>/dev/null || systemctl restart sshd
        echo -e "${GREEN}密码登录已关闭，公钥认证已启用。当前 SSH 端口: $CURRENT_PORT${NC}"
        echo "请务必新开终端测试密钥登录是否正常！"
    else
        echo -e "${RED}SSH 配置测试失败，未重启服务，请检查配置文件。${NC}"
        return 1
    fi
}

set_ssh_whitelist() {
    echo -e "${YELLOW}===== 设置 SSH 访问控制 (白名单 / 全网开放) =====${NC}"
    if ! ufw_available; then
        echo -e "${RED}错误：UFW 未安装。${NC}"
        return 1
    fi
    if ! ufw status | grep -q "active"; then
        echo -e "${YELLOW}警告：UFW 未启用。是否现在安全启用？(y/N)${NC}"
        read -r enable_ufw
        if [[ "$enable_ufw" =~ ^[Yy]$ ]]; then
            safe_enable_ufw
        else
            echo "已取消。"
            return 0
        fi
    fi

    local SSH_PORT
    SSH_PORT=$(get_ssh_port)
    echo -e "当前 SSH 端口: $SSH_PORT"
    echo -e "请输入允许访问 SSH 的白名单 IP（多个用空格分隔）："
    echo -e "  - 输入一个或多个 IP：仅放行这些 IP（白名单模式）"
    echo -e "  - 输入 ${CYAN}all${NC} 或 ${CYAN}any${NC}：恢复全网开放该端口 (关闭白名单)"
    read -r IPS
    if [ -z "$IPS" ]; then
        echo -e "${RED}未输入任何内容，操作取消。${NC}"
        return 1
    fi

    local CURRENT_IP
    CURRENT_IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')

    # 支持一键切换回全网开放
    if [ "$IPS" = "all" ] || [ "$IPS" = "any" ]; then
        read -p "确认清除当前白名单，恢复全网开放 SSH 端口 $SSH_PORT？(y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            echo "已取消。"
            return 0
        fi
        ufw_delete_port_rules "$SSH_PORT" "tcp"
        ufw allow "$SSH_PORT/tcp" comment 'SSH'
        ufw reload
        echo -e "${GREEN}已恢复全网开放 SSH 端口 $SSH_PORT。${NC}"
        return 0
    fi

    echo -e "${YELLOW}当前连接 IP: ${CURRENT_IP:-未知}，将强制放行防失联。${NC}"
    read -p "确认清空旧规则并应用新的白名单？(y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消。"
        return 0
    fi

    ufw_delete_port_rules "$SSH_PORT" "tcp"

    for ip in $IPS; do
        if validate_ip "$ip"; then
            if ! ufw status | grep -q "ALLOW.*$ip.*$SSH_PORT/tcp"; then
                ufw allow from "$ip" to any port "$SSH_PORT" proto tcp comment "ssh-whitelist-$ip"
                echo "已添加白名单 IP: $ip"
            fi
        else
            echo -e "${YELLOW}忽略无效 IP: $ip${NC}"
        fi
    done

    if [ -n "$CURRENT_IP" ] && validate_ip "$CURRENT_IP"; then
        if ! ufw status | grep -q "ALLOW.*$CURRENT_IP.*$SSH_PORT/tcp"; then
            ufw allow from "$CURRENT_IP" to any port "$SSH_PORT" proto tcp comment 'current-ssh-session'
            echo "已自动放行当前连接 IP: $CURRENT_IP"
        fi
    fi

    ufw reload
    echo -e "${GREEN}SSH 白名单设置完成，旧的全网放行规则已清除。${NC}"
}

open_ports() {
    echo -e "${YELLOW}===== 开放本地端口 (UFW) =====${NC}"
    if ! ufw_available; then
        echo -e "${RED}错误：UFW 未安装。${NC}"
        return 1
    fi
    if ! ufw status | grep -q "active"; then
        echo -e "${YELLOW}警告：UFW 未启用。是否现在安全启用？(y/N)${NC}"
        read -r enable_ufw
        if [[ "$enable_ufw" =~ ^[Yy]$ ]]; then
            safe_enable_ufw
        else
            echo "已取消。"
            return 0
        fi
    fi
    echo -e "请输入要全局开放的本地服务端口（空格分隔，例如 80 443）："
    read -r PORTS
    if [ -z "$PORTS" ]; then
        echo -e "${RED}未输入端口，操作取消。${NC}"
        return 1
    fi
    for p in $PORTS; do
        if validate_port "$p"; then
            if ! ufw status | grep -q "ALLOW.*$p/tcp"; then
                ufw allow "$p/tcp" comment "open-$p" || true
                echo "已开放 TCP 端口 $p"
            else
                echo "端口 $p 已处于开放状态，跳过"
            fi
        else
            echo "无效端口: $p，已跳过"
        fi
    done
    ufw reload
}

close_ports() {
    echo -e "${YELLOW}===== 关闭/删除 UFW 规则 =====${NC}"
    if ! ufw_available; then
        echo -e "${RED}错误：UFW 未安装。${NC}"
        return 1
    fi
    if ! ufw status | grep -q "active"; then
        echo -e "${YELLOW}警告：UFW 未启用。${NC}"
        return 1
    fi
    local SSH_PORT
    SSH_PORT=$(get_ssh_port)
    echo "当前 UFW 规则列表:"
    ufw status numbered
    echo -e "请输入要删除的规则编号（多个用空格分隔），或输入 0 取消："
    read -r RULES
    if [ -z "$RULES" ] || [ "$RULES" = "0" ]; then
        echo "操作取消。"
        return 0
    fi
    for num in $RULES; do
        if [[ "$num" =~ ^[0-9]+$ ]]; then
            local rule_line
            rule_line=$(ufw status numbered | grep -E "^\[ *$num\]" || true)
            if echo "$rule_line" | grep -q "$SSH_PORT"; then
                echo -e "${RED}[高危警告] 编号 $num 包含当前 SSH 端口 ($SSH_PORT)，误删会导致失联！${NC}"
            fi
        fi
    done
    read -p "确认删除所选规则？(y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "已取消删除。"
        return 0
    fi
    local sorted_rules
    sorted_rules=$(echo "$RULES" | tr ' ' '\n' | grep -E '^[0-9]+$' | sort -rn | uniq)
    for num in $sorted_rules; do
        ufw --force delete "$num"
        echo "已删除规则: $num"
    done
    ufw reload
}

# ============================================================
# 模块二：中转机功能 (DNAT 转发体系)
# ============================================================

precheck_relay() {
    echo -e "${YELLOW}===== 预检查中转网络环境 =====${NC}"

    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "${YELLOW}[安装] 安装 iptables...${NC}"
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq && apt-get install -y iptables
    fi

    if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
        echo -e "${YELLOW}[优化] 开启 IPv4 内核转发...${NC}"
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
        sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
        echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
        echo -e "${GREEN}[完成] IP 转发已开启并持久化${NC}"
    else
        echo -e "${GREEN}[通过] IP 转发已处于启用状态${NC}"
    fi

    # 若安装了 UFW，保障 FORWARD 策略为 ACCEPT (不影响 UFW INPUT 拦截)
    if ufw_available && [ -f /etc/default/ufw ]; then
        if grep -q '^DEFAULT_FORWARD_POLICY="DROP"' /etc/default/ufw; then
            echo -e "${YELLOW}[调整] 设置 UFW 转发策略为 ACCEPT...${NC}"
            sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
            ufw reload >/dev/null 2>&1 || true
            echo -e "${GREEN}[完成] UFW 转发通道已放行${NC}"
        fi
    fi

    # 确保原生 iptables FORWARD 链默认放行已建立连接
    iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    ensure_persistence_service
    echo -e "${GREEN}===== 预检查完成 =====${NC}"
}

configure_relay() {
    echo -e "${YELLOW}===== 配置 DNAT 中转转发 (当前为中转机) =====${NC}"
    precheck_relay

    read -p "请输入目标落地机 IP 地址: " B_IP
    if ! validate_ip "$B_IP"; then
        echo -e "${RED}无效的目标 IP: $B_IP${NC}"
        return 1
    fi

    read -p "请输入转发协议 PROTO (tcp/udp, 默认 tcp): " PROTO
    PROTO=${PROTO:-tcp}
    if ! validate_proto "$PROTO"; then
        echo -e "${RED}无效协议: $PROTO${NC}"
        return 1
    fi

    echo -e "${YELLOW}请输入转发端口映射，格式: 本机中转端口[:目标落地端口] ...${NC}"
    echo -e "  例 1: 8443 (同端口映射，8443 -> $B_IP:8443)"
    echo -e "  例 2: 2054:2053 (异端口映射，2054 -> $B_IP:2053)"
    read -p "端口映射列表: " RULES_INPUT
    if [ -z "$RULES_INPUT" ]; then
        echo -e "${RED}未输入任何端口映射，操作取消。${NC}"
        return 1
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
            echo -e "${RED}无效端口格式: $item，已忽略${NC}"
            continue
        fi

        # 端口冲突检测：避免抢占本机已运行的服务
        if ss -tlnp 2>/dev/null | grep -qE ":$A_PORT "; then
            echo -e "${RED}[冲突警告] 本机已有服务正在监听端口 $A_PORT，该端口无法作为中转端口！已忽略。${NC}"
            continue
        fi

        MAPPINGS+=("$A_PORT:$B_PORT")
    done

    if [ ${#MAPPINGS[@]} -eq 0 ]; then
        echo -e "${RED}无有效且空闲的中转端口，操作终止。${NC}"
        return 1
    fi

    echo -e "${YELLOW}开始应用并持久化 DNAT 转发规则...${NC}"

    for mapping in "${MAPPINGS[@]}"; do
        A_PORT="${mapping%%:*}"
        B_PORT="${mapping##*:}"

        # 1. 倒序深度清理该 A_PORT 上所有的旧 PREROUTING 规则 (避免编号位移导致残留)
        local existing_rules
        existing_rules=$(iptables -t nat -L PREROUTING --line-numbers -n 2>/dev/null | grep -E "dpt:$A_PORT( |$)" | awk '{print $1}' | grep -E '^[0-9]+$' | sort -rn || true)
        if [ -n "$existing_rules" ]; then
            for r in $existing_rules; do
                iptables -t nat -D PREROUTING "$r" 2>/dev/null || true
            done
        fi

        # 2. 清理可能残留的相同目标 POSTROUTING 与 FORWARD 规则
        iptables -t nat -D POSTROUTING -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j ACCEPT 2>/dev/null || true

        # 3. 写入新的 PREROUTING、POSTROUTING、FORWARD 规则
        if ! iptables -t nat -C PREROUTING -p "$PROTO" --dport "$A_PORT" -j DNAT --to-destination "$B_IP:$B_PORT" 2>/dev/null; then
            iptables -t nat -A PREROUTING -p "$PROTO" --dport "$A_PORT" -j DNAT --to-destination "$B_IP:$B_PORT"
        fi
        if ! iptables -t nat -C POSTROUTING -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE 2>/dev/null; then
            iptables -t nat -A POSTROUTING -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j MASQUERADE
        fi
        if ! iptables -C FORWARD -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j ACCEPT 2>/dev/null; then
            iptables -I FORWARD 2 -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j ACCEPT
        fi

        echo "已生效: 本机 $A_PORT -> $B_IP:$B_PORT ($PROTO)"
    done

    save_iptables_rules
    check_relay_success "$B_IP" "$PROTO" "${MAPPINGS[@]}"
}

check_relay_success() {
    local B_IP=$1 PROTO=$2
    shift 2
    local mappings=("$@")
    echo -e "${YELLOW}===== 验证中转规则生效情况 =====${NC}"

    local nat_rules
    nat_rules=$(iptables-save -t nat)
    local all_ok=true

    for mapping in "${mappings[@]}"; do
        local A_PORT="${mapping%%:*}"
        local B_PORT="${mapping##*:}"

        if echo "$nat_rules" | grep -qE -- "-A PREROUTING -p $PROTO -m $PROTO --dport $A_PORT -j DNAT --to-destination $B_IP(:$B_PORT)?"; then
            echo -e "${GREEN}[通过] PREROUTING 规则正常: $A_PORT -> $B_IP:$B_PORT${NC}"
        else
            echo -e "${RED}[失败] PREROUTING 规则缺失: $A_PORT${NC}"
            all_ok=false
        fi

        if echo "$nat_rules" | grep -qE -- "-A POSTROUTING -d $B_IP(/32)? -p $PROTO -m $PROTO --dport $B_PORT -j MASQUERADE"; then
            echo -e "${GREEN}[通过] POSTROUTING MASQUERADE 正常${NC}"
        else
            echo -e "${RED}[失败] POSTROUTING MASQUERADE 缺失${NC}"
            all_ok=false
        fi

        if iptables -C FORWARD -p "$PROTO" -d "$B_IP" --dport "$B_PORT" -j ACCEPT 2>/dev/null; then
            echo -e "${GREEN}[通过] FORWARD 链放行正常${NC}"
        else
            echo -e "${RED}[失败] FORWARD 链放行缺失${NC}"
            all_ok=false
        fi
    done

    if [ "$all_ok" = true ]; then
        echo -e "${GREEN}===== 验证通过：所选中转规则配置完毕且已持久化 =====${NC}"
    else
        echo -e "${RED}===== 部分规则异常，请排查 =====${NC}"
    fi
}

check_forwarding_effectiveness() {
    echo -e "${YELLOW}===== 检查本机中转有效性与网络链路 =====${NC}"

    if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
        echo -e "${RED}[失败] 系统未启用 IP 转发${NC}"
        return 1
    fi

    local DNAT_LINES
    DNAT_LINES=$(iptables-save -t nat | grep -- "-A PREROUTING .* -j DNAT" || true)
    if [ -z "$DNAT_LINES" ]; then
        echo -e "${YELLOW}当前未检测到任何正在生效的 DNAT 转发规则。${NC}"
        return 0
    fi

    echo -e "${GREEN}发现生效中的 DNAT 规则：${NC}"
    echo "$DNAT_LINES"

    echo -e "${YELLOW}正在检测至目标落地节点的端口可达性...${NC}"
    local overall_success=true

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        
        local b_ip b_port proto_used
        b_ip=$(echo "$line" | sed -n 's/.*--to-destination \([0-9.]*\).*/\1/p' | cut -d':' -f1)
        b_port=$(echo "$line" | sed -n 's/.*--to-destination [0-9.]*:\([0-9]*\).*/\1/p')
        if [ -z "$b_port" ]; then
            b_port=$(echo "$line" | sed -n 's/.*--dport \([0-9]*\).*/\1/p')
        fi

        if [ -z "$b_ip" ] || [ -z "$b_port" ]; then
            continue
        fi

        proto_used=$(echo "$line" | sed -n 's/.*-p \([a-z0-9]*\).*/\1/p')
        proto_used=${proto_used:-tcp}

        if [ "$proto_used" = "udp" ]; then
            echo -e "${YELLOW}[跳过] UDP 规则 (${b_ip}:${b_port})，不支持 TCP 握手探针。${NC}"
            continue
        fi

        # 解决 set -u 下变量后接标点导致解析崩溃的问题
        if timeout 3 bash -c "echo > /dev/tcp/${b_ip}/${b_port}" 2>/dev/null; then
            echo -e "${GREEN}[通过] 到目标 ${b_ip}:${b_port} 的网络握手成功${NC}"
        elif command -v nc >/dev/null 2>&1 && nc -z -w 3 "$b_ip" "$b_port" >/dev/null 2>&1; then
            echo -e "${GREEN}[通过] 到目标 ${b_ip}:${b_port} 的网络握手成功${NC}"
        else
            echo -e "${RED}[失败] 无法连通目标 ${b_ip}:${b_port}，请排查落地机防火墙/安全组或服务监听状态${NC}"
            overall_success=false
        fi
    done <<< "$DNAT_LINES"

    if [ "$overall_success" = true ]; then
        echo -e "${GREEN}===== 检查完成：全部转发链路通畅 =====${NC}"
    else
        echo -e "${RED}===== 检查完成：存在异常链路项 =====${NC}"
    fi
}

delete_forwarding_rule() {
    echo -e "${YELLOW}===== 删除指定端口中转规则 (原子化清理) =====${NC}"
    local DNAT_LINES
    DNAT_LINES=$(iptables-save -t nat | grep -- "-A PREROUTING .* -j DNAT" || true)
    if [ -z "$DNAT_LINES" ]; then
        echo -e "${YELLOW}当前未检测到任何 DNAT 转发规则。${NC}"
        return 0
    fi

    echo "当前正在生效的 DNAT 规则："
    iptables -t nat -L PREROUTING --line-numbers -n -v | grep -E "DNAT|Chain"
    echo ""
    read -p "请输入要删除的本机监听中转端口 (例如 2054): " DEL_PORT
    if ! validate_port "$DEL_PORT"; then
        echo -e "${RED}无效端口号: $DEL_PORT${NC}"
        return 1
    fi

    # 提取该端口对应的目标 IP 与目标端口，以便联动清理 POSTROUTING 与 FORWARD
    local matched_lines
    matched_lines=$(echo "$DNAT_LINES" | grep -E -- "--dport $DEL_PORT " || true)
    if [ -z "$matched_lines" ]; then
        echo -e "${YELLOW}未找到中转端口 $DEL_PORT 对应的规则。${NC}"
        return 0
    fi

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local t_ip t_port t_proto
        t_ip=$(echo "$line" | sed -n 's/.*--to-destination \([0-9.]*\).*/\1/p' | cut -d':' -f1)
        t_port=$(echo "$line" | sed -n 's/.*--to-destination [0-9.]*:\([0-9]*\).*/\1/p')
        t_proto=$(echo "$line" | sed -n 's/.*-p \([a-z0-9]*\).*/\1/p')
        t_proto=${t_proto:-tcp}

        if [ -z "$t_port" ]; then
            t_port="$DEL_PORT"
        fi

        # 联动清理 POSTROUTING MASQUERADE
        if [ -n "$t_ip" ] && [ -n "$t_port" ]; then
            iptables -t nat -D POSTROUTING -p "$t_proto" -d "$t_ip" --dport "$t_port" -j MASQUERADE 2>/dev/null || true
            iptables -D FORWARD -p "$t_proto" -d "$t_ip" --dport "$t_port" -j ACCEPT 2>/dev/null || true
        fi
    done <<< "$matched_lines"

    # 清理 PREROUTING 规则
    local existing_rules
    existing_rules=$(iptables -t nat -L PREROUTING --line-numbers -n 2>/dev/null | grep -E "dpt:$DEL_PORT( |$)" | awk '{print $1}' | grep -E '^[0-9]+$' | sort -rn || true)
    local count=0
    if [ -n "$existing_rules" ]; then
        for r in $existing_rules; do
            iptables -t nat -D PREROUTING "$r" 2>/dev/null || true
            count=$((count + 1))
        done
    fi

    save_iptables_rules
    echo -e "${GREEN}[成功] 已完整清理中转端口 $DEL_PORT 的 NAT 与 FORWARD 链规则，并已持久化保存。${NC}"
}

# ============================================================
# 模块三：落地机功能 (防火墙白名单与源站隐身)
# ============================================================

configure_landing() {
    echo -e "${YELLOW}===== 配置落地节点入站安全放行 (当前为落地机) =====${NC}"

    read -p "请输入中转机的公网 IP 地址: " RELAY_IP
    if ! validate_ip "$RELAY_IP"; then
        echo -e "${RED}无效中转机 IP: $RELAY_IP${NC}"
        return 1
    fi

    read -p "请输入本机需要对该中转机开放的业务端口 (空格分隔，例如 8443 2053): " B_PORTS_INPUT
    if [ -z "$B_PORTS_INPUT" ]; then
        echo -e "${RED}未输入端口，操作取消。${NC}"
        return 1
    fi

    read -p "请输入协议 PROTO (tcp/udp, 默认 tcp): " PROTO
    PROTO=${PROTO:-tcp}
    if ! validate_proto "$PROTO"; then
        echo -e "${RED}无效协议: $PROTO${NC}"
        return 1
    fi

    read -ra B_PORTS <<< "$B_PORTS_INPUT"
    local valid_ports=()
    for p in "${B_PORTS[@]}"; do
        if validate_port "$p"; then
            valid_ports+=("$p")
        fi
    done

    if [ ${#valid_ports[@]} -eq 0 ]; then
        echo -e "${RED}没有有效的端口，操作取消。${NC}"
        return 1
    fi

    echo -e "${YELLOW}开始应用落地入站白名单...${NC}"

    if ufw_available && ufw status | grep -q "active"; then
        for p in "${valid_ports[@]}"; do
            # 如果该业务端口此前存在全网放行 (Anywhere)，清理之以防止穿透击穿落地源站隐身
            if ufw status 2>/dev/null | grep -E "^\[ *[0-9]+\] +$p(/$PROTO| ) " | grep -q "Anywhere"; then
                echo -e "${YELLOW}[检测] 业务端口 $p 存在全网放行 (Anywhere)，正在清理以保障仅中转机可达...${NC}"
                ufw delete allow "$p/$PROTO" >/dev/null 2>&1 || true
                ufw delete allow "$p" >/dev/null 2>&1 || true
            fi
            if ! ufw status | grep -qE "ALLOW.*$RELAY_IP.*$p/$PROTO"; then
                ufw allow from "$RELAY_IP" to any port "$p" proto "$PROTO" comment "from-relay-$RELAY_IP" || true
                echo "UFW 已放行: $p/$PROTO 仅限来自 $RELAY_IP"
            fi
        done
        ufw reload
    else
        for p in "${valid_ports[@]}"; do
            if ! iptables -C INPUT -p "$PROTO" -s "$RELAY_IP" --dport "$p" -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p "$PROTO" -s "$RELAY_IP" --dport "$p" -j ACCEPT
                echo "iptables 已放行: $p/$PROTO 仅限来自 $RELAY_IP"
            fi
        done
        save_iptables_rules
    fi

    echo -e "${GREEN}===== 落地节点放行配置完毕 =====${NC}"
    echo "后端业务监听状态检查："
    for port in "${valid_ports[@]}"; do
        if [ "$PROTO" = "tcp" ]; then
            if ss -tlnp 2>/dev/null | grep -qE ":$port "; then
                echo -e "${GREEN}[通过] 本机 TCP 端口 $port 处于监听状态${NC}"
            else
                echo -e "${YELLOW}[提示] 本机 TCP 端口 $port 当前未监听，请确认后端服务已启动${NC}"
            fi
        else
            if ss -ulnp 2>/dev/null | grep -qE ":$port "; then
                echo -e "${GREEN}[通过] 本机 UDP 端口 $port 处于监听状态${NC}"
            else
                echo -e "${YELLOW}[提示] 本机 UDP 端口 $port 当前未监听，请确认后端服务已启动${NC}"
            fi
        fi
    done
}

delete_landing_whitelist() {
    echo -e "${YELLOW}===== 移除落地机指定放行规则 =====${NC}"
    read -p "请输入要移除的中转机 IP: " RELAY_IP
    if ! validate_ip "$RELAY_IP"; then
        echo -e "${RED}无效 IP: $RELAY_IP${NC}"
        return 1
    fi

    if ufw_available && ufw status | grep -q "active"; then
        local del_rules
        del_rules=$(ufw status numbered 2>/dev/null | grep "$RELAY_IP" | awk -F'[][]' '{print $2}' | grep -E '^[0-9]+$' | sort -rn || true)
        if [ -n "$del_rules" ]; then
            for r in $del_rules; do
                ufw --force delete "$r" >/dev/null 2>&1 || true
            done
            ufw reload
            echo -e "${GREEN}已清理 UFW 中关于 $RELAY_IP 的放行规则。${NC}"
        else
            echo -e "${YELLOW}UFW 中未找到来自 $RELAY_IP 的规则。${NC}"
        fi
    else
        while true; do
            local r_num
            r_num=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep "$RELAY_IP" | awk '{print $1}' | head -n 1)
            [ -z "$r_num" ] && break
            iptables -D INPUT "$r_num" 2>/dev/null || break
        done
        save_iptables_rules
        echo -e "${GREEN}已清理 iptables INPUT 中来自 $RELAY_IP 的规则。${NC}"
    fi
}

# ============================================================
# 模块四：网络吞吐优化 (BBR)
# ============================================================

enable_bbr() {
    echo -e "${YELLOW}===== 开启 BBR 拥塞控制与网络优化 =====${NC}"
    local current_cc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    if [ "$current_cc" = "bbr" ] || [ "$current_cc" = "bbrv3" ]; then
        echo -e "${GREEN}[通过] 当前已启用 $current_cc 拥塞控制算法${NC}"
        return 0
    fi

    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true

    local new_cc
    new_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    if [ "$new_cc" = "bbr" ] || [ "$new_cc" = "bbrv3" ]; then
        echo -e "${GREEN}[成功] BBR 拥塞控制已开启生效！${NC}"
    else
        echo -e "${YELLOW}[提示] 当前内核未直接生效 BBR (当前: $new_cc)，可能需要升级内核或重启。${NC}"
    fi
}

# ============================================================
# 主菜单
# ============================================================

while true; do
    echo -e ""
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}           VPS 综合管理脚本 (中转 / 落地 通用版)            ${NC}"
    echo -e "${BLUE}============================================================${NC}"
    echo -e "  ${CYAN}【基础安全加固】 (中转机与落地机通用)${NC}"
    echo -e "  1. 一键安全加固 (修改SSH端口+密钥登录+Fail2ban+系统更新)"
    echo -e "  2. 检查本机基础加固状态"
    echo -e "  3. 添加公钥并关闭密码登录"
    echo -e "  4. 设置 SSH 来源 IP 白名单"
    echo -e "  5. 开放本地业务端口 (UFW)"
    echo -e "  6. 关闭/删除本地规则 (UFW)"
    echo -e ""
    echo -e "  ${CYAN}【中转节点功能】 (流量转发专用)${NC}"
    echo -e "  7. 配置 DNAT 端口转发规则"
    echo -e "  8. 检查本机中转规则与目标链路可用性"
    echo -e "  9. 删除指定端口转发规则 (原子化联动清理)"
    echo -e ""
    echo -e "  ${CYAN}【落地节点功能】 (业务服务与源站安全)${NC}"
    echo -e "  10. 仅放行中转机访问本机业务端口 (源站隐身)"
    echo -e "  11. 移除针对指定中转机的放行规则"
    echo -e ""
    echo -e "  ${CYAN}【系统与网络优化】${NC}"
    echo -e "  12. 开启 BBR 拥塞控制"
    echo -e "  0.  退出脚本"
    echo -e "${BLUE}============================================================${NC}"
    echo -ne "请输入数字选择操作: "
    if ! read -r choice; then
        echo -e "\n${GREEN}检测到输入流断开，退出脚本。${NC}"
        exit 0
    fi
    case "${choice:-}" in
        1) hardening ;;
        2) check_hardening ;;
        3) add_pubkey_disable_pass ;;
        4) set_ssh_whitelist ;;
        5) open_ports ;;
        6) close_ports ;;
        7) configure_relay ;;
        8) check_forwarding_effectiveness ;;
        9) delete_forwarding_rule ;;
        10) configure_landing ;;
        11) delete_landing_whitelist ;;
        12) enable_bbr ;;
        0) echo -e "${GREEN}退出脚本。${NC}"; exit 0 ;;
        *) echo -e "${RED}无效选择，请重新输入。${NC}"; sleep 1; continue ;;
    esac
    echo ""
    read -rp "按回车键返回菜单..." || exit 0
done
