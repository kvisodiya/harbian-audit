cat > /opt/start.sh << 'EOF'
#!/usr/bin/env bash
###############################################################################
# start.sh — Harbian-Audit Level 5: Install, Configure, Audit, Apply, Reboot
#             Safe for fresh SSH VPS (Debian/Ubuntu)
###############################################################################
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo ./start.sh"

LOGFILE="/var/log/harbian-audit-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1
info "Logging to $LOGFILE"

export DEBIAN_FRONTEND=noninteractive

###############################################################################
# PHASE 1 — DETECT SSH PORT & PROTECT IT
###############################################################################
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "PHASE 1: Detect & protect SSH"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | grep -oP '\d+$' | head -1)
SSH_PORT=${SSH_PORT:-22}
info "SSH port: $SSH_PORT"

# Backup original sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.BACKUP.$(date +%s) 2>/dev/null || true

# Safety drop-in — loaded first, keeps SSH alive no matter what
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-safety.conf << 'SSHCFG'
# ── Hardening safety net — review after hardening ──
Port 22
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
UsePAM yes
ClientAliveInterval 60
ClientAliveCountMax 120
TCPKeepAlive yes
MaxAuthTries 6
MaxSessions 10
X11Forwarding no
Protocol 2
Subsystem sftp /usr/lib/openssh/sftp-server
SSHCFG

# Validate and reload
if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    ok "SSH safety config applied"
else
    warn "sshd -t failed, removing drop-in"
    rm -f /etc/ssh/sshd_config.d/00-safety.conf
fi

# Firewall — make sure SSH is NEVER blocked
iptables  -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || true
ip6tables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || true
iptables  -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
ip6tables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables  -I INPUT 1 -i lo -j ACCEPT 2>/dev/null || true

ok "Firewall: SSH port $SSH_PORT is open"

###############################################################################
# PHASE 2 — INSTALL BASE PACKAGES (fresh system)
###############################################################################
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "PHASE 2: Installing essential packages"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

apt-get update -y
apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

PKGS=(
    # Core tools
    git curl wget vim nano htop tmux screen unzip zip bc jq
    build-essential ca-certificates gnupg lsb-release
    software-properties-common apt-transport-https
    sudo passwd procps psmisc pciutils usbutils

    # Networking
    openssh-server net-tools iproute2 dnsutils iputils-ping
    traceroute tcpdump nmap iptables nftables

    # Security — required by harbian-audit
    auditd audispd-plugins
    libpam-pwquality libpam-tmpdir
    apparmor apparmor-profiles apparmor-profiles-extra apparmor-utils
    aide
    fail2ban
    rkhunter chkrootkit
    acl debsums needrestart
    rsyslog sysstat logrotate cron

    # Persistence
    iptables-persistent
)

info "Installing ${#PKGS[@]} packages..."
for pkg in "${PKGS[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        ok "  $pkg (already installed)"
    else
        if apt-get install -y -o Dpkg::Options::="--force-confdef" \
                              -o Dpkg::Options::="--force-confold" \
                              "$pkg" &>/dev/null; then
            ok "  $pkg"
        else
            warn "  $pkg (unavailable — skipped)"
        fi
    fi
done

# Enable core services
systemctl enable --now ssh      2>/dev/null || systemctl enable --now sshd 2>/dev/null || true
systemctl enable --now auditd   2>/dev/null || true
systemctl enable --now apparmor 2>/dev/null || true
systemctl enable --now rsyslog  2>/dev/null || true
systemctl enable --now cron     2>/dev/null || true
systemctl enable --now fail2ban 2>/dev/null || true

ok "Phase 2 complete"

###############################################################################
# PHASE 3 — CLONE HARBIAN-AUDIT
###############################################################################
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "PHASE 3: Clone harbian-audit"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -d /opt/harbian-audit/.git ]; then
    info "Repo already exists at /opt/harbian-audit — pulling latest"
    cd /opt/harbian-audit && git pull || true
else
    info "Cloning fresh..."
    rm -rf /opt/harbian-audit
    git clone https://github.com/hardenedlinux/harbian-audit.git /opt/harbian-audit
fi

cd /opt/harbian-audit
ok "Repo ready at /opt/harbian-audit"

###############################################################################
# PHASE 4 — BOOTSTRAP CONFIG (the critical part you showed)
###############################################################################
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "PHASE 4: Bootstrap /etc/default/cis-hardening"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Copy default config
cp /opt/harbian-audit/debian/default /etc/default/cis-hardening
ok "Copied debian/default → /etc/default/cis-hardening"

# Patch all paths to point at /opt/harbian-audit
sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='/opt/harbian-audit/lib'#"           /etc/default/cis-hardening
sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='/opt/harbian-audit/bin/hardening'#" /etc/default/cis-hardening
sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='/opt/harbian-audit/etc'#"         /etc/default/cis-hardening
sed -i "s#CIS_TMP_DIR=.*#CIS_TMP_DIR='/opt/harbian-audit/tmp'#"           /etc/default/cis-hardening

# This line may or may not exist in all versions — add if missing
grep -q "CIS_VERSIONS_DIR" /etc/default/cis-hardening && \
    sed -i "s#CIS_VERSIONS_DIR=.*#CIS_VERSIONS_DIR='/opt/harbian-audit/versions'#" /etc/default/cis-hardening || \
    echo "CIS_VERSIONS_DIR='/opt/harbian-audit/versions'" >> /etc/default/cis-hardening

ok "Paths configured:"
cat /etc/default/cis-hardening | grep -E "^CIS_" | while read line; do
    echo "    $line"
done

# Create tmp dir if missing
mkdir -p /opt/harbian-audit/tmp

# Make scripts executable
chmod +x /opt/harbian-audit/bin/hardening.sh
find /opt/harbian-audit/bin/hardening/ -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

ok "Phase 4 complete — config bootstrapped"

###############################################################################
# PHASE 5 — SET LEVEL 5 + AUDIT
###############################################################################
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "PHASE 5: Set hardening level 5 + AUDIT (read-only)"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd /opt/harbian-audit

AUDIT_LOG="/var/log/harbian-AUDIT-$(date +%Y%m%d-%H%M%S).log"

./bin/hardening.sh --set-hardening-level 5 --audit 2>&1 | tee "$AUDIT_LOG"

ok "Audit complete → $AUDIT_LOG"

###############################################################################
# PHASE 6 — APPLY HARDENING LEVEL 5
###############################################################################
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "PHASE 6: APPLY hardening level 5"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

warn "Applying in 10 seconds... (Ctrl+C to cancel)"
warn "SSH will remain accessible on port $SSH_PORT"
sleep 10

# ── Safety net: auto-restart SSH in 5 minutes ──
(
    sleep 300
    # Restore SSH no matter what
    cat > /etc/ssh/sshd_config.d/00-safety.conf << 'EMERGENCY'
Port 22
PermitRootLogin yes
PasswordAuthentication yes
UsePAM yes
EMERGENCY
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
) &
SAFETY_PID=$!
info "SSH safety timer started (PID $SAFETY_PID) — auto-restores in 5 min"

APPLY_LOG="/var/log/harbian-APPLY-$(date +%Y%m%d-%H%M%S).log"

./bin/hardening.sh --set-hardening-level 5 --apply 2>&1 | tee "$APPLY_LOG"

ok "Apply complete → $APPLY_LOG"

# Kill safety timer — we made it
kill $SAFETY_PID 2>/dev/null || true

###############################################################################
# PHASE 7 — POST-APPLY SSH & FIREWALL RECOVERY
###############################################################################
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "PHASE 7: Post-hardening SSH & firewall fix-up"
info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Re-force SSH safety config
cat > /etc/ssh/sshd_config.d/00-safety.conf << 'SSHFIX'
Port 22
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
UsePAM yes
ClientAliveInterval 60
ClientAliveCountMax 120
TCPKeepAlive yes
Protocol 2
SSHFIX

# Validate and restart
if sshd -t 2>/dev/null; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    ok "SSH restarted — config valid"
else
    warn "sshd -t failed — stripping conflicts from main config"
    sed -i '/^PermitRootLogin/d; /^PasswordAuthentication/d; /^Port /d' /etc/ssh/sshd_config
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
fi

# Re-force firewall
iptables  -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || true
ip6tables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || true
iptables  -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# Save rules
mkdir -p /etc/iptables
iptables-save  > /etc/iptables/rules.v4 2>/dev/null || true
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

ok "Firewall saved"

# Configure fail2ban
cat > /etc/fail2ban/jail.local << 'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 10
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ssh
maxretry = 10
F2B
systemctl restart fail2ban 2>/dev/null || true
ok "fail2ban configured"

###############################################################################
# PHASE 8 — SUMMARY
###############################################################################
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}  ✅  HARBIAN-AUDIT LEVEL 5 — COMPLETE${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  SSH:        $(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null)  (port $SSH_PORT)"
echo -e "  Auditd:     $(systemctl is-active auditd 2>/dev/null)"
echo -e "  AppArmor:   $(systemctl is-active apparmor 2>/dev/null)"
echo -e "  Fail2ban:   $(systemctl is-active fail2ban 2>/dev/null)"
echo ""
echo "  Logs:"
echo "    Audit:   $AUDIT_LOG"
echo "    Apply:   $APPLY_LOG"
echo "    Script:  $LOGFILE"
echo ""
echo -e "  ${YELLOW}After reboot, harden SSH further:${NC}"
echo "    1.  adduser admin && usermod -aG sudo admin"
echo "    2.  ssh-copy-id admin@THIS_VPS"
echo "    3.  Edit /etc/ssh/sshd_config.d/00-safety.conf:"
echo "          PermitRootLogin no"
echo "          PasswordAuthentication no"
echo "    4.  systemctl reload ssh"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

info "Rebooting in 30 seconds... (Ctrl+C to cancel)"
sleep 30
reboot

EOF
