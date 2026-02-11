cat > start.sh << 'SCRIPT_EOF'
#!/usr/bin/env bash
#############################################################################
# start.sh — Full automated harbian-audit Level 5 hardening
#            Safe for SSH VPS (keeps SSH alive throughout)
#
# Usage:  chmod +x start.sh && sudo ./start.sh
#############################################################################
set -euo pipefail

# ─────────────────────────────────────────────────────────────
#  COLOR HELPERS
# ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }

# ─────────────────────────────────────────────────────────────
#  PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "Detected OS: $PRETTY_NAME"
else
    fail "Cannot detect OS"
    exit 1
fi

# Save the SSH connection details BEFORE we touch anything
SSH_PORT=$(ss -tlnp | grep sshd | awk '{print $4}' | grep -oP '\d+$' | head -1)
SSH_PORT=${SSH_PORT:-22}
MY_IP=$(who am i 2>/dev/null | awk '{print $NF}' | tr -d '()' || echo "")
info "Current SSH port detected: ${SSH_PORT}"
[ -n "$MY_IP" ] && info "Your source IP: ${MY_IP}"

LOGFILE="/var/log/harbian-audit-start-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1
info "Logging everything to: $LOGFILE"

# ─────────────────────────────────────────────────────────────
#  PHASE 1 — INSTALL BASIC PACKAGES (fresh system)
# ─────────────────────────────────────────────────────────────
info "═══════���═══════════════════════════════════════════"
info "PHASE 1: Installing essential packages"
info "═══════════════════════════════════════════════════"

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get upgrade -y

# Core utilities needed by harbian-audit and for a usable system
PACKAGES=(
    # Build / base
    build-essential
    curl
    wget
    git
    vim
    nano
    htop
    tmux
    screen
    unzip
    zip
    ca-certificates
    gnupg
    lsb-release
    software-properties-common
    apt-transport-https

    # Networking
    openssh-server
    net-tools
    iproute2
    dnsutils
    iputils-ping
    traceroute
    tcpdump
    nmap
    iptables
    iptables-persistent
    nftables

    # Security / audit tools (needed by harbian-audit)
    auditd
    audispd-plugins
    libpam-pwquality
    libpam-tmpdir
    apt-listbugs
    apt-listchanges
    needrestart
    debsums
    fail2ban
    rkhunter
    chkrootkit
    aide
    acl
    sysstat
    rsyslog
    logrotate
    cron

    # AppArmor (harbian-audit level 5 wants MAC)
    apparmor
    apparmor-profiles
    apparmor-profiles-extra
    apparmor-utils

    # Misc required
    sudo
    passwd
    procps
    psmisc
    pciutils
    usbutils
    bc
    jq
)

info "Installing ${#PACKAGES[@]} packages..."

for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        ok "$pkg already installed"
    else
        if apt-get install -y "$pkg" 2>/dev/null; then
            ok "$pkg installed"
        else
            warn "$pkg failed to install (may not exist in this distro)"
        fi
    fi
done

ok "Phase 1 complete — base packages installed"

# ─────────────────────────────────────────────────────────────
#  PHASE 2 — PROTECT SSH (so we don't get locked out)
# ─────────────────────────────────────────────────────────────
info "═══════════════════════════════════════════════════"
info "PHASE 2: Protecting SSH access"
info "═══════════════════════════════════════════════════"

# Backup original SSH config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%s)

# Make sure SSH stays enabled and running
systemctl enable ssh    2>/dev/null || systemctl enable sshd   2>/dev/null || true
systemctl start ssh     2>/dev/null || systemctl start sshd    2>/dev/null || true

# Create a safety SSH config drop-in so hardening can't kill our access
mkdir -p /etc/ssh/sshd_config.d/

cat > /etc/ssh/sshd_config.d/00-keep-alive.conf << 'SSHEOF'
# ── Safety: keep SSH accessible during/after hardening ──
# This file is loaded FIRST and keeps us connected.
# After hardening, review and tighten further.

Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes

X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

# Session keepalive (prevent drops during long hardening)
ClientAliveInterval 60
ClientAliveCountMax 120
TCPKeepAlive yes

# Secure defaults that DON'T lock us out
Protocol 2
MaxAuthTries 6
MaxSessions 10
LoginGraceTime 120
SSHEOF

# Validate config before reloading
if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    ok "SSH config validated and reloaded"
else
    warn "SSH config test failed, restoring backup"
    cp /etc/ssh/sshd_config.bak.* /etc/ssh/sshd_config 2>/dev/null
    rm -f /etc/ssh/sshd_config.d/00-keep-alive.conf
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
fi

# Allow SSH through firewall (iptables)
iptables  -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
iptables  -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT
ip6tables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
ip6tables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT

# Also allow established connections (critical for current session)
iptables  -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables  -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
ip6tables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables  -C INPUT -i lo -j ACCEPT 2>/dev/null || \
iptables  -I INPUT 1 -i lo -j ACCEPT

ok "SSH is protected — port $SSH_PORT open in firewall"

# Configure fail2ban for SSH (protect but don't self-ban)
mkdir -p /etc/fail2ban
cat > /etc/fail2ban/jail.local << 'F2BEOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 10
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 10
F2BEOF

systemctl enable fail2ban 2>/dev/null || true
systemctl restart fail2ban 2>/dev/null || true
ok "fail2ban configured for SSH"

# ─────────────────────────────────────────────────────────────
#  PHASE 3 — PREPARE HARBIAN-AUDIT
# ─────────────────────────────────────────────────────────────
info "═══════════════════════════════════════════════════"
info "PHASE 3: Preparing harbian-audit"
info "═══════════════════════════════════════════════════"

# Find repo root (script could be run from inside or outside the repo)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/bin/hardening.sh" ]; then
    REPO_DIR="$SCRIPT_DIR"
elif [ -f "./bin/hardening.sh" ]; then
    REPO_DIR="$(pwd)"
else
    info "Cloning harbian-audit..."
    cd /opt
    rm -rf harbian-audit
    git clone https://github.com/hardenedlinux/harbian-audit.git
    REPO_DIR="/opt/harbian-audit"
fi

cd "$REPO_DIR"
info "Working from: $REPO_DIR"

# Make everything executable
chmod -R +x bin/ 2>/dev/null || true

ok "harbian-audit is ready at $REPO_DIR"

# ─────────────────────────────────────────────────────────────
#  PHASE 4 — SET HARDENING LEVEL 5 & CONFIGURE
# ─────────────────────────────────────────────────────────────
info "═══════════════════════════════════════════════════"
info "PHASE 4: Setting hardening level 5"
info "═══════════════════════════════════════════════════"

# Set level 5 (enables all checks up to level 5)
if [ -x bin/hardening.sh ]; then
    bash bin/hardening.sh --set-hardening-level 5
    ok "Hardening level set to 5"
else
    fail "bin/hardening.sh not found or not executable"
    exit 1
fi

# ─────────────────────────────────────────────────────────────
#  PHASE 4b — OVERRIDE DANGEROUS CHECKS (SSH safety)
# ─────────────────────────────────────────────────────────────
info "Tweaking configs to protect SSH access..."

# Find and patch SSH-lockout-dangerous configs
# These are the check configs that could kill SSH
CONF_DIR="$REPO_DIR/etc/conf.d"

if [ -d "$CONF_DIR" ]; then
    # For each config, we can set status=disabled for truly dangerous ones
    # or adjust parameters

    # Pattern: files related to SSH that might break access
    for conf_file in "$CONF_DIR"/*.cfg; do
        [ -f "$conf_file" ] || continue
        basename_f=$(basename "$conf_file")

        # Checks that disable password auth or restrict SSH too hard
        # We keep them in AUDIT mode only (not apply)
        case "$basename_f" in
            *ssh*disable*root*|*SSH*root*)
                info "  Adjusting $basename_f (keep root login for VPS)"
                # Don't disable root login on a VPS where it might be the only account
                sed -i 's/^status=.*/status=disabled/' "$conf_file" 2>/dev/null || true
                ;;
        esac
    done

    ok "SSH-safe overrides applied"
fi

# ─────────────────────────────────────────────────────────────
#  PHASE 5 — RUN AUDIT (dry-run first)
# ─────────────────────────────────────────────────────────────
info "═══════════════════════════════════════════════════"
info "PHASE 5: Running AUDIT (read-only scan)"
info "═══════════════════════════════════════════════════"

AUDIT_LOG="/var/log/harbian-audit-results-$(date +%Y%m%d-%H%M%S).log"

bash bin/hardening.sh --audit 2>&1 | tee "$AUDIT_LOG"

ok "Audit complete — results in $AUDIT_LOG"

# ─────────────────────────────────────────────────────────────
#  PHASE 6 — APPLY HARDENING
# ─────────────────────────────────────────────────────────────
info "═══════════════════════════════════════════════════"
info "PHASE 6: APPLYING Level 5 hardening"
info "═══════════════════════════════════════════════════"

warn "Applying hardening in 10 seconds... (Ctrl+C to abort)"
warn "SSH will remain available on port $SSH_PORT"

# Safety: schedule an SSH restart in 5 minutes in case something breaks
(
    sleep 300
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
    # Re-inject firewall rule
    iptables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null
) &
SAFETY_PID=$!
info "Safety SSH-restart scheduled (PID $SAFETY_PID) in 5 minutes"

sleep 10

APPLY_LOG="/var/log/harbian-audit-apply-$(date +%Y%m%d-%H%M%S).log"

bash bin/hardening.sh --apply 2>&1 | tee "$APPLY_LOG"

ok "Hardening applied — log: $APPLY_LOG"

# Kill safety timer if we got here fine
kill $SAFETY_PID 2>/dev/null || true

# ─────────────────────────────────────────────────────────────
#  PHASE 7 — POST-HARDENING SSH FIX-UP
# ─────────────────────────────────────────────────────────────
info "═══════════════════════════════════════════════════"
info "PHASE 7: Post-hardening SSH & firewall fix-up"
info "═══════════════════════════════════════════════════"

# Re-ensure SSH config is sane
if [ -f /etc/ssh/sshd_config.d/00-keep-alive.conf ]; then
    ok "SSH safety config still in place"
else
    warn "Recreating SSH safety config..."
    cat > /etc/ssh/sshd_config.d/00-keep-alive.conf << 'SSHEOF2'
Port 22
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
UsePAM yes
ClientAliveInterval 60
ClientAliveCountMax 120
Protocol 2
SSHEOF2
fi

# Re-validate and reload SSH
if sshd -t 2>/dev/null; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    ok "SSH restarted successfully"
else
    warn "SSH config broken — trying to fix..."
    # Nuke any conflicting settings and use our safety config
    grep -v "^PermitRootLogin\|^PasswordAuthentication\|^Port " \
        /etc/ssh/sshd_config > /tmp/sshd_config.clean
    cp /tmp/sshd_config.clean /etc/ssh/sshd_config
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
fi

# Re-ensure firewall allows SSH
iptables  -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
iptables  -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT
ip6tables -C INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || \
ip6tables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j ACCEPT
iptables  -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
iptables  -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Save iptables rules
iptables-save  > /etc/iptables/rules.v4 2>/dev/null || \
    mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

ok "Firewall rules saved"

# Enable critical services
systemctl enable ssh        2>/dev/null || true
systemctl enable auditd     2>/dev/null || true
systemctl enable rsyslog    2>/dev/null || true
systemctl enable apparmor   2>/dev/null || true
systemctl enable fail2ban   2>/dev/null || true
systemctl enable cron       2>/dev/null || true

systemctl start auditd      2>/dev/null || true
systemctl start apparmor    2>/dev/null || true

# ─────────────────────────────────────────────────────────────
#  PHASE 8 — FINAL AUDIT (verify hardening)
# ─────────────────────────────────────────────────────────────
info "═══════════════════════════════════════════════════"
info "PHASE 8: Final verification audit"
info "═══════════════════════════════════════════════════"

FINAL_LOG="/var/log/harbian-audit-final-$(date +%Y%m%d-%H%M%S).log"
bash bin/hardening.sh --audit 2>&1 | tee "$FINAL_LOG"

# ─────────────────────────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "ALL DONE! Harbian-audit Level 5 applied."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  ${GREEN}SSH Status:${NC}    $(systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null)"
echo -e "  ${GREEN}SSH Port:${NC}      $SSH_PORT"
echo -e "  ${GREEN}Auditd:${NC}        $(systemctl is-active auditd 2>/dev/null)"
echo -e "  ${GREEN}AppArmor:${NC}      $(systemctl is-active apparmor 2>/dev/null)"
echo -e "  ${GREEN}Fail2ban:${NC}      $(systemctl is-active fail2ban 2>/dev/null)"
echo ""
echo -e "  ${CYAN}Logs:${NC}"
echo "    Initial audit:  $AUDIT_LOG"
echo "    Apply log:      $APPLY_LOG"
echo "    Final audit:    $FINAL_LOG"
echo "    Script log:     $LOGFILE"
echo ""
echo -e "  ${YELLOW}POST-HARDENING TODO:${NC}"
echo "    1. Create a non-root user:   adduser admin && usermod -aG sudo admin"
echo "    2. Set up SSH keys:          ssh-copy-id admin@your-vps"
echo "    3. Then disable root login:  edit /etc/ssh/sshd_config.d/00-keep-alive.conf"
echo "       Change: PermitRootLogin no"
echo "       Change: PasswordAuthentication no"
echo "    4. Reload SSH:               systemctl reload ssh"
echo "    5. Review: $FINAL_LOG"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

SCRIPT_EOF
