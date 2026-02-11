#!/bin/bash

set -e

# Check root

if [[ $EUID -ne 0 ]]; then
echo “This script must be run as root: sudo bash start.sh”
exit 1
fi

echo “========================================”
echo “Harbian Audit Level 5 - Setup”
echo “========================================”
echo “”

# Step 1: Clone if needed

echo “[1] Setting up repository…”
if [[ ! -d “harbian-audit” ]]; then
git clone https://github.com/hardenedlinux/harbian-audit.git
fi
cd harbian-audit
REPO_DIR=”$(pwd)”
echo “Repository: $REPO_DIR”
echo “”

# Step 2: Configure

echo “[2] Configuring system…”
cp etc/default.cfg /etc/default/cis-hardening
sed -i “s#CIS_ROOT_DIR=.*#CIS_ROOT_DIR=’$REPO_DIR’#” /etc/default/cis-hardening
echo “Config updated”
echo “”

# Step 3: Initialize

echo “[3] Initializing hardening…”
./bin/hardening.sh –init
echo “”

# Step 4: Audit all

echo “[4] Auditing system (all 270+ checks)…”
echo “This takes 5-10 minutes…”
echo “”
./bin/hardening.sh –audit-all
echo “”

# Step 5: Set level 5

echo “[5] Setting hardening level to 5…”
./bin/hardening.sh –set-hardening-level 5
echo “”

# Step 6: Apply

echo “[6] Applying Level 5 hardening…”
echo “WARNING: This makes changes to your system”
echo “WARNING: A reboot will be required”
read -p “Continue? (yes/no): “ answer
if [[ “$answer” != “yes” ]]; then
echo “Cancelled”
exit 0
fi
echo “”

./bin/hardening.sh –apply
echo “”

# Step 7: Schedule audits

echo “[7] Scheduling daily audits…”
(crontab -l 2>/dev/null || true; echo “0 3 * * * cd $REPO_DIR && ./bin/hardening.sh –audit-all > /tmp/harbian-daily-audit.log 2>&1”) | crontab -
echo “”

# Step 8: Summary

echo “========================================”
echo “Setup Complete!”
echo “========================================”
echo “”
echo “Repository: $REPO_DIR”
echo “Config: /etc/default/cis-hardening”
echo “Backups: $REPO_DIR/tmp/backups”
echo “”
echo “Daily audit scheduled at 3:00 AM”
echo “”
echo “Next steps:”
echo “1. Reboot: sudo reboot”
echo “2. After reboot, verify: cd $REPO_DIR && ./bin/hardening.sh –audit-all”
echo “”

# Step 9: Ask reboot

read -p “Reboot now? (yes/no): “ reboot_answer
if [[ “$reboot_answer” == “yes” ]]; then
echo “Rebooting in 10 seconds…”
sleep 10
reboot
else
echo “Remember to reboot later: sudo reboot”
fi
