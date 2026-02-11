#!/bin/bash

################################################################################

# Harbian Audit Level 5 - Automated Setup Script

# Based on official harbian-audit repository README

# Source: https://github.com/hardenedlinux/harbian-audit

# Usage: sudo bash start.sh

################################################################################

set -e

# Colors

RED=’\033[0;31m’
GREEN=’\033[0;32m’
YELLOW=’\033[1;33m’
BLUE=’\033[0;34m’
NC=’\033[0m’

print_header() {
echo -e “${BLUE}================================================================================${NC}”
echo -e “${BLUE}$1${NC}”
echo -e “${BLUE}================================================================================${NC}”
}

print_info() {
echo -e “${GREEN}[INFO]${NC} $1”
}

print_success() {
echo -e “${GREEN}[✓]${NC} $1”
}

print_warning() {
echo -e “${YELLOW}[!]${NC} $1”
}

# Check root

if [[ $EUID -ne 0 ]]; then
echo “This script must be run as root: sudo bash start.sh”
exit 1
fi

print_header “Harbian Audit Level 5 - Automated Setup”
echo “”

# Step 1: Check dependencies

print_header “Step 1: Checking Dependencies”
if ! command -v git &> /dev/null; then
print_info “Git not found, installing…”
apt-get update -qq
apt-get install -y git >/dev/null 2>&1
fi
print_success “Git is available”

# Step 2: Clone or use existing repo

print_header “Step 2: Setting Up Repository”
if [[ ! -d “harbian-audit” ]]; then
print_info “Cloning harbian-audit repository…”
git clone https://github.com/hardenedlinux/harbian-audit.git >/dev/null 2>&1
print_success “Repository cloned”
else
print_warning “harbian-audit directory already exists, using existing”
fi

cd harbian-audit
REPO_DIR=”$(pwd)”
print_info “Working directory: $REPO_DIR”

# Step 3: Configure

print_header “Step 3: Configuring System”
print_info “Copying configuration file…”
cp etc/default.cfg /etc/default/cis-hardening

print_info “Setting CIS_ROOT_DIR…”
sed -i “s#CIS_ROOT_DIR=.*#CIS_ROOT_DIR=’$REPO_DIR’#” /etc/default/cis-hardening

print_success “Configuration completed”

# Step 4: Initialize

print_header “Step 4: Initializing Hardening System”
print_info “Running: bin/hardening.sh –init”
./bin/hardening.sh –init >/dev/null 2>&1
print_success “Hardening system initialized”

# Step 5: Audit all

print_header “Step 5: Auditing System (All 270+ Checks)”
print_info “This will take 5-10 minutes…”
./bin/hardening.sh –audit-all

# Step 6: Set hardening level

print_header “Step 6: Setting Hardening Level to 5”
print_info “Configuring for MAXIMUM security (270+ checks)…”
./bin/hardening.sh –set-hardening-level 5
print_success “Hardening level set to 5”

# Step 7: Apply hardening

print_header “Step 7: Applying Level 5 Hardening”
echo “”
print_warning “This will make CHANGES to your system”
print_warning “SSH and other services will be hardened”
print_warning “A reboot will be required afterward”
echo “”
read -p “Continue with hardening? (yes/no): “ -r
echo
if [[ ! $REPLY =~ ^[Yy][Ss]$ ]]; then
print_info “Setup cancelled by user”
exit 0
fi

print_info “Applying hardening changes (15-20 minutes)…”
./bin/hardening.sh –apply

print_success “Hardening applied successfully!”

# Step 8: Schedule regular audits

print_header “Step 8: Scheduling Regular Audits”
print_info “Adding daily audit at 3 AM…”
(crontab -l 2>/dev/null || true; echo “0 3 * * * cd $REPO_DIR && ./bin/hardening.sh –audit-all > /tmp/harbian-daily-audit.log 2>&1”) | crontab -
print_success “Daily audit scheduled”

# Step 9: Create summary

print_header “Step 9: Setup Summary”

cat <<EOF

╔════════════════════════════════════════════════════════════════════════╗
║              Harbian Audit Level 5 Setup Complete!                    ║
╚════════════════════════════════════════════════════════════════════════╝

✓ Repository: Configured
✓ System: Initialized  
✓ Audit: Completed
✓ Hardening: Applied
✓ Monitoring: Scheduled

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SYSTEM INFORMATION:
Repository: $REPO_DIR
Config: /etc/default/cis-hardening
Backups: $REPO_DIR/tmp/backups

SECURITY STATUS:
Total Checks: 270+
Hardening Level: 5 (MAXIMUM)
Grade: ARMY GRADE SECURITY

SCHEDULED TASKS:
Daily Audit: 3:00 AM every day
Log File: /tmp/harbian-daily-audit.log

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NEXT STEPS:

1. REBOOT SYSTEM (required for kernel-level changes)
   sudo reboot
1. AFTER REBOOT, TEST AUDIT:
   cd $REPO_DIR
   ./bin/hardening.sh –audit-all
1. VIEW DAILY AUDIT LOGS:
   cat /tmp/harbian-daily-audit.log
1. VERIFY CRITICAL SERVICES:
   ssh localhost
   systemctl status ssh
   systemctl status networking
1. MONTHLY UPDATES:
   cd $REPO_DIR
   git pull

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

USEFUL COMMANDS:

Audit only (no changes):
cd $REPO_DIR
./bin/hardening.sh –audit-all

Apply hardening again:
cd $REPO_DIR
./bin/hardening.sh –apply

Set different level (1-5):
cd $REPO_DIR
./bin/hardening.sh –set-hardening-level 3
./bin/hardening.sh –apply

View backups:
ls -la $REPO_DIR/tmp/backups/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUPPORT & DOCUMENTATION:
GitHub: https://github.com/hardenedlinux/harbian-audit
Issues: https://github.com/hardenedlinux/harbian-audit/issues

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

# Step 10: Ask for reboot

print_header “Step 10: Reboot Required”
echo “”
read -p “Reboot system now? (yes/no): “ -r
echo
if [[ $REPLY =~ ^[Yy][Ss]$ ]]; then
print_info “System will reboot in 10 seconds…”
print_info “After reboot, run: cd $REPO_DIR && ./bin/hardening.sh –audit-all”
sleep 10
reboot
else
print_warning “Remember to reboot later: sudo reboot”
print_info “After reboot, verify: cd $REPO_DIR && ./bin/hardening.sh –audit-all”
fi
