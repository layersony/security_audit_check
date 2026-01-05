#!/bin/bash

# Server Security Audit Script
# Run with: sudo bash security_audit.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Output file
OUTPUT_FILE="security_audit_$(date +%Y%m%d_%H%M%S).txt"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   SERVER SECURITY AUDIT REPORT${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Generated: $(date)"
echo ""

# Redirect all output to both console and file
exec > >(tee -a "$OUTPUT_FILE")

# 1. SYSTEM INFORMATION
echo -e "\n${GREEN}[1] SYSTEM INFORMATION${NC}"
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"

# 2. USER ACCOUNTS AUDIT
echo -e "\n${GREEN}[2] USER ACCOUNTS AUDIT${NC}"
TOTAL_USERS=$(wc -l < /etc/passwd)
REAL_USERS=$(awk -F: '$3 >= 1000 && $3 != 65534 {print $1}' /etc/passwd | wc -l)
ROOT_USERS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l)

echo "Total entries in /etc/passwd: $TOTAL_USERS"
echo "Real user accounts (UID >= 1000): $REAL_USERS"
echo "Root-level accounts (UID 0): $ROOT_USERS"
echo ""
echo "Users with UID 0 (root privileges):"
awk -F: '$3 == 0 {print "  - " $1}' /etc/passwd

echo ""
echo "Regular user accounts:"
awk -F: '$3 >= 1000 && $3 != 65534 {print "  - " $1 " (UID: " $3 ")"}' /etc/passwd

echo ""
echo "Users with login shells:"
grep -v '/nologin\|/false' /etc/passwd | awk -F: '{print "  - " $1 " - " $7}'

# 3. GROUP AUDIT
echo -e "\n${GREEN}[3] GROUP AUDIT${NC}"
TOTAL_GROUPS=$(wc -l < /etc/group)
echo "Total groups: $TOTAL_GROUPS"
echo ""
echo "Groups with members:"
awk -F: '$4 != "" {print "  - " $1 ": " $4}' /etc/group | head -20

# 4. WORLD-WRITABLE FILES
echo -e "\n${GREEN}[4] WORLD-WRITABLE FILES (Security Risk)${NC}"
echo "Scanning for world-writable files (excluding /proc, /sys)..."
WORLD_WRITABLE=$(find / -path /proc -prune -o -path /sys -prune -o -type f -perm -002 -ls 2>/dev/null | wc -l)
echo "Found $WORLD_WRITABLE world-writable files"
if [ $WORLD_WRITABLE -gt 0 ]; then
    echo -e "${RED}WARNING: World-writable files found:${NC}"
    find / -path /proc -prune -o -path /sys -prune -o -type f -perm -002 -ls 2>/dev/null | head -20
    [ $WORLD_WRITABLE -gt 20 ] && echo "  ... (showing first 20 of $WORLD_WRITABLE)"
fi

# 5. SUID/SGID FILES
echo -e "\n${GREEN}[5] SUID/SGID FILES${NC}"
echo "Files with SUID bit (run as owner):"
SUID_COUNT=$(find / -path /proc -prune -o -path /sys -prune -o -type f -perm -4000 2>/dev/null | wc -l)
echo "Found $SUID_COUNT SUID files:"
find / -path /proc -prune -o -path /sys -prune -o -type f -perm -4000 -ls 2>/dev/null | awk '{print "  - " $11}' | head -15
[ $SUID_COUNT -gt 15 ] && echo "  ... (showing first 15 of $SUID_COUNT)"

echo ""
echo "Files with SGID bit:"
SGID_COUNT=$(find / -path /proc -prune -o -path /sys -prune -o -type f -perm -2000 2>/dev/null | wc -l)
echo "Found $SGID_COUNT SGID files:"
find / -path /proc -prune -o -path /sys -prune -o -type f -perm -2000 -ls 2>/dev/null | awk '{print "  - " $11}' | head -15
[ $SGID_COUNT -gt 15 ] && echo "  ... (showing first 15 of $SGID_COUNT)"

# 6. RECENTLY MODIFIED FILES
echo -e "\n${GREEN}[6] RECENTLY MODIFIED FILES${NC}"
echo "Files modified in last 24 hours in critical directories:"
find /etc /home /root /var/log -type f -mtime 0 2>/dev/null | head -20
echo ""
echo "Files modified in last 7 days in /etc:"
find /etc -type f -mtime -7 2>/dev/null | head -20

# 7. RECENTLY ADDED FILES
echo -e "\n${GREEN}[7] FILES CREATED IN LAST 24 HOURS${NC}"
find /home /var /tmp -type f -ctime 0 2>/dev/null | head -30

# 8. SSH CONFIGURATION CHECK
echo -e "\n${GREEN}[8] SSH SECURITY CHECK${NC}"
if [ -f /etc/ssh/sshd_config ]; then
    echo "SSH Configuration:"
    echo "  PermitRootLogin: $(grep -i "^PermitRootLogin" /etc/ssh/sshd_config || echo "Not explicitly set")"
    echo "  PasswordAuthentication: $(grep -i "^PasswordAuthentication" /etc/ssh/sshd_config || echo "Not explicitly set")"
    echo "  Port: $(grep -i "^Port" /etc/ssh/sshd_config || echo "Default (22)")"
    echo "  PubkeyAuthentication: $(grep -i "^PubkeyAuthentication" /etc/ssh/sshd_config || echo "Not explicitly set")"
else
    echo "SSH config file not found"
fi

# 9. OPEN PORTS
echo -e "\n${GREEN}[9] LISTENING PORTS${NC}"
if command -v ss &> /dev/null; then
    echo "TCP Listening ports:"
    ss -tlnp | head -20
elif command -v netstat &> /dev/null; then
    echo "TCP Listening ports:"
    netstat -tlnp | head -20
else
    echo "Neither ss nor netstat available"
fi

# 10. FAILED LOGIN ATTEMPTS
echo -e "\n${GREEN}[10] FAILED LOGIN ATTEMPTS${NC}"
if [ -f /var/log/auth.log ]; then
    FAILED_LOGINS=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
    echo "Recent failed login attempts: $FAILED_LOGINS"
    if [ $FAILED_LOGINS -gt 0 ]; then
        echo "Last 10 failed attempts:"
        grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10
    fi
elif [ -f /var/log/secure ]; then
    FAILED_LOGINS=$(grep "Failed password" /var/log/secure 2>/dev/null | wc -l)
    echo "Recent failed login attempts: $FAILED_LOGINS"
    if [ $FAILED_LOGINS -gt 0 ]; then
        echo "Last 10 failed attempts:"
        grep "Failed password" /var/log/secure 2>/dev/null | tail -10
    fi
fi

# 11. FIREWALL STATUS
echo -e "\n${GREEN}[11] FIREWALL STATUS${NC}"
if command -v ufw &> /dev/null; then
    echo "UFW Status:"
    ufw status
elif command -v firewall-cmd &> /dev/null; then
    echo "Firewalld Status:"
    firewall-cmd --state
    firewall-cmd --list-all
elif command -v iptables &> /dev/null; then
    echo "iptables rules:"
    iptables -L -n | head -20
else
    echo "No firewall tool found"
fi

# 12. PACKAGE UPDATES
echo -e "\n${GREEN}[12] SYSTEM UPDATES${NC}"
if command -v apt &> /dev/null; then
    echo "Checking for updates (Ubuntu/Debian)..."
    apt list --upgradable 2>/dev/null | head -10
elif command -v yum &> /dev/null; then
    echo "Checking for updates (RHEL/CentOS)..."
    yum list updates 2>/dev/null | head -10
fi

# SUMMARY
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}   SECURITY AUDIT SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "Total Users: $TOTAL_USERS (Real users: $REAL_USERS)"
echo -e "Total Groups: $TOTAL_GROUPS"
echo -e "World-writable files: ${RED}$WORLD_WRITABLE${NC}"
echo -e "SUID files: ${YELLOW}$SUID_COUNT${NC}"
echo -e "SGID files: ${YELLOW}$SGID_COUNT${NC}"
echo ""
echo -e "${GREEN}Report saved to: $OUTPUT_FILE${NC}"
echo ""
echo -e "${YELLOW}RECOMMENDATIONS:${NC}"
echo "1. Review all world-writable files and restrict permissions"
echo "2. Audit SUID/SGID files - remove unnecessary ones"
echo "3. Disable root SSH login if not needed"
echo "4. Review failed login attempts for suspicious activity"
echo "5. Keep system packages updated"
echo "6. Enable and configure firewall if not active"
