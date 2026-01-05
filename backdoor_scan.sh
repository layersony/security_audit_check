#!/bin/bash

# Comprehensive Backdoor and Malware Detection Script
# Run with: sudo bash backdoor_scan.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Output file
OUTPUT_FILE="backdoor_scan_$(date +%Y%m%d_%H%M%S).txt"
ALERT_COUNT=0

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  BACKDOOR & MALWARE DETECTION SCAN${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Started: $(date)"
echo ""

# Redirect all output to both console and file
exec > >(tee -a "$OUTPUT_FILE")

# Function to print alerts
alert() {
    echo -e "${RED}[!] ALERT: $1${NC}"
    ((ALERT_COUNT++))
}

warning() {
    echo -e "${YELLOW}[*] WARNING: $1${NC}"
}

info() {
    echo -e "${CYAN}[i] INFO: $1${NC}"
}

success() {
    echo -e "${GREEN}[✓] $1${NC}"
}

# 1. CHECK FOR EXECUTABLES IN TEMP DIRECTORIES
echo -e "\n${MAGENTA}[1] CHECKING FOR EXECUTABLES IN TEMP DIRECTORIES${NC}"
echo "==================================================="
TEMP_EXECS=$(sudo find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null)
if [ -n "$TEMP_EXECS" ]; then
    alert "Executable files found in temp directories!"
    echo "$TEMP_EXECS"
else
    success "No executable files in temp directories"
fi

# 2. CHECK FOR HIDDEN FILES IN TEMP DIRECTORIES
echo -e "\n${MAGENTA}[2] CHECKING FOR HIDDEN FILES IN TEMP DIRECTORIES${NC}"
echo "==================================================="
HIDDEN_TEMP=$(sudo find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null)
if [ -n "$HIDDEN_TEMP" ]; then
    warning "Hidden files found in temp directories"
    echo "$HIDDEN_TEMP"
else
    success "No hidden files in temp directories"
fi

# 3. CHECK FOR FILES IN /DEV
echo -e "\n${MAGENTA}[3] CHECKING FOR REGULAR FILES IN /DEV${NC}"
echo "==================================================="
DEV_FILES=$(sudo find /dev -type f 2>/dev/null)
if [ -n "$DEV_FILES" ]; then
    alert "Regular files found in /dev (should only contain device files)!"
    echo "$DEV_FILES"
else
    success "No regular files in /dev"
fi

# 4. CHECK FOR DELETED RUNNING EXECUTABLES
echo -e "\n${MAGENTA}[4] CHECKING FOR DELETED RUNNING EXECUTABLES${NC}"
echo "==================================================="
DELETED_EXEC=$(sudo ls -l /proc/*/exe 2>/dev/null | grep deleted)
if [ -n "$DELETED_EXEC" ]; then
    alert "Processes running from deleted executables (common malware technique)!"
    echo "$DELETED_EXEC"
else
    success "No deleted running executables"
fi

# 5. CHECK FOR LD_PRELOAD BACKDOORS
echo -e "\n${MAGENTA}[5] CHECKING FOR LD_PRELOAD BACKDOORS${NC}"
echo "==================================================="
if [ -f /etc/ld.so.preload ]; then
    alert "/etc/ld.so.preload exists (rootkit technique)!"
    cat /etc/ld.so.preload
else
    success "No /etc/ld.so.preload file"
fi

if [ -n "$LD_PRELOAD" ]; then
    alert "LD_PRELOAD environment variable is set!"
    echo "LD_PRELOAD=$LD_PRELOAD"
fi

# 6. CHECK FOR UNAUTHORIZED SSH KEYS
echo -e "\n${MAGENTA}[6] CHECKING FOR UNAUTHORIZED SSH KEYS${NC}"
echo "==================================================="
echo "Root's authorized_keys:"
if [ -f /root/.ssh/authorized_keys ]; then
    sudo cat /root/.ssh/authorized_keys
else
    info "No authorized_keys for root"
fi

echo ""
echo "All users' SSH keys:"
for user_home in /home/*; do
    if [ -f "$user_home/.ssh/authorized_keys" ]; then
        echo "--- $(basename $user_home) ---"
        sudo cat "$user_home/.ssh/authorized_keys"
    fi
done

# 7. CHECK FOR SUSPICIOUS NETWORK CONNECTIONS
echo -e "\n${MAGENTA}[7] CHECKING FOR SUSPICIOUS NETWORK CONNECTIONS${NC}"
echo "==================================================="
echo "Established connections:"
CONNECTIONS=$(sudo netstat -antp 2>/dev/null | grep ESTABLISHED || sudo ss -antp 2>/dev/null | grep ESTAB)
if [ -n "$CONNECTIONS" ]; then
    echo "$CONNECTIONS"
    
    # Extract unique foreign IPs
    echo ""
    info "Unique foreign IPs connected:"
    if command -v netstat &> /dev/null; then
        sudo netstat -antp 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u
    else
        sudo ss -antp 2>/dev/null | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort -u
    fi
else
    success "No suspicious established connections"
fi

# 8. CHECK FOR SUSPICIOUS PROCESSES
echo -e "\n${MAGENTA}[8] CHECKING FOR SUSPICIOUS PROCESSES${NC}"
echo "==================================================="
echo "Processes running from /tmp or /var/tmp:"
SUSPICIOUS_PROCS=$(sudo lsof 2>/dev/null | grep -E "/tmp|/var/tmp|/dev/shm")
if [ -n "$SUSPICIOUS_PROCS" ]; then
    warning "Processes found running from temp directories"
    echo "$SUSPICIOUS_PROCS"
else
    success "No processes running from temp directories"
fi

echo ""
echo "Looking for suspicious process names:"
SUSP_NAMES=$(ps aux | grep -iE "nc |netcat|/dev/tcp|bash -i|perl.*socket|python.*socket" | grep -v grep)
if [ -n "$SUSP_NAMES" ]; then
    warning "Suspicious process names found"
    echo "$SUSP_NAMES"
else
    success "No obviously suspicious process names"
fi

# 9. CHECK FOR RECENTLY MODIFIED SYSTEM BINARIES
echo -e "\n${MAGENTA}[9] CHECKING FOR RECENTLY MODIFIED SYSTEM BINARIES${NC}"
echo "==================================================="
MODIFIED_BINS=$(sudo find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 2>/dev/null)
if [ -n "$MODIFIED_BINS" ]; then
    warning "System binaries modified in last 7 days"
    echo "$MODIFIED_BINS"
else
    success "No recently modified system binaries"
fi

# 10. CHECK FOR SUSPICIOUS CRON JOBS
echo -e "\n${MAGENTA}[10] CHECKING FOR SUSPICIOUS CRON JOBS${NC}"
echo "==================================================="
echo "System crontab:"
sudo cat /etc/crontab 2>/dev/null

echo ""
echo "User cron jobs:"
for user in $(cut -f1 -d: /etc/passwd); do
    CRON_OUTPUT=$(sudo crontab -u $user -l 2>/dev/null)
    if [ -n "$CRON_OUTPUT" ]; then
        echo "--- $user ---"
        echo "$CRON_OUTPUT"
    fi
done

echo ""
echo "Cron directories:"
ls -la /etc/cron.d/ 2>/dev/null
ls -la /etc/cron.daily/ 2>/dev/null
ls -la /etc/cron.hourly/ 2>/dev/null

# 11. CHECK FOR WEBSHELLS (if web server exists)
echo -e "\n${MAGENTA}[11] CHECKING FOR WEBSHELLS${NC}"
echo "==================================================="
if [ -d /var/www ]; then
    echo "Scanning for common webshell patterns in PHP files..."
    WEBSHELLS=$(sudo find /var/www -type f -name "*.php" -exec grep -l "eval(\|base64_decode(\|gzinflate(\|system(\|passthru(\|shell_exec(" {} \; 2>/dev/null)
    if [ -n "$WEBSHELLS" ]; then
        alert "Potential webshells found!"
        echo "$WEBSHELLS"
    else
        success "No obvious webshells detected"
    fi
    
    echo ""
    echo "Checking for suspicious PHP filenames:"
    SUSP_PHP=$(sudo find /var/www -type f \( -name "*shell*.php" -o -name "*cmd*.php" -o -name "c99.php" -o -name "r57.php" \) 2>/dev/null)
    if [ -n "$SUSP_PHP" ]; then
        alert "Suspicious PHP files found!"
        echo "$SUSP_PHP"
    else
        success "No suspicious PHP filenames"
    fi
    
    echo ""
    echo "Recently uploaded PHP files (last 7 days):"
    sudo find /var/www -type f -name "*.php" -mtime -7 -ls 2>/dev/null | head -20
else
    info "No /var/www directory (web server not detected)"
fi

# 12. CHECK FOR HIDDEN FILES IN HOME DIRECTORIES
echo -e "\n${MAGENTA}[12] CHECKING FOR SUSPICIOUS HIDDEN FILES IN /HOME${NC}"
echo "==================================================="
HIDDEN_HOME=$(sudo find /home -name ".*" -type f -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null)
if [ -n "$HIDDEN_HOME" ]; then
    warning "Hidden script files in home directories"
    echo "$HIDDEN_HOME"
else
    success "No suspicious hidden scripts in home directories"
fi

# 13. CHECK SYSTEMD SERVICES FOR ANOMALIES
echo -e "\n${MAGENTA}[13] CHECKING FOR SUSPICIOUS SYSTEMD SERVICES${NC}"
echo "==================================================="
echo "Recently modified systemd services (last 30 days):"
RECENT_SERVICES=$(sudo find /etc/systemd/system /lib/systemd/system -type f -name "*.service" -mtime -30 2>/dev/null)
if [ -n "$RECENT_SERVICES" ]; then
    warning "Recently modified systemd services"
    echo "$RECENT_SERVICES"
else
    success "No recently modified systemd services"
fi

# 14. CHECK FOR FILES WITH UNUSUAL NAMES
echo -e "\n${MAGENTA}[14] CHECKING FOR FILES WITH UNUSUAL NAMES${NC}"
echo "==================================================="
echo "Files with spaces in names:"
sudo find /tmp /var/tmp /home -name "* *" -type f 2>/dev/null | head -20

echo ""
echo "Files with multiple dots:"
sudo find /tmp /var/tmp /home -name "*...*" -type f 2>/dev/null | head -20

# 15. CHECK KERNEL MODULES
echo -e "\n${MAGENTA}[15] CHECKING LOADED KERNEL MODULES${NC}"
echo "==================================================="
echo "Currently loaded modules:"
lsmod | head -20
echo "... (showing first 20)"

echo ""
echo "Recently added kernel modules (last 30 days):"
RECENT_MODS=$(find /lib/modules/$(uname -r) -name "*.ko" -mtime -30 2>/dev/null)
if [ -n "$RECENT_MODS" ]; then
    warning "Recently added kernel modules"
    echo "$RECENT_MODS"
else
    success "No recently added kernel modules"
fi

# 16. CHECK LOGS FOR TAMPERING
echo -e "\n${MAGENTA}[16] CHECKING FOR LOG FILE TAMPERING${NC}"
echo "==================================================="
echo "Log file sizes:"
ls -lh /var/log/auth.log /var/log/syslog /var/log/secure /var/log/messages 2>/dev/null

echo ""
echo "Empty or suspiciously small log files:"
sudo find /var/log -type f -size 0 2>/dev/null

# 17. RUN AUTOMATED SCANNERS (if available)
echo -e "\n${MAGENTA}[17] RUNNING AUTOMATED SECURITY SCANNERS${NC}"
echo "==================================================="

if command -v rkhunter &> /dev/null; then
    echo "Running rkhunter..."
    sudo rkhunter --update >/dev/null 2>&1
    sudo rkhunter --check --sk --report-warnings-only
else
    warning "rkhunter not installed. Install with: sudo apt install rkhunter"
fi

echo ""
if command -v chkrootkit &> /dev/null; then
    echo "Running chkrootkit..."
    sudo chkrootkit | grep -i "warning\|infected"
else
    warning "chkrootkit not installed. Install with: sudo apt install chkrootkit"
fi

# SUMMARY
echo -e "\n${BLUE}========================================${NC}"
echo -e "${BLUE}           SCAN SUMMARY${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Scan completed: $(date)"
echo ""

if [ $ALERT_COUNT -eq 0 ]; then
    success "No critical alerts found!"
else
    alert "Total critical alerts: $ALERT_COUNT"
fi

echo ""
echo -e "${YELLOW}CRITICAL ITEMS TO REVIEW:${NC}"
echo "1. Any executables in /tmp, /var/tmp, /dev/shm"
echo "2. Regular files in /dev directory"
echo "3. Deleted running executables"
echo "4. /etc/ld.so.preload file existence"
echo "5. Unauthorized SSH keys"
echo "6. Suspicious network connections"
echo "7. Webshells in /var/www"
echo "8. Recently modified system binaries"
echo ""
echo -e "${GREEN}Report saved to: $OUTPUT_FILE${NC}"
echo ""

if [ $ALERT_COUNT -gt 3 ]; then
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  ⚠️  HIGH RISK - INVESTIGATE IMMEDIATELY${NC}"
    echo -e "${RED}========================================${NC}"
    echo "Multiple security alerts detected!"
    echo "Consider isolating this system and conducting a forensic analysis."
fi

echo ""
echo "To install missing security tools:"
echo "  sudo apt install rkhunter chkrootkit lynis aide"
echo ""
echo "For deeper analysis, run:"
echo "  sudo lynis audit system"
