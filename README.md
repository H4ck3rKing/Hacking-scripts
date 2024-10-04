# Hacking-scripts
The script for automating the entire process so as to not get hacked{
v1 script: 
#!/bin/bash

# Advanced Hardening Script for Metasploitable 3 (Linux Version)
# This script thoroughly hardens the Metasploitable 3 machine, putting all ports in a filtered state
# while still allowing ping. It provides verbose output for all actions.

# Exit immediately if a command exits with a non-zero status
set -e

# Enable command trace mode for verbosity
set -x

# Variables
LOGFILE="/var/log/advanced_hardening_metasploitable3.log"
SSH_PORT=22222  # Choose a non-standard port for SSH
DEFAULT_PASSWORD="StrongP@ssw0rd123!"  # Change this to your secure password

# Function to log messages
log() {
    echo "$(date +"%Y-%m-%d %T") : $1" | tee -a "$LOGFILE"
}

# Function to update system packages
update_system() {
    log "Updating system packages..."
    sudo apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y
    log "System packages updated successfully."
}

# Function to install security tools
install_security_tools() {
    log "Installing security tools..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban unattended-upgrades auditd libpam-cracklib nmap iptables-persistent
    log "Security tools installed successfully."
}

# Function to configure UFW and iptables
configure_firewall() {
    log "Configuring UFW and iptables..."

    # Reset UFW to default settings
    sudo ufw --force reset

    # Set default policies
    sudo ufw default deny incoming
    sudo ufw default deny outgoing

    # Allow ping (ICMP)
    sudo ufw allow in icmp
    sudo ufw allow out icmp

    # Allow DNS
    sudo ufw allow out 53/udp
    sudo ufw allow out 53/tcp

    # Allow SSH on custom port
    sudo ufw allow in "$SSH_PORT"/tcp

    # Allow outgoing HTTP and HTTPS for updates
    sudo ufw allow out 80/tcp
    sudo ufw allow out 443/tcp

    # Enable UFW
    sudo ufw --force enable

    # Configure iptables for additional protection
    sudo iptables -F
    sudo iptables -X
    sudo iptables -t nat -F
    sudo iptables -t nat -X
    sudo iptables -t mangle -F
    sudo iptables -t mangle -X

    # Set default chain policies
    sudo iptables -P INPUT DROP
    sudo iptables -P FORWARD DROP
    sudo iptables -P OUTPUT DROP

    # Allow loopback
    sudo iptables -A INPUT -i lo -j ACCEPT
    sudo iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established connections
    sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ping
    sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

    # Allow SSH on custom port
    sudo iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # Allow DNS
    sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow HTTP and HTTPS outgoing for updates
    sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

    # Save iptables rules
    sudo netfilter-persistent save

    log "Firewall configured successfully."
}

# Function to disable unnecessary services
disable_unnecessary_services() {
    log "Disabling unnecessary services..."
    
    # List of common unnecessary services
    SERVICES_TO_DISABLE=(
        apache2 vsftpd tftpd-hpa rpcbind nfs-kernel-server smbd nmbd
        telnetd xinetd atd avahi-daemon cups dhcpd slapd squid3 snmpd
    )

    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-active --quiet "$service"; then
            sudo systemctl stop "$service"
            sudo systemctl disable "$service"
            log "Service $service stopped and disabled."
        else
            log "Service $service is not active or not installed."
        fi
    done

    log "Unnecessary services disabled."
}

# Function to harden SSH configuration
harden_ssh() {
    log "Hardening SSH configuration..."

    SSH_CONFIG="/etc/ssh/sshd_config"

    # Backup SSH config
    sudo cp "$SSH_CONFIG" "${SSH_CONFIG}.bak"

    # Modify SSH configurations
    sudo sed -i "s/^#*Port .*/Port $SSH_PORT/" "$SSH_CONFIG"
    sudo sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' "$SSH_CONFIG"
    sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' "$SSH_CONFIG"
    sudo sed -i 's/^#*PermitEmptyPasswords .*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    sudo sed -i 's/^#*X11Forwarding .*/X11Forwarding no/' "$SSH_CONFIG"
    sudo sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 3/' "$SSH_CONFIG"
    sudo sed -i 's/^#*UsePAM .*/UsePAM yes/' "$SSH_CONFIG"

    # Restart SSH service
    sudo systemctl restart ssh

    log "SSH configuration hardened successfully."
}

# Function to enforce strong password policies
enforce_password_policy() {
    log "Enforcing strong password policies..."

    # Update PAM password policy
    sudo sed -i 's/^password\s\+requisite\s\+pam_cracklib.so.*/password requisite pam_cracklib.so retry=3 minlen=14 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

    # Update login.defs for password aging
    sudo sed -i 's/^PASS_MAX_DAYS\s\+[0-9]*/PASS_MAX_DAYS\t90/' /etc/login.defs
    sudo sed -i 's/^PASS_MIN_DAYS\s\+[0-9]*/PASS_MIN_DAYS\t10/' /etc/login.defs
    sudo sed -i 's/^PASS_WARN_AGE\s\+[0-9]*/PASS_WARN_AGE\t7/' /etc/login.defs

    log "Password policies enforced successfully."
}

# Function to set proper permissions on sensitive files
set_file_permissions() {
    log "Setting file permissions on sensitive files..."

    sudo chmod 600 /etc/shadow
    sudo chmod 644 /etc/passwd
    sudo chmod 644 /etc/group
    sudo chmod 600 /etc/gshadow
    sudo chmod 644 /etc/login.defs
    sudo chmod 600 /etc/ssh/sshd_config
    
    sudo chown root:root /etc/shadow /etc/passwd /etc/group /etc/gshadow /etc/login.defs /etc/ssh/sshd_config

    log "File permissions set successfully."
}

# Function to configure system auditing
configure_auditing() {
    log "Configuring system auditing..."

    # Enable auditd
    sudo systemctl enable auditd
    sudo systemctl start auditd

    # Configure audit rules
    AUDIT_RULES_FILE="/etc/audit/rules.d/audit.rules"

    # Backup existing rules
    sudo cp "$AUDIT_RULES_FILE" "${AUDIT_RULES_FILE}.bak"

    # Add custom audit rules
    cat << EOF | sudo tee "$AUDIT_RULES_FILE"
# Monitor changes to system authentication files
-w /etc/passwd -p wa -k auth_changes
-w /etc/shadow -p wa -k auth_changes
-w /etc/group -p wa -k auth_changes
-w /etc/gshadow -p wa -k auth_changes

# Monitor changes to system configuration files
-w /etc/ssh/sshd_config -p wa -k config_changes
-w /etc/sudoers -p wa -k config_changes

# Monitor user and group management
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/groupdel -p x -k group_modification

# Monitor changes to network configuration
-w /etc/network/ -p wa -k network_changes
-w /etc/sysconfig/network -p wa -k network_changes

# Monitor system startup scripts
-w /etc/init.d/ -p wa -k init_changes
-w /etc/systemd/ -p wa -k systemd_changes

# Monitor kernel module loading and unloading
-w /sbin/insmod -p x -k module_insertion
-w /sbin/rmmod -p x -k module_removal
-w /sbin/modprobe -p x -k module_insertion

# Enable logging of all commands run by root
-a exit,always -F arch=b64 -F euid=0 -S execve -k root_commands
-a exit,always -F arch=b32 -F euid=0 -S execve -k root_commands
EOF

    # Restart auditd to apply new rules
    sudo systemctl restart auditd

    log "System auditing configured successfully."
}

# Function to remove or secure default credentials
remove_default_credentials() {
    log "Removing or securing default credentials..."

    # Check if user 'msfadmin' exists
    if id "msfadmin" &>/dev/null; then
        log "Securing 'msfadmin' account..."
        echo "msfadmin:$DEFAULT_PASSWORD" | sudo chpasswd
        sudo usermod -L msfadmin
        log "'msfadmin' password changed and account locked."
    else
        log "User 'msfadmin' does not exist. Skipping."
    fi

    # Check and secure other common default users
    USERS_TO_CHECK=(root admin user guest test)
    for user in "${USERS_TO_CHECK[@]}"; do
        if id "$user" &>/dev/null; then
            log "Securing '$user' account..."
            sudo usermod -L "$user"
            log "'$user' account locked."
        fi
    done

    log "Default credentials secured."
}

# Function to verify system hardening
verify_hardening() {
    log "Verifying system hardening..."

    # Check UFW status
    sudo ufw status verbose

    # Check iptables rules
    sudo iptables -L -v -n

    # Verify open ports
    log "Open ports:"
    sudo ss -tuln

    # Run nmap scan on localhost
    log "Running nmap scan on localhost..."
    sudo nmap -sS -O -p- localhost

    log "Hardening verification completed."
}

# Main execution
main() {
    log "========== Starting Advanced Metasploitable 3 Hardening Script =========="

    update_system
    install_security_tools
    configure_firewall
    disable_unnecessary_services
    harden_ssh
    enforce_password_policy
    set_file_permissions
    configure_auditing
    remove_default_credentials
    verify_hardening

    log "========== Advanced Hardening Script Completed Successfully =========="
}

# Run the main function
main



}




V2 Script{
#!/bin/bash

# Run this script as root on Metasploitable 3

# Function to stop and disable specific services
stop_and_disable_services() {
    echo "Stopping and disabling specific vulnerable services..."
    
    services=(
        "vsftpd"       # Port 21
        "apache2"      # Port 80
        "rpcbind"      # Port 111
        "smbd"         # Ports 139, 445
        "nmbd"         # NetBIOS
        "cups"         # Port 631
        "mysql"        # Port 3306
        "ircd"         # Port 6667
        "tomcat6"      # Port 8080
    )

    for service in "${services[@]}"; do
        if command -v systemctl >/dev/null 2>&1; then
            systemctl stop $service
            systemctl disable $service
            echo "$service stopped and disabled (systemd)."
        elif command -v service >/dev/null 2>&1; then
            service $service stop
            update-rc.d $service disable
            echo "$service stopped and disabled (init.d)."
        else
            echo "Could not stop $service. Neither systemctl nor service command found."
        fi
    done

    # Stop any process on port 3000 (might be a custom service)
    pid=$(lsof -ti:3000)
    if [ ! -z "$pid" ]; then
        kill -9 $pid
        echo "Process on port 3000 terminated."
    fi
}

# Function to configure iptables firewall
configure_firewall() {
    echo "Configuring firewall..."

    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established and related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

    # Explicitly block the mentioned ports
    for port in 21 80 111 139 445 631 3000 3306 6667 8080; do
        iptables -A INPUT -p tcp --dport $port -j DROP
        iptables -A INPUT -p udp --dport $port -j DROP
    done

    # Log dropped packets
    iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: "

    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4

    echo "Firewall configured. Specified ports are now blocked."
}

# Function to remove unnecessary software
remove_unnecessary_software() {
    echo "Removing unnecessary software..."
    apt remove -y vsftpd apache2 samba cups mysql-server ircd-hybrid tomcat6
    apt autoremove -y
}

# Function to secure configurations
secure_configurations() {
    echo "Securing configurations..."

    # Disable anonymous FTP (in case vsftpd is reinstalled)
    if [ -f /etc/vsftpd.conf ]; then
        sed -i 's/anonymous_enable=YES/anonymous_enable=NO/' /etc/vsftpd.conf
    fi

    # Secure SMB (in case Samba is reinstalled)
    if [ -f /etc/samba/smb.conf ]; then
        sed -i 's/\[global\]/[global]\nserver signing = mandatory\nserver min protocol = SMB2/' /etc/samba/smb.conf
    fi

    # Secure MySQL (in case MySQL is reinstalled)
    if command -v mysql >/dev/null 2>&1; then
        mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY 'StrongPassword123!';"
        mysql -e "DELETE FROM mysql.user WHERE User='';"
        mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
        mysql -e "DROP DATABASE IF EXISTS test;"
        mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
        mysql -e "FLUSH PRIVILEGES;"
    fi
}

# Main execution
stop_and_disable_services
configure_firewall
remove_unnecessary_software
secure_configurations

echo "Targeted system hardening complete. The specified ports should now be closed and services stopped."
echo "Please review changes and adjust as needed for your specific requirements."

}

V3{
#!/bin/bash

# Enhanced Hardening Script for Metasploitable 3 (Linux Version) v3
# Run this script as root on Metasploitable 3

set -e  # Exit immediately if a command exits with a non-zero status
#set -x  # Uncomment for debugging

LOG_FILE="/var/log/metasploitable3_hardening.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Variables
SSH_PORT=2222
DEFAULT_PASSWORD="newsecurepassword" # Change this to your secure password
START_PORT=21
END_PORT=8080
ALLOWED_USERS=("your_username") # Replace with actual usernames

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to stop and disable specific services
stop_and_disable_services() {
    log "Stopping and disabling specific vulnerable services..."

    services=(
        "vsftpd"       # Port 21
        "apache2"      # Port 80
        "rpcbind"      # Port 111
        "smbd"         # Ports 139, 445
        "nmbd"         # NetBIOS
        "cups"         # Port 631
        "mysql"        # Port 3306
        "ircd-hybrid"  # Port 6667
        "tomcat6"      # Port 8080
        "telnetd"      # Port 23
        "snmpd"        # Port 161
    )

    for service in "${services[@]}"; do
        if service "$service" status >/dev/null 2>&1; then
            service "$service" stop
            service "$service" disable
            log "$service stopped and disabled."
        else
            log "$service is not active or not installed."
        fi
    done

    # Special handling for sshd (will reconfigure later)
    if service ssh status >/dev/null 2>&1; then
        service ssh stop
        log "sshd stopped for reconfiguration."
    fi

    # Stop any process on port 3000 (might be a custom service)
    pid=$(lsof -ti:3000 || true)
    if [ -n "$pid" ]; then
        kill -9 "$pid"
        log "Process on port 3000 (PID: $pid) terminated."
    else
        log "No process found running on port 3000."
    fi
}

# Function to configure iptables firewall
configure_firewall() {
    log "Configuring iptables firewall..."

    # Install iptables-persistent for rule persistence
    if ! command_exists iptables-save; then
        log "Installing iptables-persistent..."
        apt-get update -y >> "$LOG_FILE" 2>&1
        apt-get install -y iptables-persistent >> "$LOG_FILE" 2>&1
    fi

    # Flush existing rules
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    # Set default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback traffic
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow established and related connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

    # Allow SSH on custom port
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT

    # Deny all ports from START_PORT to END_PORT
    iptables -A INPUT -p tcp --dport "$START_PORT":"$END_PORT" -j DROP
    iptables -A INPUT -p udp --dport "$START_PORT":"$END_PORT" -j DROP

    # Rate limit incoming SSH connections to prevent brute-force attacks
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m state --state NEW -m recent --set
    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

    # Log dropped packets
    iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: " --log-level 7

    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4

    log "Firewall configured. Ports $START_PORT-$END_PORT are now blocked."
}

# Function to remove unnecessary software
remove_unnecessary_software() {
    log "Removing unnecessary software..."

    packages=(
        "vsftpd" 
        "apache2" 
        "samba" 
        "cups" 
        "mysql-server" 
        "ircd-hybrid" 
        "tomcat6" 
        "telnetd" 
        "snmpd"
    )

    for pkg in "${packages[@]}"; do
        if dpkg -l | grep -qw "$pkg"; then
            apt-get purge -y "$pkg" >> "$LOG_FILE" 2>&1
            log "$pkg removed."
        else
            log "$pkg is not installed."
        fi
    done

    apt-get autoremove -y >> "$LOG_FILE" 2>&1
    apt-get autoclean -y >> "$LOG_FILE" 2>&1

    log "Unnecessary software removal completed."
}

# Function to secure configurations
secure_configurations() {
    log "Securing configurations..."

    # Secure SSH
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        log "Backup of sshd_config created."

        # Modify SSH configurations
        cat > /etc/ssh/sshd_config <<EOL
Port $SSH_PORT
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers $(IFS=, ; echo "${ALLOWED_USERS[*]}")
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
EOL

        service ssh start
        log "SSH configuration secured and service restarted."
    else
        log "sshd_config not found. Skipping SSH configuration."
    fi

    # Harden sysctl settings
    cat >> /etc/sysctl.conf <<EOL

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOL

    sysctl -p >> "$LOG_FILE" 2>&1
    log "Sysctl settings hardened."

    # Disable USB storage
    echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf
    log "USB storage disabled."

    # Disable core dumps
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    sysctl -p >> "$LOG_FILE" 2>&1
    log "Core dumps disabled."

    # Set stronger umask
    sed -i 's/^UMASK\s\+022/UMASK\t027/' /etc/login.defs
    log "Umask set to 027."

    log "Configuration hardening completed."
}

# Function to implement additional security measures
implement_additional_security() {
    log "Implementing additional security measures..."

    # Install and configure fail2ban
    if ! dpkg -l | grep -qw "fail2ban"; then
        apt-get install -y fail2ban >> "$LOG_FILE" 2>&1
        log "fail2ban installed."
    fi

    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local <<EOL
[DEFAULT]
bantime = 3600
findtime = 1800
maxretry = 5

[sshd]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOL

    service fail2ban restart
    log "fail2ban configured and restarted."

    # Install and configure auditd
    if ! dpkg -l | grep -qw "auditd"; then
        apt-get install -y auditd >> "$LOG_FILE" 2>&1
        log "auditd installed."
    fi

    auditctl -e 1
    log "auditd enabled."

    # Install and configure chkrootkit and rkhunter
    if ! dpkg -l | grep -qw "chkrootkit"; then
        apt-get install -y chkrootkit >> "$LOG_FILE" 2>&1
        log "chkrootkit installed."
    fi

    if ! dpkg -l | grep -qw "rkhunter"; then
        apt-get install -y rkhunter >> "$LOG_FILE" 2>&1
        log "rkhunter installed."
    fi

    chkrootkit -q >> "$LOG_FILE" 2>&1
    rkhunter --update >> "$LOG_FILE" 2>&1
    rkhunter -c --skip-keypress >> "$LOG_FILE" 2>&1

    log "Rootkit check completed."

    log "Additional security measures implemented."
}

# Main function
main() {
    log "Starting Metasploitable 3 hardening script..."

    stop_and_disable_services
    configure_firewall
    remove_unnecessary_software
    secure_configurations
    implement_additional_security

    log "Metasploitable 3 hardening script completed."
}

# Execute main function
main



}

