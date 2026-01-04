#!/bin/bash

# =========================================================
#  ALIAHORAN OCSERV INSTALLER - ULTIMATE EDITION
#  Version: 3.0 (Stable/API-Ready)
#  Created by: Aliahoran
# =========================================================

# --- Colors & Styles ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Configuration ---
VPN_PORT=443
API_PORT=8080
API_TOKEN="12345678900"
WWW_DIR="/var/www/html"
OCSERV_CONF="/etc/ocserv/ocserv.conf"

# --- Functions ---

function print_logo() {
    clear
    echo -e "${CYAN}"
    echo "    _    _ _       _                          "
    echo "   / \  | (_) __ _| |__   ___  _ __ __ _ _ __ "
    echo "  / _ \ | | |/ _\` | '_ \ / _ \| '__/ _\` | '_ \ "
    echo " / ___ \| | | (_| | | | | (_) | | | (_| | | | |"
    echo "/_/   \_\_|_|\__,_|_| |_|\___/|_|  \__,_|_| |_|"
    echo -e "${NC}"
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${YELLOW}   Cisco AnyConnect VPN Server Installer${NC}"
    echo -e "${YELLOW}   Created by Aliahoran${NC}"
    echo -e "${BLUE}=================================================${NC}"
    echo ""
}

function check_status() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✔] Success: $1${NC}"
    else
        echo -e "${RED}[✘] Error: $1 failed!${NC}"
        echo -e "${YELLOW}>>> Troubleshooting Tip: $2${NC}"
        exit 1
    fi
}

function section_title() {
    echo -e "\n${BLUE}>>> $1...${NC}"
    sleep 1
}

# --- Start Installation ---

print_logo
echo -e "${YELLOW}Starting installation in 3 seconds...${NC}"
sleep 3

# 1. Root Check
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root (sudo bash install_aliahoran.sh)${NC}"
  exit
fi

# 2. Kill Firewall (Make it wide open)
section_title "Disabling Firewalls & Cleaning IPTables"
ufw disable > /dev/null 2>&1
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
check_status "Firewall disabled" "Check if you have another firewall like AWS Security Group or Hetzner Cloud Firewall."

# 3. System Update
section_title "Updating System Repositories"
export DEBIAN_FRONTEND=noninteractive
apt-get update
check_status "System Update" "Check your internet connection or DNS settings (try changing DNS to 8.8.8.8)."

# 4. Install Packages
section_title "Installing Dependencies (OCServ, Apache, PHP)"
apt-get install -y ocserv gnutls-bin apache2 php libapache2-mod-php curl nano iptables-persistent
check_status "Package Installation" "Try running 'apt-get --fix-broken install' manually."

# 5. Enable BBR
section_title "Enabling TCP BBR Congestion Control"
if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
fi
sysctl -p > /dev/null 2>&1
echo -e "${GREEN}[✔] BBR Enabled.${NC}"

# 6. SSL Certificates
section_title "Generating SSL Certificates"
mkdir -p /etc/ocserv/ssl
cd /etc/ocserv/ssl

# CA Template
cat <<EOF > ca.tmpl
cn = "Aliahoran VPN CA"
organization = "Aliahoran"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
EOF

# Server Template
cat <<EOF > server.tmpl
cn = "VPN Server"
organization = "Aliahoran"
expiration_days = 3650
signing_key
encryption_key
tls_www_server
EOF

certtool --generate-privkey --outfile ca-key.pem > /dev/null 2>&1
certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem > /dev/null 2>&1
certtool --generate-privkey --outfile server-key.pem > /dev/null 2>&1
certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem > /dev/null 2>&1

# Copy certs
cp ca-cert.pem /etc/ocserv/
cp server-cert.pem /etc/ocserv/
cp server-key.pem /etc/ocserv/

if [ -f "/etc/ocserv/server-cert.pem" ]; then
    echo -e "${GREEN}[✔] Certificates Generated.${NC}"
else
    echo -e "${RED}[✘] Certificate generation failed.${NC}"
    exit 1
fi

# 7. Configure OCServ
section_title "Configuring OCServ (Optimized)"
cat <<EOF > $OCSERV_CONF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $VPN_PORT
# udp-port = $VPN_PORT
run-as-user = ocserv
run-as-group = ocserv
socket-file = /var/run/ocserv-socket
server-cert = /etc/ocserv/server-cert.pem
server-key = /etc/ocserv/server-key.pem
ca-cert = /etc/ocserv/ca-cert.pem
isolate-workers = false
max-clients = 100
max-same-clients = 2
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = false
server-stats-reset-time = 604800
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.3"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = aliahoran.com
ipv4-network = 10.10.10.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 1.1.1.1
ping-leases = false
cisco-client-compat = true
dtls-legacy = true
mtu = 1200
EOF

touch /etc/ocserv/ocpasswd
check_status "Configuration Written" "Disk might be full or permissions denied."

# 8. Apache & API Setup
section_title "Setting up Apache & PHP API"
sed -i "s/Listen 80/Listen $API_PORT/" /etc/apache2/ports.conf
sed -i "s/:80/:$API_PORT/" /etc/apache2/sites-available/000-default.conf

# API Code
cat <<EOF > $WWW_DIR/api.php
<?php
// Created by Aliahoran
\$SECRET_TOKEN = "$API_TOKEN"; 

header('Content-Type: application/json');

// Check Token
if (!isset(\$_POST['token']) || \$_POST['token'] !== \$SECRET_TOKEN) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Invalid Token']);
    exit;
}

\$action = \$_POST['action'] ?? '';

if (\$action === 'create_user') {
    \$username = escapeshellcmd(\$_POST['username']);
    \$password = escapeshellarg(\$_POST['password']); 
    \$cmd = "echo \$password | sudo /usr/bin/ocpasswd -c /etc/ocserv/ocpasswd \$username";
    exec(\$cmd, \$output, \$return_var);
    if (\$return_var === 0) echo json_encode(['status' => 'success', 'message' => "User created."]);
    else echo json_encode(['status' => 'error', 'message' => 'Failed to create user.']);
}
elseif (\$action === 'change_password') {
    \$username = escapeshellcmd(\$_POST['username']);
    \$password = escapeshellarg(\$_POST['password']); 
    \$cmd = "echo \$password | sudo /usr/bin/ocpasswd -c /etc/ocserv/ocpasswd \$username";
    exec(\$cmd, \$output, \$return_var);
    if (\$return_var === 0) echo json_encode(['status' => 'success', 'message' => "Password changed."]);
    else echo json_encode(['status' => 'error', 'message' => 'Failed to change password.']);
}
elseif (\$action === 'delete_user') {
    \$username = escapeshellcmd(\$_POST['username']);
    // Just remove from file, do not disconnect to prevent crash
    \$cmd = "sudo /usr/bin/ocpasswd -c /etc/ocserv/ocpasswd -d " . escapeshellarg(\$username);
    exec(\$cmd, \$output, \$return_var);
    echo json_encode(['status' => 'success', 'message' => "User deleted."]);
}
elseif (\$action === 'get_online_users') {
    \$cmd = "sudo /usr/bin/occtl -j show users";
    exec(\$cmd, \$output);
    echo implode("\n", \$output) ?: "[]";
}
else {
    echo json_encode(['status' => 'error', 'message' => 'Invalid action']);
}
?>
EOF
rm -f $WWW_DIR/index.html

# Sudoers for API
echo "www-data ALL=(ALL) NOPASSWD: /usr/bin/ocpasswd" > /etc/sudoers.d/ocserv-api
echo "www-data ALL=(ALL) NOPASSWD: /usr/bin/occtl" >> /etc/sudoers.d/ocserv-api
chmod 0440 /etc/sudoers.d/ocserv-api
check_status "API & Permissions" "Apache might not be installed correctly."

# 9. Network Forwarding
section_title "Applying Network NAT Rules"
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p > /dev/null 2>&1
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables-save > /etc/iptables/rules.v4
check_status "NAT & Forwarding" "Kernel might not support forwarding."

# 10. Service Restart
section_title "Restarting Services"
systemctl restart apache2
systemctl enable ocserv
systemctl restart ocserv
check_status "Services Restarted" "Check logs: journalctl -u ocserv -f"

# --- Final Info ---
PUBLIC_IP=$(curl -s ifconfig.me)

print_logo
echo -e "${GREEN} INSTALLATION COMPLETE SUCCESSFULLY! ${NC}"
echo -e "${BLUE}-------------------------------------------------${NC}"
echo -e "${YELLOW} ► Server IP:${NC}      $PUBLIC_IP"
echo -e "${YELLOW} ► Cisco Port:${NC}    $VPN_PORT (TCP Only)"
echo -e "${YELLOW} ► API URL:${NC}       http://$PUBLIC_IP:$API_PORT/api.php"
echo -e "${YELLOW} ► API Token:${NC}     $API_TOKEN"
echo -e "${BLUE}-------------------------------------------------${NC}"
echo -e " ${CYAN}Created by Aliahoran${NC}"
echo -e " ${CYAN}Enjoy your private network!${NC}"
echo ""
