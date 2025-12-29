#!/bin/bash
set -e

echo "======================================"
echo "OpenVPN Server Configuration Script"
echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect public IP (prefer IPv4)
echo "[1/5] Detecting server public IP..."
PUBLIC_IP=$(curl -4 -s ifconfig.me 2>/dev/null || curl -4 -s icanhazip.com 2>/dev/null || curl -s ifconfig.me || echo "UNKNOWN")
echo "Detected IP: $PUBLIC_IP"

# Get network interface
echo "[2/5] Detecting network interface..."
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "Default interface: $DEFAULT_IFACE"

# Create server configuration
echo "[3/5] Creating server configuration..."
cat > /etc/openvpn/server/server.conf << EOF
# OpenVPN Server Configuration
# Using TCP 995 (former POP3S port) for better firewall traversal and obfuscation
port 995
proto tcp
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0

# Network configuration
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt

# Push routes to clients
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# MTU optimization - larger MTU for better throughput
# Fragment disabled for better performance (let system handle it)
# MSS fix set to optimize TCP traffic
tun-mtu 1500
mssfix 1440
push "tun-mtu 1500"
push "mssfix 1440"

# Compression for better performance
# Note: Not pushing compression to avoid conflicts with desktop clients
# Clients can enable compression in their config if supported
compress lz4-v2

# Performance tuning - increased buffer sizes for better throughput
sndbuf 1048576
rcvbuf 1048576
push "sndbuf 1048576"
push "rcvbuf 1048576"
fast-io

# TCP-specific optimizations
tcp-nodelay

# Client configuration
keepalive 10 120
ping-timer-rem
user nobody
group nogroup
persist-key
persist-tun

# Modern cipher - AES-128-GCM is faster than AES-256-GCM with same security for VPN
# Allow negotiation of best cipher (AES-128-GCM preferred for speed)
data-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-128-GCM
cipher AES-128-GCM
auth SHA256

# Logging
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
EOF

# Create log directory
mkdir -p /var/log/openvpn

# Set up NAT/Firewall rules with UFW
echo "[4/5] Configuring firewall rules..."

# Check if UFW is installed
if ! command -v ufw > /dev/null; then
    echo "Installing UFW..."
    apt-get install -y ufw
fi

# Configure UFW
echo "Configuring UFW..."

# Allow SSH (to prevent lockout)
ufw allow 22/tcp

# Allow OpenVPN on TCP 995
ufw allow 995/tcp comment 'OpenVPN'

# Enable IP forwarding in UFW
if ! grep -q "^DEFAULT_FORWARD_POLICY=\"ACCEPT\"" /etc/default/ufw; then
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
fi

# Add NAT rules to UFW before.rules
UFW_BEFORE_RULES="/etc/ufw/before.rules"
if ! grep -q "# START OPENVPN RULES" $UFW_BEFORE_RULES; then
    # Backup original file
    cp $UFW_BEFORE_RULES ${UFW_BEFORE_RULES}.backup

    # Add NAT rules at the beginning (after initial comments)
    sed -i "/^# End required lines/a\\
\\
# START OPENVPN RULES\\
# NAT table rules\\
*nat\\
:POSTROUTING ACCEPT [0:0]\\
# Allow traffic from OpenVPN client to $DEFAULT_IFACE\\
-A POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_IFACE -j MASQUERADE\\
COMMIT\\
# END OPENVPN RULES" $UFW_BEFORE_RULES
fi

# Enable UFW
echo "y" | ufw enable

echo "UFW configured and enabled"

# Enable and start OpenVPN
echo "[5/5] Starting OpenVPN server..."
systemctl enable openvpn-server@server
systemctl restart openvpn-server@server

# Wait a moment and check status
sleep 2
if systemctl is-active --quiet openvpn-server@server; then
    echo ""
    echo "✓ OpenVPN server is running!"
    echo ""
    echo "Server IP: $PUBLIC_IP"
    echo "Server Port: 995 (TCP) - using POP3S port for better firewall traversal"
    echo "VPN Network: 10.8.0.0/24"
    echo ""
    echo "Next step: Run ./create-client.sh <client-name> to create client profiles"
else
    echo ""
    echo "✗ Failed to start OpenVPN server"
    echo "Check logs with: journalctl -u openvpn-server@server -n 50"
    exit 1
fi
