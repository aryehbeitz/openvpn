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
port 1194
proto udp
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

# MTU optimization for mobile devices
tun-mtu 1400
mssfix 1360
push "tun-mtu 1400"
push "mssfix 1360"

# Compression for better performance
compress lz4-v2
push "compress lz4-v2"

# Performance tuning
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
fast-io
tcp-nodelay

# Client configuration
keepalive 10 120
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun

# Logging
status /var/log/openvpn/openvpn-status.log
log-append /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
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

# Allow OpenVPN
ufw allow 1194/udp

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
    echo "Server Port: 1194 (UDP)"
    echo "VPN Network: 10.8.0.0/24"
    echo ""
    echo "Next step: Run ./create-client.sh <client-name> to create client profiles"
else
    echo ""
    echo "✗ Failed to start OpenVPN server"
    echo "Check logs with: journalctl -u openvpn-server@server -n 50"
    exit 1
fi
