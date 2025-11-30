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

# Detect public IP
echo "[1/5] Detecting server public IP..."
PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "UNKNOWN")
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

# Set up NAT/Firewall rules
echo "[4/5] Configuring firewall rules..."

# Add iptables rules for NAT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $DEFAULT_IFACE -j MASQUERADE

# Save iptables rules
if command -v netfilter-persistent > /dev/null; then
    netfilter-persistent save
elif command -v iptables-save > /dev/null; then
    iptables-save > /etc/iptables/rules.v4
fi

# Allow OpenVPN through UFW if it's active
if command -v ufw > /dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 1194/udp
    echo "UFW rule added for port 1194/udp"
fi

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
