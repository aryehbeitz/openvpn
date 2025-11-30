#!/bin/bash
set -e

echo "======================================"
echo "OpenVPN Server Installation Script"
echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Update package list
echo "[1/4] Updating package list..."
apt-get update -qq

# Install OpenVPN and Easy-RSA
echo "[2/4] Installing OpenVPN and Easy-RSA..."
apt-get install -y openvpn easy-rsa

# Create necessary directories
echo "[3/4] Creating directory structure..."
mkdir -p /etc/openvpn/server
mkdir -p /etc/openvpn/client
mkdir -p ~/openvpn-ca

# Enable IP forwarding
echo "[4/4] Enabling IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p > /dev/null 2>&1

echo ""
echo "✓ Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Run ./setup-ca.sh to set up the Certificate Authority"
echo "  2. Run ./setup-server.sh to configure the OpenVPN server"
echo "  3. Run ./create-client.sh <client-name> to create client profiles"
