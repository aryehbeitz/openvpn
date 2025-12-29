#!/bin/bash
set -e

echo "======================================"
echo "OpenVPN Client Profile Generator"
echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Check for client name argument
if [ -z "$1" ]; then
    echo "Usage: $0 <client-name>"
    echo "Example: $0 john-laptop"
    exit 1
fi

CLIENT_NAME="$1"
CA_DIR=~/openvpn-ca
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
OUTPUT_DIR=$SCRIPT_DIR/clients
CLIENT_DIR=$OUTPUT_DIR/$CLIENT_NAME

# Validate client name
if [[ ! "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "Error: Client name can only contain letters, numbers, hyphens, and underscores"
    exit 1
fi

# Create output directory
mkdir -p $CLIENT_DIR

# Check if client already exists
if [ -f "$CA_DIR/pki/issued/${CLIENT_NAME}.crt" ]; then
    echo "Warning: Client '$CLIENT_NAME' already exists"
    read -p "Regenerate? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Using existing certificate..."
    else
        cd $CA_DIR
        ./easyrsa --batch revoke $CLIENT_NAME
        ./easyrsa gen-crl
        rm -f pki/reqs/${CLIENT_NAME}.req
        rm -f pki/private/${CLIENT_NAME}.key
        rm -f pki/issued/${CLIENT_NAME}.crt
        echo "Generating new certificate..."
        ./easyrsa --batch build-client-full $CLIENT_NAME nopass
    fi
else
    # Generate client certificate
    echo "[1/3] Generating certificate for '$CLIENT_NAME'..."
    cd $CA_DIR
    ./easyrsa --batch build-client-full $CLIENT_NAME nopass
fi

# Get server IP (prefer IPv4)
echo "[2/3] Detecting server IP..."
PUBLIC_IP=$(curl -4 -s ifconfig.me 2>/dev/null || curl -4 -s icanhazip.com 2>/dev/null || curl -s ifconfig.me || echo "YOUR_SERVER_IP")

# Create client configuration file
echo "[3/3] Creating client profile..."
cat > $CLIENT_DIR/${CLIENT_NAME}.ovpn << EOF
client
dev tun
proto tcp
remote $PUBLIC_IP 995
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
remote-cert-tls server
# Modern cipher - allow negotiation for best performance
data-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-128-GCM
cipher AES-128-GCM
auth SHA256
key-direction 1

# Performance optimizations
# Compression - enable if your client supports it (most do)
compress lz4-v2
# Buffer sizes are pushed by the server

verb 3

<ca>
$(cat $CA_DIR/pki/ca.crt)
</ca>

<cert>
$(openssl x509 -in $CA_DIR/pki/issued/${CLIENT_NAME}.crt)
</cert>

<key>
$(cat $CA_DIR/pki/private/${CLIENT_NAME}.key)
</key>

<tls-auth>
$(cat $CA_DIR/pki/ta.key)
</tls-auth>
EOF

# Set proper permissions and ownership
chmod 600 $CLIENT_DIR/${CLIENT_NAME}.ovpn

# Change ownership to the user who ran sudo (not root)
if [ -n "$SUDO_USER" ]; then
    chown -R $SUDO_USER:$SUDO_USER $OUTPUT_DIR
    echo "Ownership set to: $SUDO_USER"
fi

echo ""
echo "✓ Client profile created successfully!"
echo ""
echo "Profile location: $CLIENT_DIR/${CLIENT_NAME}.ovpn"
echo ""
echo "Transfer this file to your client device and import it into your OpenVPN client."
echo ""
echo "Download command (from your local machine):"
echo "  scp $(whoami)@$PUBLIC_IP:$CLIENT_DIR/${CLIENT_NAME}.ovpn ."
echo ""
echo "Or display the profile content:"
echo "  cat $CLIENT_DIR/${CLIENT_NAME}.ovpn"
