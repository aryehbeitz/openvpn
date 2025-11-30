#!/bin/bash
set -e

echo "======================================"
echo "Certificate Authority Setup Script"
echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

CA_DIR=~/openvpn-ca

# Initialize PKI
echo "[1/6] Initializing PKI..."
cd $CA_DIR
if [ -d "pki" ]; then
    read -p "PKI directory already exists. Overwrite? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Aborted."
        exit 1
    fi
    rm -rf pki
fi

# Copy easy-rsa
cp -r /usr/share/easy-rsa/* $CA_DIR/

# Create vars file
cat > $CA_DIR/vars << 'EOF'
set_var EASYRSA_REQ_COUNTRY    "US"
set_var EASYRSA_REQ_PROVINCE   "California"
set_var EASYRSA_REQ_CITY       "San Francisco"
set_var EASYRSA_REQ_ORG        "MyVPN"
set_var EASYRSA_REQ_EMAIL      "admin@myvpn.net"
set_var EASYRSA_REQ_OU         "IT"
set_var EASYRSA_ALGO           "ec"
set_var EASYRSA_DIGEST         "sha512"
EOF

./easyrsa init-pki

# Build CA
echo "[2/6] Building Certificate Authority..."
./easyrsa --batch build-ca nopass

# Generate server certificate and key
echo "[3/6] Generating server certificate..."
./easyrsa --batch build-server-full server nopass

# Generate Diffie-Hellman parameters
echo "[4/6] Generating Diffie-Hellman parameters (this may take a while)..."
./easyrsa gen-dh

# Generate TLS auth key
echo "[5/6] Generating TLS auth key..."
openvpn --genkey secret $CA_DIR/pki/ta.key

# Copy keys to OpenVPN directory
echo "[6/6] Copying certificates to /etc/openvpn/server..."
cp $CA_DIR/pki/ca.crt /etc/openvpn/server/
cp $CA_DIR/pki/issued/server.crt /etc/openvpn/server/
cp $CA_DIR/pki/private/server.key /etc/openvpn/server/
cp $CA_DIR/pki/dh.pem /etc/openvpn/server/
cp $CA_DIR/pki/ta.key /etc/openvpn/server/

chmod 600 /etc/openvpn/server/server.key
chmod 600 /etc/openvpn/server/ta.key

echo ""
echo "✓ Certificate Authority setup complete!"
echo ""
echo "Certificates location: $CA_DIR/pki"
echo "Next step: Run ./setup-server.sh to configure the OpenVPN server"
