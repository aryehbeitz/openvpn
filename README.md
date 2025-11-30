# OpenVPN Server Setup

Automated OpenVPN server setup with shell scripts for easy deployment and client profile generation.

## Features

- Automated installation and configuration
- Certificate Authority (CA) setup with Easy-RSA
- Client profile generation with embedded certificates
- Secure defaults (AES-256-GCM, SHA256, TLS auth)
- NAT/firewall configuration
- Easy client onboarding

## Quick Start

### 1. Install OpenVPN

```bash
sudo ./install-openvpn.sh
```

This installs OpenVPN, Easy-RSA, and prepares the directory structure.

### 2. Set Up Certificate Authority

```bash
sudo ./setup-ca.sh
```

This creates the PKI infrastructure, generates:
- CA certificate
- Server certificate and key
- Diffie-Hellman parameters
- TLS auth key

### 3. Configure and Start Server

```bash
sudo ./setup-server.sh
```

This:
- Detects your public IP
- Creates server configuration
- Sets up firewall/NAT rules
- Starts the OpenVPN service

### 4. Create Client Profiles

```bash
sudo ./create-client.sh <client-name>
```

Example:
```bash
sudo ./create-client.sh laptop
sudo ./create-client.sh phone
sudo ./create-client.sh work-computer
```

Client profiles are saved to: `~/dev/vpn/clients/<client-name>/<client-name>.ovpn`

## Downloading Client Profiles

### Option 1: SCP (from your local machine)

```bash
scp user@server-ip:~/dev/vpn/clients/laptop/laptop.ovpn .
```

### Option 2: Display and copy

```bash
cat ~/dev/vpn/clients/laptop/laptop.ovpn
```

Then copy the output to a `.ovpn` file on your client device.

## Client Setup

### Windows
1. Install [OpenVPN GUI](https://openvpn.net/community-downloads/)
2. Copy the `.ovpn` file to `C:\Program Files\OpenVPN\config\`
3. Run OpenVPN GUI and connect

### macOS
1. Install [Tunnelblick](https://tunnelblick.net/)
2. Double-click the `.ovpn` file to import
3. Connect via Tunnelblick

### Linux
```bash
sudo apt install openvpn
sudo openvpn --config client.ovpn
```

### iOS/Android
1. Install OpenVPN Connect app
2. Import the `.ovpn` file
3. Connect

## Server Configuration

Default settings:
- Port: 1194 (UDP)
- VPN Network: 10.8.0.0/24
- DNS: 8.8.8.8, 8.8.4.4
- Cipher: AES-256-GCM
- Auth: SHA256

Edit `/etc/openvpn/server/server.conf` to customize.

## Management Commands

### Check server status
```bash
sudo systemctl status openvpn-server@server
```

### View logs
```bash
sudo journalctl -u openvpn-server@server -f
```

### View connected clients
```bash
sudo cat /var/log/openvpn/openvpn-status.log
```

### Restart server
```bash
sudo systemctl restart openvpn-server@server
```

### Stop server
```bash
sudo systemctl stop openvpn-server@server
```

## Revoking Client Access

```bash
cd ~/openvpn-ca
./easyrsa revoke <client-name>
./easyrsa gen-crl
sudo cp pki/crl.pem /etc/openvpn/server/
```

Add to `/etc/openvpn/server/server.conf`:
```
crl-verify crl.pem
```

Then restart the server.

## Troubleshooting

### Server won't start
```bash
sudo journalctl -u openvpn-server@server -n 50
```

### Connection issues
- Check firewall: `sudo ufw status`
- Verify port 1194/UDP is open
- Check public IP in client profile matches server

### Can't access internet through VPN
- Verify IP forwarding: `sysctl net.ipv4.ip_forward`
- Check NAT rules: `sudo iptables -t nat -L`

## Security Notes

- Server key and TLS auth key have restricted permissions (600)
- Client keys are embedded in profile files - keep them secure
- Consider using client certificates with passphrases for production
- Regularly update OpenVPN: `sudo apt update && sudo apt upgrade`

## Files and Directories

- `/etc/openvpn/server/` - Server config and certificates
- `~/openvpn-ca/` - Certificate Authority and PKI
- `~/dev/vpn/clients/` - Generated client profiles (in repo, gitignored)
- `/var/log/openvpn/` - Server logs

## License

This setup script is provided as-is for educational and personal use.
