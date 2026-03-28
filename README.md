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

### 4. Open Cloud Provider Ports (if needed)

**For Oracle Cloud:**
```bash
# If connection fails, run the included port opening script
sudo ./open-port.sh
```

**For other cloud providers:** Ensure your Security Groups/Firewalls allow the OpenVPN port.

### 5. Create Client Profiles

```bash
sudo ./create-client.sh <client-name>
```

Example:
```bash
sudo ./create-client.sh laptop
sudo ./create-client.sh phone
sudo ./create-client.sh work-computer
```

Client profiles are saved to: `clients/<client-name>/<client-name>.ovpn`

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
- Port: 995 (TCP)
- VPN Network: 10.8.0.0/24
- DNS: 8.8.8.8, 8.8.4.4
- Cipher: AES-128-GCM
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

## Oracle Cloud Setup

### Quick Oracle Cloud Deployment

**Recommended approach for Oracle Cloud:**

1. **Use port 443** for better firewall traversal:
```bash
# After setup-server.sh, switch to port 443
sudo systemctl stop nginx  # If nginx is running
sudo sed -i 's/port 1194/port 443/' /etc/openvpn/server/server.conf
sudo systemctl restart openvpn-server@server
```

2. **Configure Security Lists** via Oracle Console or OCI CLI:
```bash
# Install OCI CLI
pipx install oci-cli
oci setup config

# Add Security List rule for OpenVPN
oci network security-list update --security-list-id YOUR_SECURITY_LIST_ID \
  --ingress-security-rules '[{
    "description": "OpenVPN Server",
    "protocol": "6",
    "source": "0.0.0.0/0",
    "tcp-options": {"destination-port-range": {"max": 443, "min": 443}}
  }]' --force
```

3. **Handle Docker conflicts** (if Docker is installed):
```bash
# Add VPN forwarding rules before Docker rules
sudo iptables -I FORWARD 1 -s 10.8.0.0/24 -j ACCEPT
sudo iptables -I FORWARD 1 -d 10.8.0.0/24 -j ACCEPT
```

### Oracle Cloud Troubleshooting

**Connection fails but server is running:**
- Security List rules can take 3-10 minutes to propagate
- Check both Security Lists and Network Security Groups
- Port 443 typically propagates faster than port 1194

**No internet access through VPN:**
- Check for Docker iptables conflicts: `sudo iptables -L FORWARD -v`
- Ensure correct TUN interface forwarding rules
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed diagnosis

## Troubleshooting

### Server won't start
```bash
sudo journalctl -u openvpn-server@server -n 50
```

### Connection issues
- Check firewall: `sudo ufw status`
- Verify port is open: `nc -v SERVER_IP PORT`
- Check public IP in client profile matches server

### Can't access internet through VPN
- Verify IP forwarding: `sysctl net.ipv4.ip_forward`
- Check NAT rules: `sudo iptables -t nat -L`
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for comprehensive guide

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
