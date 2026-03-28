# OpenVPN Server — Configuration Reference

## Architecture

OpenVPN over TCP port 80 for firewall traversal. nginx handles HTTPS on port 443 directly (no SNI stream proxy). Port 80 is owned exclusively by OpenVPN — no HTTP redirects.

## Server Details

- **Host**: Oracle Cloud (OCI), Ubuntu 24.04
- **Interface**: `ens3`, internal IP `10.0.0.159`
- **Public IP**: detected at runtime via `curl -4 ifconfig.me`
- **VPN subnet**: `10.8.0.0/24`, server is `10.8.0.1`
- **Active service**: `openvpn@server.service` → reads `/etc/openvpn/server.conf`
- **PKI**: `/root/openvpn-ca/` (Easy-RSA, run as root)
- **Server certs**: `/etc/openvpn/ca.crt`, `server.crt`, `server.key` (symlinked/copied from `/root/openvpn-ca/pki/`)
- **HMAC key**: `/etc/openvpn/ta.key`

## Active Server Config (`/etc/openvpn/server.conf`)

```
port 80
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
keepalive 10 120
data-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305
cipher AES-128-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log-append /var/log/openvpn.log
verb 4
client-config-dir /etc/openvpn/ccd
route 192.168.0.0 255.255.0.0
route 172.16.0.0 255.240.0.0
```

## Client Config Dir (`/etc/openvpn/ccd/`)

Each client file (e.g. `phone`, `laptop`, `work-computer`) contains:
```
iroute 192.168.0.0 255.255.0.0
iroute 172.16.0.0 255.240.0.0
```

These `iroute` entries are required because Android OpenVPN Connect sends packets with the phone's LAN IP (e.g. `192.168.1.252`) as the source address instead of the assigned VPN IP (`10.8.0.4`). Without `iroute`, OpenVPN rejects them as "bad source address".

## iptables / NAT

Key rules that must be in place:

```bash
# FORWARD chain — rule 1 (top)
iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT

# POSTROUTING — masquerade VPN traffic going out to internet
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -o ens3 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.16.0.0/12 -o ens3 -j MASQUERADE
```

Rules are persisted via `iptables-persistent` / `netfilter-persistent save`.

## OCI Security List

Port 80/TCP must be open in the Oracle Cloud VCN Security List (separate from UFW). Managed via OCI CLI — UFW alone is not sufficient.

## Generating Client Profiles

```bash
sudo ./create-client.sh <name>
# e.g.:
sudo ./create-client.sh phone
sudo ./create-client.sh laptop
sudo ./create-client.sh work-computer
```

Profiles are written to `clients/<name>/<name>.ovpn`.

Download to local machine:
```bash
scp ubuntu@<server-ip>:/home/ubuntu/dev/openvpn/openvpn/clients/<name>/<name>.ovpn .
```

## Key Variables in `create-client.sh`

```bash
CA_DIR=/root/openvpn-ca    # Easy-RSA PKI — must run as root
SERVER_DIR=/etc/openvpn    # ca.crt and ta.key live here
```

The script pulls:
- CA cert from `$SERVER_DIR/ca.crt`
- Client cert from `$CA_DIR/pki/issued/<name>.crt`
- Client key from `$CA_DIR/pki/private/<name>.key`
- TLS auth key from `$SERVER_DIR/ta.key`

## Known Pitfalls

### Two OpenVPN instances create conflicting routes
`openvpn-server@server.service` (reads `/etc/openvpn/server/server.conf`) and `openvpn@server.service` (reads `/etc/openvpn/server.conf`) can run simultaneously. If both are up, they both claim `10.8.0.0/24`, creating conflicting kernel routes that silently break return traffic. **Only `openvpn@server` should run.**

```bash
sudo systemctl stop openvpn-server@server
sudo systemctl disable openvpn-server@server
```

### Android "bad source address"
Android OpenVPN Connect sends data-channel packets sourced from the phone's WiFi LAN IP (e.g. `192.168.1.252`) instead of its assigned VPN IP. This requires `iroute` in the CCD file — without it the server drops these packets. The `route` directives in `server.conf` tell the kernel to route that subnet back through the VPN tunnel.

### CA hierarchy mismatch
There are two CA roots: `/home/ubuntu/openvpn-ca/` (ubuntu's, password-protected key) and `/root/openvpn-ca/` (root's). The server certs and client certs must all be signed by the same CA. Running `sudo ./create-client.sh` uses root's CA (`/root/openvpn-ca/`), which must match the CA cert deployed at `/etc/openvpn/ca.crt`.

### No compression
Do NOT add `compress lz4-v2` or any compression directive. Android OpenVPN Connect only supports compression stubs (`IV_COMP_STUB=1`), not full LZ4v2. Mismatched compression causes packet misframing and connection drops.

### `redirect-gateway autolocal`
Do NOT use `autolocal` flag. On Android it excludes all routes because all traffic goes through the local WiFi gateway, resulting in zero traffic through the VPN.

## nginx

nginx is on port 443 only. No port 80 blocks anywhere (OpenVPN owns 80).

Active sites: `tools.aryeh.win` only (all `aryeh.site` entries removed).

Stream block removed from `nginx.conf` — no SNI-based multiplexing.
