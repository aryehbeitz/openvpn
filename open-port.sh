#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Detect default network interface
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$DEFAULT_IFACE" ]; then
    echo "Error: could not detect default network interface"
    exit 1
fi
echo "Default interface: $DEFAULT_IFACE"

# ── 1. UFW port rule ─────────────────────────────────────────────────────────
echo "[1/5] Opening port 995/tcp in UFW..."
ufw allow 995/tcp comment 'OpenVPN'

# ── 2. UFW forwarding policy ─────────────────────────────────────────────────
echo "[2/5] Ensuring UFW forward policy is ACCEPT..."
if ! grep -q '^DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw; then
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    echo "  Set DEFAULT_FORWARD_POLICY=ACCEPT"
else
    echo "  Already set"
fi

# ── 3. before.rules — NAT + tun0 forward (persistence across reboots) ────────
echo "[3/5] Configuring /etc/ufw/before.rules for persistence..."
UFW_BEFORE_RULES="/etc/ufw/before.rules"

if ! grep -q "# START OPENVPN RULES" "$UFW_BEFORE_RULES"; then
    cp "$UFW_BEFORE_RULES" "${UFW_BEFORE_RULES}.bak"

    # *nat block must come before *filter
    sed -i "/^# Don't delete these required lines/i\\
# START OPENVPN RULES - NAT table (must be before *filter block)\\
*nat\\
:POSTROUTING ACCEPT [0:0]\\
-A POSTROUTING -s 10.8.0.0\\/24 -o $DEFAULT_IFACE -j MASQUERADE\\
COMMIT\\
# END OPENVPN RULES\\
" "$UFW_BEFORE_RULES"

    # tun0 forward rules inside *filter
    sed -i "/^# ok icmp code for FORWARD/a\\
\\
# OpenVPN: allow forwarding for tun0\\
-A ufw-before-forward -i tun0 -j ACCEPT\\
-A ufw-before-forward -o tun0 -j ACCEPT" "$UFW_BEFORE_RULES"

    echo "  NAT and tun0 forward rules added to before.rules"
else
    echo "  Already present in before.rules"
fi

# ── 4. IP forwarding ─────────────────────────────────────────────────────────
echo "[4/5] Ensuring IP forwarding is enabled..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -q -w net.ipv4.ip_forward=1
echo "  IP forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"

# ── 5. Apply live iptables rules idempotently (avoid duplicates on reload) ───
echo "[5/5] Applying live iptables rules..."

# Reload UFW first so before.rules gets applied, then check what's missing
ufw reload > /dev/null

# NAT MASQUERADE — add only if not already present (before.rules may have added it)
if ! iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE
    echo "  NAT MASQUERADE rule added"
else
    echo "  NAT MASQUERADE rule already active"
fi

# tun0 forward — add only if not already present
if ! iptables -C ufw-before-forward -i tun0 -j ACCEPT 2>/dev/null; then
    iptables -I ufw-before-forward -i tun0 -j ACCEPT
    echo "  tun0 inbound forward rule added"
else
    echo "  tun0 inbound forward rule already active"
fi

if ! iptables -C ufw-before-forward -o tun0 -j ACCEPT 2>/dev/null; then
    iptables -I ufw-before-forward -o tun0 -j ACCEPT
    echo "  tun0 outbound forward rule added"
else
    echo "  tun0 outbound forward rule already active"
fi

# ── Verify ───────────────────────────────────────────────────────────────────
echo ""
echo "=== Verification ==="
echo "UFW 995/tcp:"
ufw status | grep 995

echo "NAT MASQUERADE for 10.8.0.0/24:"
iptables -t nat -L POSTROUTING -n -v | grep "10\.8\.0" || echo "  WARNING: rule not found"

echo "tun0 forward rules:"
iptables -L ufw-before-forward -n -v | grep tun0 || echo "  WARNING: rules not found"

echo ""
echo "Done."
