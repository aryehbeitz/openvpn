#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "Opening OpenVPN port 995/tcp in UFW..."

ufw allow 995/tcp comment 'OpenVPN'

echo "Done. Port 995/tcp open"
ufw status | grep 995
