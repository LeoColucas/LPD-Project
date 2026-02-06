#!/usr/bin/env bash
set -euo pipefail

echo "=== knockd status ==="
sudo systemctl --no-pager --full status knockd || true
echo

echo "=== iptables INPUT ==="
sudo iptables -L INPUT -n --line-numbers
echo

echo "=== knockd logs (last 60 lines) ==="
sudo journalctl -u knockd --no-pager | tail -n 60
