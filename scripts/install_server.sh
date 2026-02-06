#!/usr/bin/env bash
set -euo pipefail

echo "[+] Updating packages"
sudo apt update

echo "[+] Installing knockd + tools"
sudo apt install -y knockd iptables-persistent netcat-openbsd

echo "[+] Done."
