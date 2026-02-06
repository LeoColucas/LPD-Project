#!/usr/bin/env bash
set -euo pipefail

ADMIN_IP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-ip)
      ADMIN_IP="${2:-}"
      shift 2
      ;;
    *)
      echo "Usage: $0 [--admin-ip x.x.x.x]"
      exit 1
      ;;
  esac
done

echo "[!] WARNING: This script will set default INPUT policy to DROP and close SSH (22) by default."
if [[ -n "${ADMIN_IP}" ]]; then
  echo "[+] Admin IP allowlist for SSH: ${ADMIN_IP}"
else
  echo "[!] No admin IP provided. If you're connected via SSH, you may lock yourself out."
fi

echo "[+] Resetting INPUT chain and policies"
sudo iptables -F INPUT
sudo iptables -P INPUT DROP

echo "[+] Allow established/related"
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[+] Allow loopback"
sudo iptables -A INPUT -i lo -j ACCEPT

if [[ -n "${ADMIN_IP}" ]]; then
  echo "[+] Allow SSH from admin IP first (safety)"
  sudo iptables -I INPUT 1 -p tcp -s "${ADMIN_IP}" --dport 22 -j ACCEPT
fi

echo "[+] Close SSH by default"
sudo iptables -A INPUT -p tcp --dport 22 -j DROP

echo "[+] Allow ICMP ping (optional)"
sudo iptables -A INPUT -p icmp -j ACCEPT

echo "[+] Saving rules"
sudo netfilter-persistent save

echo "[+] Current rules:"
sudo iptables -L INPUT -n --line-numbers

echo "[+] Done."
