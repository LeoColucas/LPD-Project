#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[+] Installing knockd configs from repo"
sudo cp "${REPO_ROOT}/configs/knockd.conf" /etc/knockd.conf
sudo cp "${REPO_ROOT}/configs/knockd.default" /etc/default/knockd

echo "[+] Restarting knockd"
sudo systemctl enable knockd
sudo systemctl restart knockd

echo "[+] knockd status:"
sudo systemctl --no-pager --full status knockd || true

echo "[+] Done."
