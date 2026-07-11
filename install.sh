#!/usr/bin/env bash
# =====================================================================
#  Lulz Honeypot — remote one-liner installer.
#  Clones the repo and runs setup.sh. Meant to be curl-piped:
#
#    curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/install.sh \
#      | sudo DOMAIN=honeypot.yourdomain.com bash
#
#  Env:
#    DOMAIN   (recommended) domain for auto-TLS
#    REPO     override git URL (default set below after you push)
#    BRANCH   default: main
# =====================================================================
set -euo pipefail
REPO="${REPO:-https://github.com/codeyomang/owl-honeypot.git}"   # <-- set after first push
BRANCH="${BRANCH:-main}"
DEST="${DEST:-/opt/owl-honeypot-src}"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
command -v git >/dev/null || { apt-get update -y && apt-get install -y git; }

echo "[*] cloning $REPO ($BRANCH) -> $DEST"
rm -rf "$DEST"
git clone --depth 1 -b "$BRANCH" "$REPO" "$DEST"

cd "$DEST"
chmod +x setup.sh
echo "[*] running installer..."
exec ./setup.sh
