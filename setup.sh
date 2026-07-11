#!/usr/bin/env bash
# =====================================================================
#  Lulz Honeypot — one-shot installer for a fresh Debian/Ubuntu box.
#  Installs the app to /opt/lulz-honeypot, sets up the systemd service,
#  installs Caddy, and wires TLS for your domain.
#
#  Usage:
#    sudo DOMAIN=honeypot.yourdomain.com ./setup.sh
#  (run from inside the honeypot-site/ folder)
# =====================================================================
set -euo pipefail
DOMAIN="${DOMAIN:-}"
APP=/opt/lulz-honeypot
SRC="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

echo "[*] 1/6 deps (python3, caddy)"
apt-get update -y
apt-get install -y python3 debian-keyring debian-archive-keyring apt-transport-https curl
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi

echo "[*] 2/6 app user + files -> $APP"
id honeypot &>/dev/null || useradd --system --home "$APP" --shell /usr/sbin/nologin honeypot
mkdir -p "$APP"
cp "$SRC"/server.py "$SRC"/index.html "$SRC"/style.css "$SRC"/app.js "$SRC"/lulz-honeypot.rules "$APP"/
# canary secrets: copy canary.env if present (never in git), else drop the example
if [ -f "$SRC"/canary.env ]; then cp "$SRC"/canary.env "$APP"/canary.env; chmod 600 "$APP"/canary.env
else cp "$SRC"/canary.env.example "$APP"/canary.env.example
  echo "    !! no canary.env - copy canary.env.example -> $APP/canary.env and add your tokens"; fi
chown -R honeypot:honeypot "$APP"

echo "[*] 3/6 systemd service"
cp "$SRC"/lulz-honeypot.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now lulz-honeypot

echo "[*] 4/6 Caddy config"
if [ -n "$DOMAIN" ]; then
  sed "s/honeypot.example.com/$DOMAIN/" "$SRC"/Caddyfile > /etc/caddy/Caddyfile
  systemctl restart caddy
  echo "    -> TLS will provision for https://$DOMAIN on first request"
else
  echo "    !! no DOMAIN set — skipping Caddy TLS. Set DOMAIN=... and re-run,"
  echo "       or point Caddy at 127.0.0.1:8096 manually."
fi

echo "[*] 5/6 firewall (allow 80/443 if ufw present)"
if command -v ufw >/dev/null; then ufw allow 80,443/tcp || true; fi

echo "[*] 6/6 done."
systemctl --no-pager status lulz-honeypot | head -5
echo
echo "  Honeypot:  http://127.0.0.1:8096  (behind Caddy at your domain)"
echo "  Logs:      journalctl -u lulz-honeypot -f"
echo "  Data:      $APP/honeypot-data.json (persists across restarts)"
