#!/usr/bin/env bash
# =====================================================================
#  Migrate a live deploy from the old 'owl-honeypot' names/paths to
#  'lulz-honeypot'. Safe + idempotent. Run as root on the VPS:
#      sudo bash migrate-rename.sh
#
#  Moves:
#    /opt/owl-honeypot        -> /opt/lulz-honeypot
#    /opt/owl-honeypot-src    -> /opt/lulz-honeypot-src
#    systemd owl-honeypot.service -> lulz-honeypot.service
#    rules file owl-honeypot.rules -> lulz-honeypot.rules
#  Keeps your data (honeypot-data.json) and canary.env.
# =====================================================================
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

echo "[*] stopping old services"
systemctl stop owl-honeypot 2>/dev/null || true
systemctl stop cowrie-shipper 2>/dev/null || true

echo "[*] moving app dir /opt/owl-honeypot -> /opt/lulz-honeypot"
if [ -d /opt/owl-honeypot ] && [ ! -d /opt/lulz-honeypot ]; then
  mv /opt/owl-honeypot /opt/lulz-honeypot
fi
if [ -d /opt/owl-honeypot-src ] && [ ! -d /opt/lulz-honeypot-src ]; then
  mv /opt/owl-honeypot-src /opt/lulz-honeypot-src
fi

echo "[*] rename rules file inside app dir"
if [ -f /opt/lulz-honeypot/owl-honeypot.rules ]; then
  mv /opt/lulz-honeypot/owl-honeypot.rules /opt/lulz-honeypot/lulz-honeypot.rules
fi

echo "[*] install renamed systemd units"
# disable/remove old unit
systemctl disable owl-honeypot 2>/dev/null || true
rm -f /etc/systemd/system/owl-honeypot.service
# copy new units from the pulled source (adjust if your src path differs)
SRC=/opt/lulz-honeypot-src
[ -f "$SRC/lulz-honeypot.service" ] && cp "$SRC/lulz-honeypot.service" /etc/systemd/system/
[ -f "$SRC/ssh-honeypot/cowrie-shipper.service" ] && cp "$SRC/ssh-honeypot/cowrie-shipper.service" /etc/systemd/system/

# copy refreshed app files into the (renamed) app dir
if [ -d "$SRC" ]; then
  cp "$SRC"/server.py "$SRC"/app.js "$SRC"/index.html "$SRC"/style.css "$SRC"/lulz-honeypot.rules /opt/lulz-honeypot/ 2>/dev/null || true
  mkdir -p /opt/lulz-honeypot/ssh-honeypot
  cp "$SRC"/ssh-honeypot/ship-cowrie.py /opt/lulz-honeypot/ssh-honeypot/ 2>/dev/null || true
fi

# ownership (service runs as 'honeypot' user)
id honeypot &>/dev/null && chown -R honeypot:honeypot /opt/lulz-honeypot || true

echo "[*] reload + start renamed services"
systemctl daemon-reload
systemctl enable --now lulz-honeypot
systemctl enable --now cowrie-shipper 2>/dev/null || true

echo
echo "[ok] migrated. Verify:"
echo "  systemctl status lulz-honeypot --no-pager | head -5"
echo "  curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:8096/api/feed"
echo "  (old owl-honeypot service/dir are gone; data + canary.env preserved)"
