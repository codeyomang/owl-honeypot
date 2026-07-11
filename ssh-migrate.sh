#!/usr/bin/env bash
# =====================================================================
#  Lulz Honeypot — safely move admin SSH off :22 (so Cowrie can take it)
#  WITH auto-rollback so you can't lock yourself out.
#
#  Run on the server as root:
#      sudo NEWPORT=2222 bash ssh-migrate.sh
#
#  What it does:
#    1) verifies key auth is enabled (won't proceed on password-only)
#    2) adds a new SSH Port (keeps :22 ALSO listening for now)
#    3) opens the new port in ufw (if ufw active)
#    4) restarts ssh + arms a 5-min auto-rollback timer
#    5) you open a NEW session on the new port and run the confirm cmd;
#       if you DON'T within 5 min, it auto-reverts to :22-only.
# =====================================================================
set -euo pipefail
NEWPORT="${NEWPORT:-2222}"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
CONF=/etc/ssh/sshd_config.d/00-port-migrate.conf
FLAG=/run/ssh-migrate-confirm

echo "[*] target admin SSH port: $NEWPORT"

# 1) require a key to exist (don't strand a password-only box)
KEYS=0
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] && KEYS=$((KEYS+$(grep -cE '^(ssh-|ecdsa-)' "$f" 2>/dev/null || echo 0)))
done
[ "$KEYS" -gt 0 ] || { echo "!! no SSH keys found — aborting (would risk lockout)"; exit 1; }

# 2) listen on BOTH 22 and new port during migration
cat >"$CONF" <<EOF
Port 22
Port $NEWPORT
EOF

# 3) firewall
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "${NEWPORT}/tcp" comment 'ssh-migrate' || true
fi

sshd -t || { echo "!! sshd config test failed, aborting"; rm -f "$CONF"; exit 1; }
systemctl restart ssh 2>/dev/null || systemctl restart sshd

# 4) arm auto-rollback: if $FLAG not created within 5 min, revert to :22 only
cat >/usr/local/sbin/ssh-migrate-rollback <<EOF
#!/usr/bin/env bash
sleep 300
if [ ! -f "$FLAG" ]; then
  echo "Port 22" > "$CONF"
  sshd -t && (systemctl restart ssh 2>/dev/null || systemctl restart sshd)
  logger "ssh-migrate: NOT confirmed in 5min -> rolled back to :22 only"
fi
EOF
chmod +x /usr/local/sbin/ssh-migrate-rollback
rm -f "$FLAG"
setsid /usr/local/sbin/ssh-migrate-rollback >/dev/null 2>&1 &

echo
echo "=================================================================="
echo " SSH now listening on BOTH :22 and :$NEWPORT."
echo
echo " >>> DO THIS NOW, within 5 minutes, in a NEW terminal: <<<"
echo "       ssh -p $NEWPORT root@<this-server>"
echo "     and once in, run:"
echo "       sudo touch $FLAG && echo CONFIRMED"
echo
echo " If you do NOT confirm, it auto-reverts to :22-only (no lockout)."
echo " After you confirm + are happy on :$NEWPORT, finalize with:"
echo "       sudo sed -i 's/^Port 22$//' $CONF && sudo systemctl restart ssh"
echo "   (that drops :22 so Cowrie can take it)"
echo "=================================================================="
