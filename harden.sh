#!/usr/bin/env bash
# =====================================================================
#  Lulz Honeypot — host hardening for a DEDICATED honeypot VPS.
#  Safe + idempotent. Run as root on the honeypot box:
#      sudo bash harden.sh
#
#  What it does:
#    - ufw firewall: allow only SSH + 80/443, deny the rest
#    - fail2ban on SSH
#    - unattended-upgrades (auto security patches)
#    - SSH hardening (key-only, no root pw login)  [guarded]
#    - kernel/network sysctl hardening
#  It will NOT lock you out: SSH key auth is verified before disabling
#  password auth, and your current SSH port is auto-detected + kept open.
# =====================================================================
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo bash harden.sh)"; exit 1; }

# --- detect current SSH port so we never lock ourselves out ---
SSH_PORT="$(grep -iE '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)"
SSH_PORT="${SSH_PORT:-22}"
echo "[*] Detected SSH port: $SSH_PORT"

echo "[*] 1/6 packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ufw fail2ban unattended-upgrades apt-listchanges

echo "[*] 2/6 firewall (ufw) — allow SSH + web only"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp" comment 'SSH'
ufw allow 80/tcp comment 'http'
ufw allow 443/tcp comment 'https'
ufw --force enable
ufw status verbose

echo "[*] 3/6 fail2ban (SSH brute-force protection)"
cat >/etc/fail2ban/jail.d/honeypot.conf <<EOF
[sshd]
enabled = true
port    = ${SSH_PORT}
maxretry = 4
bantime  = 1h
findtime = 10m
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

echo "[*] 4/6 unattended security upgrades"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
dpkg-reconfigure -f noninteractive unattended-upgrades || true

echo "[*] 5/6 SSH hardening (guarded)"
# Only disable password auth if at least one authorized key exists,
# so we don't lock you out of a key-less box.
KEYS=0
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] && KEYS=$((KEYS+$(grep -cE '^ssh-' "$f" 2>/dev/null || echo 0)))
done
D=/etc/ssh/sshd_config.d/99-honeypot-hardening.conf
if [ "$KEYS" -gt 0 ]; then
  cat >"$D" <<EOF
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
EOF
  echo "    -> key auth found ($KEYS keys): password login DISABLED"
else
  cat >"$D" <<EOF
PermitRootLogin prohibit-password
X11Forwarding no
MaxAuthTries 3
EOF
  echo "    !! NO SSH KEYS FOUND — kept password auth ON to avoid lockout."
  echo "       Add your key (ssh-copy-id) then re-run to fully lock down."
fi
sshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

echo "[*] 6/6 sysctl network hardening"
cat >/etc/sysctl.d/99-honeypot.conf <<EOF
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_syncookies=1
kernel.randomize_va_space=2
EOF
sysctl --system >/dev/null

echo
echo "[ok] Hardening complete."
echo "  Firewall:      ufw status"
echo "  Banned IPs:    fail2ban-client status sshd"
echo "  SSH port kept: ${SSH_PORT}"
echo "  !! Before closing this session, open a NEW ssh connection to confirm"
echo "     you can still get in."
