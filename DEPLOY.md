# Lulz Honeypot — Deploy Guide

A real, single-page **SOC-console honeypot**: logs genuine attack traffic,
classifies it with Suricata-style signatures, plots sources on a 3D globe +
world map (GeoIP), tracks severity/threshold/brute-force, and serves decoy
endpoints seeded with **live Canarytokens** that email you when tripped.

## What's in this folder
```
server.py             # the honeypot app (Python stdlib only, no pip deps)
index.html style.css app.js   # the SOC-console UI
lulz-honeypot.rules    # Suricata-format ruleset (loadable into real Suricata)
Caddyfile             # reverse proxy: auto-TLS + real-IP passthrough + headers
lulz-honeypot.service  # systemd unit (24/7, auto-restart, sandboxed)
setup.sh              # one-shot installer for Debian/Ubuntu
```

## Requirements
- A **Linux VPS** (Debian/Ubuntu easiest) with a **public IP**
- **Python 3** (stdlib only — no packages needed)
- A **domain name** pointed at the server (for HTTPS). Optional but recommended.

---

## Quick deploy (recommended — one command)
On a fresh Debian/Ubuntu box, copy this folder over, then:
```bash
# 1) point a DNS A record: honeypot.yourdomain.com -> <server public IP>
# 2) run the installer
cd honeypot-site
sudo DOMAIN=honeypot.yourdomain.com ./setup.sh
```
That installs Python + Caddy, drops the app in `/opt/lulz-honeypot`, starts the
systemd service, and provisions TLS. Visit **https://honeypot.yourdomain.com**.

---

## Manual deploy (any Linux)
```bash
# run the app (binds 127.0.0.1:8096 by default via env)
HONEYPOT_HOST=127.0.0.1 HONEYPOT_PORT=8096 python3 server.py

# put a TLS reverse proxy in front (Caddy shown; nginx works too)
#   edit Caddyfile -> set your domain, then:
caddy run --config Caddyfile
```
Key env vars:
- `HONEYPOT_PORT` (default 8096), `HONEYPOT_HOST` (default 0.0.0.0)
- `HONEYPOT_DATA` — persistence file (default ./honeypot-data.json)
- `GEOIP=off` — disable outbound geo lookups (privacy / offline)

## Run 24/7 (systemd)
```bash
sudo cp lulz-honeypot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lulz-honeypot
journalctl -u lulz-honeypot -f          # live logs
```

## Reverse proxy WITHOUT the installer
Point Caddy (or nginx) at `127.0.0.1:8096` and **forward the real client IP**
(`X-Real-IP` / `X-Forwarded-For` / `Cf-Connecting-Ip`) — the app already reads
those headers so GeoIP and logs show the true attacker, not the proxy.

---

## Persistence
The app auto-saves stats/hits/alerts to `honeypot-data.json` every 30s and on
exit, and reloads on start — so counts and history survive restarts.

## The Canarytokens (already wired)
Decoy `/.env` and `/admin` serve live tokens that email **sdaniel@duck.com**:
- **AWS key** (`/.env`) — fires when the key is used against AWS
- **DNS token** (`/.env` DB/Redis host) — fires on hostname resolution
- **Web-bug** (`/admin` pixel) — fires when the bait page is opened

To rotate/replace them, edit the `CANARY_*` constants near the top of
`server.py`. (These live at canarytokens.org; they keep working independently
of this server.)

## SSH honeypot (Cowrie) — optional, high value
Adds real SSH attack capture (brute-force creds + commands attackers run),
shipped into the same dashboard feed + globe.

```bash
# 1) MOVE YOUR REAL SSH OFF :22 FIRST or you'll lock yourself out!
#    edit /etc/ssh/sshd_config -> Port 2222 ; systemctl restart ssh
#    then re-run harden.sh so ufw allows your new SSH port.
# 2) set INGEST_TOKEN in /opt/lulz-honeypot/canary.env (openssl rand -hex 24)
#    -> same value the dashboard reads.
# 3) deploy Cowrie (needs docker):
cd ssh-honeypot && docker compose up -d
# 4) ship its events to the dashboard:
sudo cp ship-cowrie.py /opt/lulz-honeypot/ssh-honeypot/ 2>/dev/null || true
sudo cp cowrie-shipper.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now cowrie-shipper
```
SSH attacks now appear in the live feed (method=SSH), globe, and severity mix.

> ⚠️ The whole point is Cowrie listens on :22 as the attacker-facing SSH. Your
> real admin SSH MUST be on a different port, key-only, before you do this.

## Feeding real Suricata (optional)
`lulz-honeypot.rules` is valid Suricata syntax — load it on a real Suricata
sensor to get the same detections at the packet level.

## Security notes
- A honeypot *invites* attack traffic — run it on an **isolated box/VPS**, not
  alongside anything sensitive. The systemd unit is sandboxed
  (NoNewPrivileges, ProtectSystem=strict) as defense-in-depth.
- Don't expose port 8096 directly; keep it behind the reverse proxy on
  127.0.0.1 and only open 80/443 at the firewall.
- Data is in-memory + a local JSON file; for long-term intel, ship
  `/api/eve` (Suricata EVE-JSON) to a SIEM.
