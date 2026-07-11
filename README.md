# 🕸 Lulz Honeypot

A real, single-page **SOC-console honeypot**. Logs genuine attack traffic,
classifies it with Suricata-style signatures, plots sources on a rotating 3D
globe + world map (GeoIP), tracks severity / brute-force thresholds, and serves
decoy endpoints seeded with live **Canarytokens** that email you when tripped.

Pure Python stdlib — **no pip dependencies**. GatesOS-style terminal UI.

![status](https://img.shields.io/badge/status-live--fire%20ready-34ff66)

## One-liner deploy

On a fresh Debian/Ubuntu VPS with a domain pointed at it:

```bash
curl -fsSL https://raw.githubusercontent.com/codeyomang/lulz-honeypot/main/install.sh \
  | sudo DOMAIN=honeypot.yourdomain.com bash
```

That installs Python + Caddy, deploys the app under `/opt/lulz-honeypot`, starts
the systemd service (24/7, auto-restart), and provisions HTTPS automatically.
Then visit `https://honeypot.yourdomain.com`.

> Replace `OWNER` with your GitHub user/org after you push this repo.

## What it does

- **Live attack feed** — every probe, classified & color-coded by severity
- **Suricata engine** — SIDs, classtypes, EVE-JSON output (`/api/eve`), real `.rules` file
- **GeoIP** — country flags + rotating 3D attack globe / flat map toggle
- **Thresholds** — brute-force / mass-scan detection
- **Honeytokens** — decoy `/.env` + `/admin` seeded with AWS / DNS / web-bug
  Canarytokens (email alerts on trip)
- **Persistence** — survives restarts; SOC-console single-screen UI

## Local run

```bash
python3 server.py            # http://localhost:8096
```

See [`DEPLOY.md`](DEPLOY.md) for manual deploy, env vars, and security notes.

## ⚠️ Note

A honeypot invites attack traffic — run it on an **isolated VPS**, never
alongside anything sensitive. Keep the app bound to `127.0.0.1` behind the
reverse proxy; expose only 80/443.
