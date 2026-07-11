#!/usr/bin/env python3
"""
Lulz Honeypot — Cowrie log shipper.
Tails Cowrie's JSON event log and POSTs new events to the main dashboard's
/api/ingest endpoint, so SSH attacks appear in the live feed + globe.

Env:
  DASH_URL      dashboard base URL (default http://127.0.0.1:8096)
  INGEST_TOKEN  must match the dashboard's INGEST_TOKEN (canary.env)
  COWRIE_LOG    path to cowrie.json (default below)

Run via systemd (cowrie-shipper.service). Pure stdlib.
"""
import json, os, time, urllib.request
from pathlib import Path

DASH = os.environ.get("DASH_URL", "http://127.0.0.1:8096").rstrip("/")
TOKEN = os.environ.get("INGEST_TOKEN", "")
LOG = Path(os.environ.get("COWRIE_LOG",
      "/var/lib/docker/volumes/lulz-ssh-honeypot_cowrie-var/_data/log/cowrie/cowrie.json"))
WANT = {"cowrie.login.success", "cowrie.login.failed", "cowrie.command.input", "cowrie.session.connect"}


def post(batch):
    data = "\n".join(json.dumps(e) for e in batch).encode()
    req = urllib.request.Request(DASH + "/api/ingest", data=data,
        headers={"Content-Type": "application/x-ndjson", "X-Ingest-Token": TOKEN})
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:
        print("[!] ship failed:", e)


def follow():
    if not TOKEN:
        raise SystemExit("set INGEST_TOKEN (must match dashboard)")
    print(f"[*] shipping {LOG} -> {DASH}/api/ingest")
    while not LOG.exists():
        print("[..] waiting for cowrie log to appear…"); time.sleep(5)
    with LOG.open() as f:
        f.seek(0, 2)                      # start at end (only new events)
        buf = []
        while True:
            line = f.readline()
            if not line:
                if buf:
                    post(buf); buf = []
                time.sleep(1); continue
            try:
                ev = json.loads(line)
                if ev.get("eventid") in WANT:
                    buf.append(ev)
                    if len(buf) >= 20:
                        post(buf); buf = []
            except Exception:
                pass


if __name__ == "__main__":
    follow()
