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
import json, os, sys, time, urllib.request
from pathlib import Path

def log(*a):
    print(*a); sys.stdout.flush()   # flush so journald shows it live

DASH = os.environ.get("DASH_URL", "http://127.0.0.1:8096").rstrip("/")
TOKEN = os.environ.get("INGEST_TOKEN", "")
# Cowrie may write a live 'cowrie.json' OR dated files 'cowrie.json.YYYY-MM-DD'
# (daily rotation). Follow the NEWEST matching file; switch on rotation.
LOG_DIR = Path(os.environ.get("COWRIE_LOG_DIR",
      "/var/lib/docker/volumes/lulz-ssh-honeypot_cowrie-var/_data/log/cowrie"))
LOG_GLOB = os.environ.get("COWRIE_LOG_GLOB", "cowrie.json*")
WANT = {"cowrie.login.success", "cowrie.login.failed", "cowrie.command.input", "cowrie.session.connect"}

def newest_log():
    files = [p for p in LOG_DIR.glob(LOG_GLOB) if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


def post(batch):
    data = "\n".join(json.dumps(e) for e in batch).encode()
    req = urllib.request.Request(DASH + "/api/ingest", data=data,
        headers={"Content-Type": "application/x-ndjson", "X-Ingest-Token": TOKEN})
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:
        print("[!] ship failed:", e)


def _handle_line(line, buf):
    try:
        ev = json.loads(line)
        if ev.get("eventid") in WANT:
            buf.append(ev)
            if len(buf) >= 20:
                post(buf); buf.clear()
    except Exception:
        pass

def follow():
    if not TOKEN:
        raise SystemExit("set INGEST_TOKEN (must match dashboard)")
    log(f"[*] shipping {LOG_DIR}/{LOG_GLOB} -> {DASH}/api/ingest (follows newest)")
    cur = None
    while cur is None:
        cur = newest_log()
        if cur is None:
            log("[..] no cowrie log yet…"); time.sleep(5)
    log(f"[*] following {cur.name}")
    f = cur.open(); f.seek(0, 2)             # start at end of newest file
    ino = os.fstat(f.fileno()).st_ino
    buf = []
    last_check = 0
    while True:
        line = f.readline()
        if line:
            _handle_line(line, buf)
            continue
        if buf:
            post(buf); buf.clear()
        now = time.time()
        if now - last_check >= 3:
            last_check = now
            try:
                nl = newest_log()
                if nl and nl.stat().st_ino != ino:   # newer dated file appeared
                    for rest in f:            # drain old file's tail
                        _handle_line(rest, buf)
                    if buf: post(buf); buf.clear()
                    f.close()
                    f = nl.open(); f.seek(0, 0)
                    ino = os.fstat(f.fileno()).st_ino
                    log(f"[*] rotation -> now following {nl.name}")
                    continue
            except Exception as e:
                log("[!] rotation check error:", e)
        time.sleep(1)


if __name__ == "__main__":
    follow()
