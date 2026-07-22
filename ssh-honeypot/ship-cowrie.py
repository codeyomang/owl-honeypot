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


def _handle_line(line, buf):
    try:
        ev = json.loads(line)
        if ev.get("eventid") in WANT:
            buf.append(ev)
            if len(buf) >= 20:
                post(buf); buf.clear()
    except Exception:
        pass

def _open_at_end():
    while not LOG.exists():
        log("[..] waiting for cowrie log to appear…"); time.sleep(5)
    f = LOG.open()
    f.seek(0, 2)
    return f, os.fstat(f.fileno()).st_ino

def follow():
    if not TOKEN:
        raise SystemExit("set INGEST_TOKEN (must match dashboard)")
    log(f"[*] shipping {LOG} -> {DASH}/api/ingest (rotation-aware)")
    f, ino = _open_at_end()
    buf = []
    last_check = 0
    while True:
        line = f.readline()
        if line:
            _handle_line(line, buf)
            continue
        # no new line: flush, then check for log ROTATION
        if buf:
            post(buf); buf.clear()
        now = time.time()
        if now - last_check >= 2:
            last_check = now
            try:
                # if cowrie.json now points at a different inode, it rotated:
                # finish reading the old handle, then reopen the fresh file
                if LOG.exists() and os.stat(LOG).st_ino != ino:
                    for rest in f:           # drain tail of the rotated file
                        _handle_line(rest, buf)
                    if buf: post(buf); buf.clear()
                    f.close()
                    f = LOG.open(); f.seek(0, 0)   # read new file from start
                    ino = os.fstat(f.fileno()).st_ino
                    log("[*] detected log rotation -> reopened cowrie.json")
                    continue
            except Exception as e:
                log("[!] rotation check error:", e)
        time.sleep(1)


if __name__ == "__main__":
    follow()
