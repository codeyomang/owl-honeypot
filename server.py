#!/usr/bin/env python3
"""
Lulz Honeypot — real self-hit logging + live feed.
Every HTTP request to this server is recorded. Requests matching known
attack/recon patterns (probing for /wp-admin, /.env, /.git, shells, etc.)
are flagged. The one-pager UI polls /api/feed to render hits in real time.

This is a REAL honeypot for its own surface: once published on the public
web, automated scanners will hit it within minutes and you'll see genuine
malicious traffic. No fake data.

Run:  python3 server.py [port]            (default 8096)
Env:  HONEYPOT_PORT, HONEYPOT_HOST, HONEYPOT_DATA (persistence file),
      GEOIP=off  to disable outbound geo lookups.
"""
import json, os, re, sys, time, threading, html, secrets, urllib.request, atexit, signal
from collections import deque, Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("HONEYPOT_PORT", 8096))
HOST = os.environ.get("HONEYPOT_HOST", "0.0.0.0")
DATA_FILE = Path(os.environ.get("HONEYPOT_DATA", HERE / "honeypot-data.json"))
GEOIP_ON = os.environ.get("GEOIP", "on").lower() != "off"

# ---- Suricata-style signatures ----
# each: (regex, msg, sev_word, sid, classtype, severity_num)  where 1=high 2=med 3=low
# SIDs/classtypes mirror owl-honeypot.rules (loadable into real Suricata).
SIGS = [
    (re.compile(r"/\.env\b", re.I),                   "Env-file / secret theft", "high", 9000001, "web-application-attack", 1),
    (re.compile(r"/\.git", re.I),                     "Git repo exposure probe", "high", 9000002, "attempted-recon", 1),
    (re.compile(r"/wp-(admin|login)", re.I),          "WordPress admin probe", "med", 9000003, "attempted-recon", 2),
    (re.compile(r"/(phpmyadmin|pma|adminer)", re.I),  "DB admin probe", "med", 9000004, "attempted-recon", 2),
    (re.compile(r"\.\./|%2e%2e", re.I),               "Path traversal", "high", 9000005, "web-application-attack", 1),
    (re.compile(r"(union\s+select|or\s+1=1|sleep\()", re.I), "SQL injection attempt", "high", 9000006, "web-application-attack", 1),
    (re.compile(r"(<script|onerror=|javascript:)", re.I),   "XSS attempt", "high", 9000007, "web-application-attack", 1),
    (re.compile(r"/(cgi-bin|boaform|shell|cmd|eval)", re.I), "RCE / shell probe", "high", 9000008, "web-application-attack", 1),
    (re.compile(r"/(config|backup|\.aws|\.ssh|id_rsa)", re.I), "Sensitive-file probe", "high", 9000009, "web-application-attack", 1),
    (re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|hydra)", re.I), "Scanner tool signature", "med", 9000010, "attempted-recon", 2),
    (re.compile(r"/(actuator|solr|struts|jenkins|\.php)", re.I), "App-framework probe", "med", 9000011, "attempted-recon", 2),
    (re.compile(r"/(login|admin|manager|owa)\b", re.I), "Admin login probe", "low", 9000012, "attempted-recon", 3),
]

LOCK = threading.Lock()
HITS = deque(maxlen=500)          # recent hits (newest first)
STATS = {"total": 0, "attacks": 0, "start": time.time()}
SEV = {1: 0, 2: 0, 3: 0}          # severity mix: 1=high 2=med 3=low
EPS_TIMES = deque(maxlen=2000)    # request timestamps for events/sec
BY_NET = Counter()               # count by /24
BY_TYPE = Counter()
BY_CLASS = Counter()             # Suricata classtype breakdown
BY_GEO = Counter()               # count by country
EVE = deque(maxlen=500)          # Suricata EVE-JSON alert records

# ---- GeoIP: free lookup w/ in-memory cache + graceful fallback ----
GEO_CACHE = {}
def geo_lookup(ip):
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    g = {"country": "??", "cc": "??"}
    if GEOIP_ON and ip and not ip.startswith(("127.", "10.", "192.168.", "172.")):
        try:
            with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=2) as r:
                d = json.loads(r.read().decode())
                g = {"country": d.get("country", "??"), "cc": d.get("countryCode", "??")}
        except Exception:
            pass
    GEO_CACHE[ip] = g
    return g

# ---- Threshold / brute-force detection (Suricata detection_filter style) ----
THRESH_WINDOW = 60      # seconds
THRESH_COUNT = 15       # hits from one IP in window -> brute/scan alert
IP_TIMES = defaultdict(lambda: deque(maxlen=200))
THRESH_FIRED = {}       # ip -> last fire time (re-arm every window)

# ---- Honeytokens / canary tokens (DEFENSIVE: bait creds we hand out) ----
# Served inside decoy files. If an attacker ever USES one -> canarytokens.org alerts you.
# SECRETS ARE NOT HARDCODED. Supply your real canarytokens.org values at runtime
# via env vars (see canary.env.example). Defaults below are harmless placeholders.
CANARY_AWS_KEY    = os.environ.get("CANARY_AWS_KEY", "AKIAEXAMPLE0PLACEHOLDER")
CANARY_AWS_SECRET = os.environ.get("CANARY_AWS_SECRET", "exampleSecretPlaceholderDoNotUse000000000")
CANARY_WEBBUG     = os.environ.get("CANARY_WEBBUG", "http://canarytokens.com/tags/PLACEHOLDER/post.jsp")
CANARY_DNS        = os.environ.get("CANARY_DNS", "placeholder.canarytokens.com")
# Shared secret for the SSH/Cowrie log shipper to POST events to /api/ingest.
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")   # set in canary.env to enable
HONEYTOKENS = {
    "aws_key":  CANARY_AWS_KEY,
    "api_key":  "owl_live_" + secrets.token_hex(16),
    "session":  secrets.token_hex(24),
}
HONEYTOKEN_HITS = deque(maxlen=100)

# ---- App-layer DDoS / flood detection ----
# NOTE: volumetric (network) DDoS must be handled upstream (Cloudflare /
# provider / the Caddy rate-limit). This detects APP-LAYER floods and raises
# an 'under attack' state on the dashboard.
REQ_TIMES = deque(maxlen=5000)          # global request timestamps (for EPS)
SRC_WINDOW = defaultdict(lambda: deque(maxlen=400))  # per-ip timestamps
DDOS = {
    "level": "normal",     # normal | elevated | under_attack
    "eps": 0.0,            # global requests/sec (10s window)
    "flood_sources": [],   # [(ip, rate_per_min), ...] single-source floods
    "distinct_sources_1m": 0,
    "note": "",
    "since": 0,
}
EPS_ATTACK = float(os.environ.get("DDOS_EPS", 25))      # global req/s -> flood
SRC_FLOOD  = int(os.environ.get("DDOS_SRC_RPM", 300))   # one IP req/min -> flood
DISTRIB_SRC = int(os.environ.get("DDOS_DISTINCT", 40))  # distinct IPs/min at high eps

def ddos_check(ip):
    now = time.time()
    REQ_TIMES.append(now)
    SRC_WINDOW[ip].append(now)
    eps = sum(1 for t in REQ_TIMES if now - t <= 10) / 10.0
    # per-source rate (req in last 60s)
    floods = []
    for s, dq in list(SRC_WINDOW.items()):
        rpm = sum(1 for t in dq if now - t <= 60)
        if rpm >= SRC_FLOOD:
            floods.append((s, rpm))
        # prune idle sources to bound memory
        if dq and now - dq[-1] > 300:
            SRC_WINDOW.pop(s, None)
    distinct = sum(1 for dq in SRC_WINDOW.values() if dq and now - dq[-1] <= 60)
    floods.sort(key=lambda x: -x[1])
    # decide level
    level, note = "normal", ""
    if eps >= EPS_ATTACK and distinct >= DISTRIB_SRC:
        level, note = "under_attack", f"distributed flood: {int(eps)} req/s from {distinct} sources"
    elif floods:
        level, note = "under_attack", f"HTTP flood: {floods[0][0]} @ {floods[0][1]} req/min"
    elif eps >= EPS_ATTACK:
        level, note = "under_attack", f"traffic spike: {int(eps)} req/s"
    elif eps >= EPS_ATTACK * 0.5:
        level, note = "elevated", f"rising traffic: {int(eps)} req/s"
    with LOCK:
        if level != "normal" and DDOS["level"] == "normal":
            DDOS["since"] = int(now)
        DDOS["level"] = level
        DDOS["eps"] = round(eps, 1)
        DDOS["flood_sources"] = floods[:5]
        DDOS["distinct_sources_1m"] = distinct
        DDOS["note"] = note


def classify(path, ua):
    hay = path + " " + ua
    for rx, label, sev, sid, classtype, sevnum in SIGS:
        if rx.search(hay):
            return {"label": label, "sev": sev, "sid": sid,
                    "classtype": classtype, "sevnum": sevnum}
    return None


def client_ip(handler):
    # honor tunnel/proxy headers so we log the real attacker, not localhost
    for h in ("Cf-Connecting-Ip", "X-Forwarded-For", "X-Real-Ip"):
        v = handler.headers.get(h)
        if v:
            return v.split(",")[0].strip()
    return handler.client_address[0]


class H(BaseHTTPRequestHandler):
    server_version = "nginx"           # look like a boring real server
    sys_version = ""

    def log_message(self, *a):         # silence default logging
        pass

    def _maybe_threshold(self, ip, now):
        """Suricata detection_filter-style: N hits from one IP in window."""
        dq = IP_TIMES[ip]; t = time.time(); dq.append(t)
        recent = sum(1 for x in dq if t - x <= THRESH_WINDOW)
        if recent >= THRESH_COUNT and (t - THRESH_FIRED.get(ip, 0)) > THRESH_WINDOW:
            THRESH_FIRED[ip] = t
            g = geo_lookup(ip)
            with LOCK:
                STATS["attacks"] += 1
                SEV[1] += 1
                BY_TYPE["Brute-force / mass-scan"] += 1
                BY_CLASS["attempted-dos"] += 1
                EVE.appendleft({
                    "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                    "event_type": "alert", "src_ip": ip, "src_port": 0,
                    "dest_ip": "honeypot", "dest_port": 80, "proto": "TCP",
                    "geoip": {"country_name": g["country"], "country_code": g["cc"]},
                    "http": {"url": "(rate)", "http_method": "*", "http_user_agent": ""},
                    "alert": {"action": "allowed", "signature_id": 9000050, "rev": 1,
                        "signature": f"OWL Threshold: {recent} req/{THRESH_WINDOW}s from one source",
                        "category": "attempted-dos", "severity": 1},
                })
                HITS.appendleft({"t": now.strftime("%H:%M:%S"), "ip": ip,
                    "path": f"[{recent} req/{THRESH_WINDOW}s]", "ua": "", "method": "THRESH",
                    "attack": True, "label": "Brute-force / mass-scan", "sev": "high",
                    "sid": 9000050, "classtype": "attempted-dos", "cc": g["cc"], "country": g["country"]})

    def _check_honeytoken(self, path, body):
        hay = (path + " " + body)
        for name, tok in HONEYTOKENS.items():
            if tok in hay:
                return name
        return None

    def _record(self, body=""):
        ip = client_ip(self)
        ua = self.headers.get("User-Agent", "")
        path = self.path
        sig = classify(path, ua)
        now = datetime.now(timezone.utc)
        geo = geo_lookup(ip)
        # honeytoken: attacker replayed a bait credential -> CRITICAL
        tok = self._check_honeytoken(path, body)
        if tok:
            with LOCK:
                STATS["attacks"] += 1
                SEV[1] += 1
                BY_TYPE["HONEYTOKEN TRIGGERED"] += 1
                BY_CLASS["credential-theft"] += 1
                rec = {"t": now.strftime("%H:%M:%S"), "ip": ip, "cc": geo["cc"],
                       "country": geo["country"], "token": tok}
                HONEYTOKEN_HITS.appendleft(rec)
                EVE.appendleft({
                    "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
                    "event_type": "alert", "src_ip": ip, "src_port": 0,
                    "dest_ip": "honeypot", "dest_port": 80, "proto": "TCP",
                    "geoip": {"country_name": geo["country"], "country_code": geo["cc"]},
                    "http": {"url": path[:200], "http_method": self.command, "http_user_agent": ua[:200]},
                    "alert": {"action": "allowed", "signature_id": 9000060, "rev": 1,
                        "signature": f"OWL HONEYTOKEN triggered ({tok}) - attacker used bait credential",
                        "category": "credential-theft", "severity": 1},
                })
        hit = {
            "t": now.strftime("%H:%M:%S"),
            "ip": ip, "path": path[:120], "ua": ua[:120],
            "method": self.command, "attack": bool(sig),
            "label": sig["label"] if sig else "recon / scan",
            "sev": sig["sev"] if sig else "low",
            "sid": sig["sid"] if sig else 9000099,
            "classtype": sig["classtype"] if sig else "not-suspicious",
            "cc": geo["cc"], "country": geo["country"],
        }
        with LOCK:
            HITS.appendleft(hit)
            STATS["total"] += 1
            EPS_TIMES.append(time.time())
            if geo["cc"] != "??":
                BY_GEO[geo["country"]] += 1
            if sig:
                SEV[sig["sevnum"]] += 1
            if sig:
                STATS["attacks"] += 1
                BY_TYPE[sig["label"]] += 1
                BY_CLASS[sig["classtype"]] += 1
                # Suricata EVE-JSON alert record (real eve.json shape)
                EVE.appendleft({
                    "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f%z") or now.isoformat(),
                    "event_type": "alert",
                    "src_ip": ip, "src_port": 0,
                    "dest_ip": "honeypot", "dest_port": 80,
                    "proto": "TCP",
                    "geoip": {"country_name": geo["country"], "country_code": geo["cc"]},
                    "http": {"hostname": self.headers.get("Host", ""),
                             "url": path[:200], "http_method": self.command,
                             "http_user_agent": ua[:200]},
                    "alert": {
                        "action": "allowed",
                        "signature_id": sig["sid"], "rev": 1,
                        "signature": "OWL " + sig["label"],
                        "category": sig["classtype"],
                        "severity": sig["sevnum"],
                    },
                })
            octet = ".".join(ip.split(".")[:3]) + ".0/24" if "." in ip else ip
            BY_NET[octet] += 1
        self._maybe_threshold(ip, now)
        ddos_check(ip)
        return hit

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Access-Control-Allow-Origin", "*")
        # Never let a CDN/browser cache the live API or app assets -> fixes
        # stale 'reconnecting' behind Cloudflare/proxies.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        # strip query string so /api/feed?_=123 (cache-buster) still routes
        self.path = self.path.split("?", 1)[0]
        # API endpoints (not counted as attacks)
        if self.path == "/api/feed":
            with LOCK:
                data = {
                    "stats": {
                        "total": STATS["total"], "attacks": STATS["attacks"],
                        "uptime": int(time.time() - STATS["start"]),
                        "sources": len(BY_NET),
                        "countries": len(BY_GEO),
                        "eps": round(sum(1 for x in EPS_TIMES if time.time() - x <= 10) / 10.0, 2),
                        "feeds": len(SIGS),
                        "sev": {"high": SEV[1], "med": SEV[2], "low": SEV[3]},
                    },
                    "top": BY_TYPE.most_common(6),
                    "sources": BY_NET.most_common(8),
                    "geo": BY_GEO.most_common(8),
                    "classtypes": BY_CLASS.most_common(6),
                    "honeytokens": list(HONEYTOKEN_HITS)[:10],
                    "ddos": dict(DDOS),
                    "eve": list(EVE)[:20],
                    "hits": list(HITS)[:60],
                }
            return self._send(200, json.dumps(data), "application/json")
        if self.path == "/api/eve":
            # downloadable Suricata EVE-JSON (one alert per line, like eve.json)
            with LOCK:
                lines = "\n".join(json.dumps(e) for e in reversed(EVE))
            return self._send(200, lines or "", "application/x-ndjson")
        if self.path == "/owl-honeypot.rules":
            return self._send(200, (HERE / "owl-honeypot.rules").read_bytes(), "text/plain")
        if self.path in ("/", "/index.html"):
            return self._send(200, (HERE / "index.html").read_bytes())
        for name, ctype in (("app.js", "application/javascript"), ("style.css", "text/css")):
            if self.path == "/" + name:
                return self._send(200, (HERE / name).read_bytes(), ctype)
        # --- DECOY endpoints: bait attackers w/ fake vulns + honeytokens ---
        if re.search(r"/\.env$", self.path):
            self._record()
            # decoy .env seeded with the REAL AWS canary token
            body = ("APP_ENV=production\nAPP_DEBUG=false\nDB_CONNECTION=mysql\n"
                    f"DB_HOST={CANARY_DNS}\nDB_DATABASE=owl_prod\nDB_USERNAME=owl_app\n"
                    f"AWS_ACCESS_KEY_ID={CANARY_AWS_KEY}\n"
                    f"AWS_SECRET_ACCESS_KEY={CANARY_AWS_SECRET}\n"
                    "AWS_DEFAULT_REGION=us-east-2\n"
                    f"REDIS_HOST={CANARY_DNS}\n"
                    f"API_KEY={HONEYTOKENS['api_key']}\n")
            return self._send(200, body, "text/plain")
        if self.path.rstrip("/") in ("/admin", "/login", "/wp-login.php"):
            self._record()
            # fake login page: web-bug canary fires on load; session token bait in comment
            return self._send(200,
                "<html><head><title>Admin · Sign in</title></head><body>"
                "<h2>Administrator Login</h2>"
                "<form method=post action='/admin'>"
                "<p>Username <input name=user></p>"
                "<p>Password <input name=pass type=password></p>"
                "<button>Sign in</button></form>"
                # invisible web-bug canary token (loads -> alert):
                f"<img src='{CANARY_WEBBUG}' width='1' height='1' style='position:absolute;opacity:0' alt=''>"
                f"<!-- internal session token: {HONEYTOKENS['session']} -->"
                "</body></html>")
        p = self.path.rstrip("/").lower()
        # fake exposed .git/config (repo-exposure bait)
        if p.endswith("/.git/config"):
            self._record()
            return self._send(200,
                "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                "[remote \"origin\"]\n\turl = https://github.com/owl-internal/prod-app.git\n"
                f"\tfetch = +refs/heads/*:refs/remotes/origin/*\n", "text/plain")
        # fake phpinfo()
        if p.endswith("/phpinfo.php") or p.endswith("/info.php"):
            self._record()
            return self._send(200, "<h1>PHP Version 7.4.33</h1><table>"
                "<tr><td>System</td><td>Linux owl-prod 5.15.0</td></tr>"
                "<tr><td>Server API</td><td>FPM/FastCGI</td></tr>"
                "<tr><td>DOCUMENT_ROOT</td><td>/var/www/owl</td></tr></table>")
        # fake database backup (seed DNS canary as host)
        if p.endswith(".sql") or p.endswith(".sql.gz") or "/backup" in p or "/dump" in p:
            self._record()
            return self._send(200,
                "-- MySQL dump 10.13  Distrib 8.0\n"
                f"-- Host: {CANARY_DNS}    Database: owl_prod\n"
                "CREATE TABLE `users` (`id` int, `email` varchar(255), `pass_hash` varchar(255));\n"
                "INSERT INTO `users` VALUES (1,'admin@owlautocs.com','$2y$10$abcdef...');\n", "text/plain")
        # fake AWS credentials file (real canary)
        if p.endswith("/.aws/credentials") or p.endswith("/credentials"):
            self._record()
            return self._send(200,
                "[default]\n"
                f"aws_access_key_id = {CANARY_AWS_KEY}\n"
                f"aws_secret_access_key = {CANARY_AWS_SECRET}\n"
                "region = us-east-2\n", "text/plain")
        # fake private SSH key (bait; not a real key)
        if p.endswith("/id_rsa") or p.endswith("/.ssh/id_rsa"):
            self._record()
            return self._send(200,
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "b3BlbnNzaC1rZXktdjEAAAAA" + secrets.token_hex(40) + "\n"
                "-----END OPENSSH PRIVATE KEY-----\n", "text/plain")
        # fake Apache server-status
        if p.endswith("/server-status"):
            self._record()
            return self._send(200, "<h1>Apache Server Status</h1>"
                "<pre>Total accesses: 184213 - Total Traffic: 4.2 GB\n"
                "CPU Usage: u2.1 s.4\n1 requests currently being processed</pre>")
        # fake API / swagger doc
        if p.endswith("/api") or p.endswith("/api/v1") or p.endswith("/swagger.json") or p.endswith("/openapi.json"):
            self._record()
            return self._send(200, json.dumps({
                "openapi": "3.0.0",
                "info": {"title": "OWL Internal API", "version": "1.0"},
                "servers": [{"url": "https://" + CANARY_DNS}],
                "paths": {"/users": {"get": {"summary": "list users"}},
                          "/admin/token": {"post": {"summary": "issue admin token"}}},
            }), "application/json")
        # ANYTHING else = a probe. Record it, then serve a bland fake page.
        self._record()
        self._send(404, "<html><body><h1>404 Not Found</h1></body></html>")

    def _ingest_ssh(self, ev):
        """Record an SSH/Telnet Cowrie event shipped to /api/ingest as a hit."""
        ip = str(ev.get("src_ip", "?"))
        etype = ev.get("eventid", "")
        user = str(ev.get("username", ""))[:40]
        pw = str(ev.get("password", ""))[:40]
        cmd = str(ev.get("input", ""))[:120]
        # Cowrie tags protocol as 'ssh' or 'telnet'
        proto = str(ev.get("protocol", "")).lower()
        PROTO = "TELNET" if proto == "telnet" else "SSH"
        pre = PROTO.lower()
        if etype == "cowrie.command.input":
            label, sev, sevnum, path = f"{PROTO} command executed", "high", 1, "$ " + cmd
        elif etype in ("cowrie.login.success", "cowrie.login.failed"):
            ok = etype.endswith("success")
            label = f"{PROTO} login " + ("SUCCESS" if ok else "attempt")
            sev, sevnum = ("high", 1) if ok else ("med", 2)
            path = f"{pre} {user}:{pw}"
        else:
            label, sev, sevnum, path = f"{PROTO} session", "low", 3, etype
        now = datetime.now(timezone.utc)
        geo = geo_lookup(ip)
        hit = {"t": now.strftime("%H:%M:%S"), "ip": ip, "path": path, "ua": PROTO + "/cowrie",
               "method": PROTO, "attack": True, "label": label, "sev": sev,
               "sid": 9000070 if PROTO == "SSH" else 9000071, "classtype": "attempted-admin",
               "cc": geo["cc"], "country": geo["country"]}
        with LOCK:
            HITS.appendleft(hit); STATS["total"] += 1; STATS["attacks"] += 1
            SEV[sevnum] += 1; BY_TYPE[label] += 1; BY_CLASS["attempted-admin"] += 1
            if geo["cc"] != "??": BY_GEO[geo["country"]] += 1
            EPS_TIMES.append(time.time())

    # attackers love POSTing to login/exploit endpoints — capture those too
    def do_POST(self):
        # SSH/Cowrie log shipper -> /api/ingest (token-gated)
        if self.path.split("?", 1)[0] == "/api/ingest":
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(min(n, 65536)).decode("utf-8", "replace")
            if not INGEST_TOKEN or self.headers.get("X-Ingest-Token") != INGEST_TOKEN:
                return self._send(403, '{"error":"forbidden"}', "application/json")
            cnt = 0
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self._ingest_ssh(json.loads(line)); cnt += 1
                except Exception:
                    pass
            return self._send(200, json.dumps({"ingested": cnt}), "application/json")
        body = ""
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(min(n, 4096)).decode("utf-8", "replace")
        except Exception:
            pass
        self._record(body)   # pass body so honeytoken replay in POST is caught
        self._send(404, "<html><body><h1>404 Not Found</h1></body></html>")
    do_HEAD = do_GET


# ---- lightweight persistence (survive restarts) ----
def save_state():
    try:
        with LOCK:
            DATA_FILE.write_text(json.dumps({
                "stats": {"total": STATS["total"], "attacks": STATS["attacks"]},
                "by_type": dict(BY_TYPE), "by_class": dict(BY_CLASS),
                "by_geo": dict(BY_GEO), "by_net": dict(BY_NET),
                "sev": SEV, "hits": list(HITS)[:200], "eve": list(EVE)[:200],
                "honeytokens": list(HONEYTOKEN_HITS),
            }))
    except Exception as e:
        print("[!] save failed:", e)

def load_state():
    if not DATA_FILE.exists():
        return
    try:
        d = json.loads(DATA_FILE.read_text())
        STATS["total"] = d["stats"]["total"]; STATS["attacks"] = d["stats"]["attacks"]
        BY_TYPE.update(d.get("by_type", {})); BY_CLASS.update(d.get("by_class", {}))
        BY_GEO.update(d.get("by_geo", {})); BY_NET.update(d.get("by_net", {}))
        for k, v in d.get("sev", {}).items(): SEV[int(k)] = v
        for h in reversed(d.get("hits", [])): HITS.appendleft(h)
        for e in reversed(d.get("eve", [])): EVE.appendleft(e)
        for t in reversed(d.get("honeytokens", [])): HONEYTOKEN_HITS.appendleft(t)
        print(f"[*] restored {STATS['total']} hits from {DATA_FILE.name}")
    except Exception as e:
        print("[!] load failed:", e)

def _autosave():
    while True:
        time.sleep(30); save_state()

def _graceful(signum, frame):
    save_state()
    print(f"\n[*] signal {signum}: saved + stopping.")
    sys.exit(0)

if __name__ == "__main__":
    load_state()
    atexit.register(save_state)
    signal.signal(signal.SIGTERM, _graceful)   # systemd/pkill stop -> save
    signal.signal(signal.SIGINT, _graceful)    # ctrl-c -> save
    threading.Thread(target=_autosave, daemon=True).start()
    print(f"[*] OWL honeypot listening on {HOST}:{PORT}  (UI: /  feed: /api/feed)")
    print(f"[*] geoip={'on' if GEOIP_ON else 'off'}  data={DATA_FILE}")
    try:
        ThreadingHTTPServer((HOST, PORT), H).serve_forever()
    except KeyboardInterrupt:
        save_state(); print("\n[*] saved + stopped.")
