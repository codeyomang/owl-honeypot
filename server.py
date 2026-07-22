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
import json, os, re, sys, time, threading, html, secrets, urllib.request, urllib.parse, atexit, signal
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
# SIDs/classtypes mirror lulz-honeypot.rules (loadable into real Suricata).
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
# ---- OSINT enrichment API keys (all optional; set in canary.env) ----
GREYNOISE_KEY = os.environ.get("GREYNOISE_KEY", "")
VT_KEY        = os.environ.get("VT_KEY", "")          # VirusTotal (free tier)
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
OSINT_ON = os.environ.get("OSINT", "on").lower() != "off"
HONEYTOKENS = {
    "aws_key":  CANARY_AWS_KEY,
    "api_key":  "lulz_live_" + secrets.token_hex(16),
    "session":  secrets.token_hex(24),
}
HONEYTOKEN_HITS = deque(maxlen=100)
CAPTURED_CREDS = deque(maxlen=300)   # {t, ip, portal, user, pass, cc, country}
C2_IOCS = deque(maxlen=200)          # {t, ip, type, ioc, cmd, ti} extracted C2 indicators
CRED_STATS = Counter()               # portal -> count

# ---- C2 / botnet indicator patterns (parsed from attacker commands) ----
C2_SIGS = [
    (re.compile(r"(wget|curl)\s+[^\s|;&]*", re.I),           "payload-download"),
    (re.compile(r"(?:tftp|ftpget)\s+", re.I),                 "payload-download"),
    (re.compile(r"\b(mirai|gafgyt|mozi|tsunami|kaiten|bashlite)\b", re.I), "botnet-family"),
    (re.compile(r"chmod\s+\+?x", re.I),                       "exec-chain"),
    (re.compile(r"/dev/(tcp|udp)/", re.I),                    "reverse-shell"),
    (re.compile(r"(nc|ncat|netcat)\s+-[a-z]*e", re.I),        "reverse-shell"),
    (re.compile(r"base64\s+-d|echo\s+[A-Za-z0-9+/]{40,}={0,2}", re.I), "encoded-payload"),
    (re.compile(r"(xmrig|minerd|stratum\+tcp|cryptonight)", re.I), "cryptominer"),
    (re.compile(r"\.(sh|bin|elf|arm7?|mips|x86|mpsl)\b", re.I), "malware-binary"),
]
# extract URLs and bare IPs (potential C2 / payload hosts) from a command
URL_RE = re.compile(r"https?://[^\s'\"|;&)]+", re.I)
IP_RE  = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

TI_CACHE = {}
def threat_intel(indicator, is_ip):
    """Cross-check an IP/URL-host against a free threat-intel source. Cached,
    fail-open (returns {} on any error/timeout). GEOIP=off also disables this."""
    if not GEOIP_ON:
        return {}
    key = indicator
    if key in TI_CACHE:
        return TI_CACHE[key]
    res = {}
    host = indicator
    if not is_ip:
        m = re.search(r"https?://([^/:\s]+)", indicator)
        host = m.group(1) if m else indicator
    # only look up bare IPs (URLs: resolve host cheaply via geo of the IP form)
    try:
        if IP_RE.fullmatch(host or ""):
            # ip-api includes proxy/hosting flags = decent C2 signal, free tier
            with urllib.request.urlopen(
                f"http://ip-api.com/json/{host}?fields=country,proxy,hosting,as", timeout=2) as r:
                d = json.loads(r.read().decode())
                res = {"country": d.get("country"), "proxy": d.get("proxy"),
                       "hosting": d.get("hosting"), "as": d.get("as")}
    except Exception:
        pass
    TI_CACHE[key] = res
    return res

# =====================================================================
#  OSINT ENRICHMENT ENGINE
#  Turns raw hits into attacker intelligence. All lookups cached +
#  fail-open (missing key / timeout -> partial data, never crashes).
# =====================================================================
import socket as _sock
IP_ENRICH = {}          # ip -> enrichment dict (cached)
HASH_ENRICH = {}        # sha256 -> malware intel
ATTACKER_PROFILES = {}  # ip -> rolled-up profile
_ENRICH_LOCK = threading.Lock()

def _http_json(url, headers=None, timeout=3):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception:
        return None

def _reverse_dns(ip):
    try:
        return _sock.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def enrich_ip(ip):
    """Full IP OSINT: rDNS + ASN/org/geo + proxy/hosting + GreyNoise +
    AbuseIPDB. Cached. Returns a dict; keys absent if a source is down/unset."""
    if not OSINT_ON or not ip or ip.startswith(("127.", "10.", "192.168.", "172.", "::1")):
        return {}
    if ip in IP_ENRICH:
        return IP_ENRICH[ip]
    e = {"ip": ip}
    # ip-api: ASN, org, geo, proxy/hosting/mobile flags (free, no key)
    d = _http_json(f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org,as,asname,proxy,hosting,mobile,reverse")
    if d:
        e.update({"country": d.get("country"), "cc": d.get("countryCode"),
                  "city": d.get("city"), "isp": d.get("isp"), "org": d.get("org"),
                  "asn": d.get("as"), "asname": d.get("asname"),
                  "proxy": bool(d.get("proxy")), "hosting": bool(d.get("hosting")),
                  "mobile": bool(d.get("mobile"))})
    e["rdns"] = e.get("reverse") or _reverse_dns(ip)
    # GreyNoise (community endpoint, key optional but recommended)
    if GREYNOISE_KEY:
        g = _http_json(f"https://api.greynoise.io/v3/community/{ip}",
                       headers={"key": GREYNOISE_KEY, "Accept": "application/json"})
        if g and "noise" in g:
            e["greynoise"] = {"noise": g.get("noise"), "riot": g.get("riot"),
                              "classification": g.get("classification"),
                              "name": g.get("name"), "last_seen": g.get("last_seen")}
    # AbuseIPDB (optional key)
    if ABUSEIPDB_KEY:
        a = _http_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                       headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
        if a and a.get("data"):
            e["abuse_score"] = a["data"].get("abuseConfidenceScore")
            e["abuse_reports"] = a["data"].get("totalReports")
    # derived scanner/threat tag
    tags = []
    if e.get("proxy"): tags.append("proxy/vpn")
    if e.get("hosting"): tags.append("hosting/datacenter")
    gn = e.get("greynoise", {})
    if gn.get("classification") == "malicious": tags.append("greynoise:malicious")
    elif gn.get("classification") == "benign": tags.append("greynoise:benign-scanner")
    if gn.get("noise"): tags.append("internet-noise")
    if isinstance(e.get("abuse_score"), int) and e["abuse_score"] >= 50: tags.append("abuseipdb:high")
    rd = (e.get("rdns") or "").lower()
    if any(s in rd for s in ("scan", "censys", "shodan", "masscan", "research")):
        tags.append("known-scanner")
    e["tags"] = tags
    with _ENRICH_LOCK:
        IP_ENRICH[ip] = e
    return e

def enrich_hash(sha256):
    """Malware intel for a payload hash: MalwareBazaar + VirusTotal (if key)."""
    if not OSINT_ON or not sha256 or sha256 in HASH_ENRICH:
        return HASH_ENRICH.get(sha256, {})
    e = {"sha256": sha256}
    # MalwareBazaar (free, no key) - POST form
    try:
        data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        req = urllib.request.Request("https://mb-api.abuse.ch/api/v1/", data=data)
        with urllib.request.urlopen(req, timeout=4) as r:
            mb = json.loads(r.read().decode())
        if mb.get("query_status") == "ok" and mb.get("data"):
            row = mb["data"][0]
            e["malwarebazaar"] = {"family": row.get("signature"),
                "file_type": row.get("file_type"), "first_seen": row.get("first_seen"),
                "tags": row.get("tags")}
    except Exception:
        pass
    if VT_KEY:
        vt = _http_json(f"https://www.virustotal.com/api/v3/files/{sha256}",
                        headers={"x-apikey": VT_KEY})
        if vt and vt.get("data"):
            st = vt["data"].get("attributes", {}).get("last_analysis_stats", {})
            e["virustotal"] = {"malicious": st.get("malicious"), "suspicious": st.get("suspicious")}
    with _ENRICH_LOCK:
        HASH_ENRICH[sha256] = e
    return e

def update_profile(ip, method, label, sev):
    """Roll a hit into a per-source attacker profile (the sellable intel unit)."""
    if not ip or ip.startswith(("127.", "10.", "192.168.", "172.")):
        return
    net = ".".join(ip.split(".")[:3]) + ".0/24" if "." in ip else ip
    now = time.time()
    with _ENRICH_LOCK:
        p = ATTACKER_PROFILES.get(ip)
        if not p:
            p = {"ip": ip, "net": net, "first": now, "hits": 0,
                 "protocols": {}, "labels": {}, "max_sev": "low", "enrich": {}}
            ATTACKER_PROFILES[ip] = p
        p["last"] = now; p["hits"] += 1
        p["protocols"][method] = p["protocols"].get(method, 0) + 1
        p["labels"][label] = p["labels"].get(label, 0) + 1
        order = {"low": 0, "med": 1, "high": 2}
        if order.get(sev, 0) > order.get(p["max_sev"], 0): p["max_sev"] = sev
        # cap memory
        if len(ATTACKER_PROFILES) > 2000:
            oldest = min(ATTACKER_PROFILES, key=lambda k: ATTACKER_PROFILES[k]["last"])
            ATTACKER_PROFILES.pop(oldest, None)

def _enrich_worker():
    """Background: enrich the most-active unenriched attacker IPs (rate-limited
    so we respect free-API limits)."""
    while True:
        time.sleep(4)
        if not OSINT_ON:
            continue
        try:
            with _ENRICH_LOCK:
                todo = [ip for ip, p in ATTACKER_PROFILES.items() if not p.get("enrich")][:1]
            for ip in todo:
                e = enrich_ip(ip)
                with _ENRICH_LOCK:
                    if ip in ATTACKER_PROFILES:
                        ATTACKER_PROFILES[ip]["enrich"] = e
        except Exception:
            pass

def scan_c2(cmd, src_ip):
    """Parse an attacker command for C2/botnet indicators; record IOCs."""
    if not cmd:
        return None
    tags = [name for rx, name in C2_SIGS if rx.search(cmd)]
    if not tags:
        return None
    urls = URL_RE.findall(cmd)
    ips = [i for i in IP_RE.findall(cmd) if i != src_ip]
    now = datetime.now(timezone.utc)
    for ioc, kind in [(u, "url") for u in urls] + [(i, "ip") for i in ips]:
        ti = threat_intel(ioc, kind == "ip")
        with LOCK:
            C2_IOCS.appendleft({"t": now.strftime("%H:%M:%S"), "src": src_ip,
                "type": kind, "ioc": ioc[:160], "tags": tags, "ti": ti,
                "cmd": cmd[:160]})
    if not urls and not ips:  # tagged behavior but no extractable host
        with LOCK:
            C2_IOCS.appendleft({"t": now.strftime("%H:%M:%S"), "src": src_ip,
                "type": "behavior", "ioc": "", "tags": tags, "ti": {}, "cmd": cmd[:160]})
    return tags

# ---- Fake login portals (capture creds + IP) ----
# path-prefix -> portal key. Serve a convincing branded login; POST logs creds.
LOGIN_ROUTES = {
    "/admin": "admin", "/login": "admin", "/wp-login.php": "admin",
    "/wp-admin": "admin", "/administrator": "admin",
    "/router": "router", "/cgi-bin/luci": "router", "/setup.cgi": "router",
    "/webmail": "webmail", "/owa": "webmail", "/remote/login": "webmail",
    "/vpn": "webmail", "/sslvpn": "webmail",
}
def login_portal_for(path):
    pl = path.rstrip("/").lower()
    for pre, portal in LOGIN_ROUTES.items():
        if pl == pre or pl.startswith(pre + "/") or pl.startswith(pre + "?"):
            return portal
    return None

def login_page(portal, err=False):
    action = {"admin": "/admin", "router": "/router", "webmail": "/webmail"}[portal]
    msg = "<p style='color:#c0392b'>Invalid credentials. Please try again.</p>" if err else ""
    canary = (f"<img src='{CANARY_WEBBUG}' width=1 height=1 style='position:absolute;opacity:0' alt=''>"
              f"<!-- session={HONEYTOKENS['session']} -->")
    css = ("body{font-family:Arial,Helvetica,sans-serif;background:#eef1f5;margin:0}"
           ".box{max-width:340px;margin:8% auto;background:#fff;padding:28px 26px;"
           "border-radius:8px;box-shadow:0 2px 14px rgba(0,0,0,.12)}"
           "h2{margin:0 0 4px;font-size:20px}.sub{color:#888;font-size:12px;margin-bottom:18px}"
           "input{width:100%;padding:9px;margin:6px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}"
           "button{width:100%;padding:10px;margin-top:10px;border:0;border-radius:4px;color:#fff;cursor:pointer}")
    if portal == "admin":
        title, brand, sub, color = "Sign in", "⚙ Admin Console", "Authorized personnel only", "#2c3e50"
    elif portal == "router":
        title, brand, sub, color = "Router Login", "📡 NetGear Genie", "Firmware v1.0.4.34", "#16a085"
    else:
        title, brand, sub, color = "Webmail", "✉ Corporate Webmail / VPN", "Outlook Web App", "#0072c6"
    return (f"<!DOCTYPE html><html><head><meta charset=utf-8><title>{title}</title>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<style>{css}button{{background:{color}}}</style></head><body>"
            f"<div class=box><h2>{brand}</h2><div class=sub>{sub}</div>{msg}"
            f"<form method=post action='{action}'>"
            f"<input name=username placeholder='Username' autofocus>"
            f"<input name=password type=password placeholder='Password'>"
            f"<button type=submit>Log In</button></form></div>{canary}</body></html>")

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
                        "signature": f"LULZ Threshold: {recent} req/{THRESH_WINDOW}s from one source",
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
                        "signature": f"LULZ HONEYTOKEN triggered ({tok}) - attacker used bait credential",
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
                        "signature": "LULZ " + sig["label"],
                        "category": sig["classtype"],
                        "severity": sig["sevnum"],
                    },
                })
            octet = ".".join(ip.split(".")[:3]) + ".0/24" if "." in ip else ip
            BY_NET[octet] += 1
        self._maybe_threshold(ip, now)
        ddos_check(ip)
        update_profile(ip, hit["method"], hit["label"], hit["sev"])
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
                    "creds": list(CAPTURED_CREDS)[:20],
                    "cred_total": sum(CRED_STATS.values()),
                    "c2": list(C2_IOCS)[:20],
                    "eve": list(EVE)[:20],
                    "hits": list(HITS)[:60],
                }
            # top attacker profiles (the sellable intel unit)
            with _ENRICH_LOCK:
                prof = sorted(ATTACKER_PROFILES.values(), key=lambda p: -p["hits"])[:15]
                data["profiles"] = [{
                    "ip": p["ip"], "net": p["net"], "hits": p["hits"],
                    "max_sev": p["max_sev"],
                    "protocols": sorted(p["protocols"], key=lambda k:-p["protocols"][k])[:5],
                    "top_label": max(p["labels"], key=p["labels"].get) if p["labels"] else "",
                    "enrich": p.get("enrich", {}),
                } for p in prof]
                data["profile_total"] = len(ATTACKER_PROFILES)
            return self._send(200, json.dumps(data), "application/json")
        # --- OSINT threat-feed exports (sellable-product output formats) ---
        if self.path == "/api/profiles":
            with _ENRICH_LOCK:
                out = list(ATTACKER_PROFILES.values())
            return self._send(200, json.dumps(out, default=str), "application/json")
        if self.path == "/api/feed-export.csv":
            with _ENRICH_LOCK:
                rows = ["ip,net,hits,max_sev,protocols,country,asn,proxy,hosting,greynoise,rdns"]
                for p in ATTACKER_PROFILES.values():
                    e = p.get("enrich", {}); gn = (e.get("greynoise") or {}).get("classification", "")
                    rows.append(",".join(str(x).replace(",", " ") for x in [
                        p["ip"], p["net"], p["hits"], p["max_sev"],
                        "|".join(p["protocols"]), e.get("country", ""), e.get("asn", ""),
                        e.get("proxy", ""), e.get("hosting", ""), gn, e.get("rdns", "")]))
            return self._send(200, "\n".join(rows), "text/csv")
        if self.path == "/api/stix":
            # minimal STIX 2.1 bundle of malicious source IPs (feed for SIEM/TIP)
            objs = []
            with _ENRICH_LOCK:
                for p in ATTACKER_PROFILES.values():
                    if p["max_sev"] == "high" or p["hits"] >= 5:
                        objs.append({"type": "indicator", "spec_version": "2.1",
                            "id": "indicator--" + secrets.token_hex(16),
                            "created": datetime.now(timezone.utc).isoformat(),
                            "pattern": f"[ipv4-addr:value = '{p['ip']}']",
                            "pattern_type": "stix", "valid_from": datetime.now(timezone.utc).isoformat(),
                            "labels": ["malicious-activity"],
                            "description": f"{p['hits']} hits, {p['max_sev']} sev, protocols: {','.join(p['protocols'])}"})
            return self._send(200, json.dumps({"type": "bundle",
                "id": "bundle--" + secrets.token_hex(16), "objects": objs}), "application/json")
        if self.path == "/api/eve":
            # downloadable Suricata EVE-JSON (one alert per line, like eve.json)
            with LOCK:
                lines = "\n".join(json.dumps(e) for e in reversed(EVE))
            return self._send(200, lines or "", "application/x-ndjson")
        if self.path == "/lulz-honeypot.rules":
            return self._send(200, (HERE / "lulz-honeypot.rules").read_bytes(), "text/plain")
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
                    f"DB_HOST={CANARY_DNS}\nDB_DATABASE=lulz_prod\nDB_USERNAME=lulz_app\n"
                    f"AWS_ACCESS_KEY_ID={CANARY_AWS_KEY}\n"
                    f"AWS_SECRET_ACCESS_KEY={CANARY_AWS_SECRET}\n"
                    "AWS_DEFAULT_REGION=us-east-2\n"
                    f"REDIS_HOST={CANARY_DNS}\n"
                    f"API_KEY={HONEYTOKENS['api_key']}\n")
            return self._send(200, body, "text/plain")
        portal = login_portal_for(self.path)
        if portal:
            self._record()
            return self._send(200, login_page(portal))
        p = self.path.rstrip("/").lower()
        # fake exposed .git/config (repo-exposure bait)
        if p.endswith("/.git/config"):
            self._record()
            return self._send(200,
                "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                "[remote \"origin\"]\n\turl = https://github.com/lulz-internal/prod-app.git\n"
                f"\tfetch = +refs/heads/*:refs/remotes/origin/*\n", "text/plain")
        # fake phpinfo()
        if p.endswith("/phpinfo.php") or p.endswith("/info.php"):
            self._record()
            return self._send(200, "<h1>PHP Version 7.4.33</h1><table>"
                "<tr><td>System</td><td>Linux lulz-prod 5.15.0</td></tr>"
                "<tr><td>Server API</td><td>FPM/FastCGI</td></tr>"
                "<tr><td>DOCUMENT_ROOT</td><td>/var/www/lulz</td></tr></table>")
        # fake database backup (seed DNS canary as host)
        if p.endswith(".sql") or p.endswith(".sql.gz") or "/backup" in p or "/dump" in p:
            self._record()
            return self._send(200,
                "-- MySQL dump 10.13  Distrib 8.0\n"
                f"-- Host: {CANARY_DNS}    Database: lulz_prod\n"
                "CREATE TABLE `users` (`id` int, `email` varchar(255), `pass_hash` varchar(255));\n"
                "INSERT INTO `users` VALUES (1,'admin@lulzautocs.com','$2y$10$abcdef...');\n", "text/plain")
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
                "info": {"title": "LULZ Internal API", "version": "1.0"},
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
            scan_c2(cmd, ip)   # extract C2/botnet indicators from the command
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
        update_profile(ip, PROTO, label, sev)

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
        # fake login portal submission -> CAPTURE creds + IP
        portal = login_portal_for(self.path)
        if portal:
            self._record(body)
            from urllib.parse import parse_qs
            q = parse_qs(body)
            user = (q.get("username") or q.get("user") or [""])[0][:60]
            pw = (q.get("password") or q.get("pass") or [""])[0][:60]
            ip = client_ip(self)
            geo = geo_lookup(ip)
            with LOCK:
                CAPTURED_CREDS.appendleft({"t": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "ip": ip, "portal": portal, "user": user, "pass": pw,
                    "cc": geo["cc"], "country": geo["country"]})
                CRED_STATS[portal] += 1
            # always "reject" so they keep trying -> re-serve page with error
            return self._send(200, login_page(portal, err=True))
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
                "creds": list(CAPTURED_CREDS), "cred_stats": dict(CRED_STATS),
                "c2": list(C2_IOCS),
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
        for c in reversed(d.get("creds", [])): CAPTURED_CREDS.appendleft(c)
        CRED_STATS.update(d.get("cred_stats", {}))
        for c in reversed(d.get("c2", [])): C2_IOCS.appendleft(c)
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

# =====================================================================
#  TCP protocol honeypots (FTP/SMTP/Redis/MySQL/RDP)
#  Lightweight listeners: send a realistic banner, log the connection +
#  whatever the attacker sends, feed the same dashboard/feed/globe.
# =====================================================================
import socket

def record_tcp(proto, ip, detail, sid, sev="med", sevnum=2):
    now = datetime.now(timezone.utc)
    geo = geo_lookup(ip)
    hit = {"t": now.strftime("%H:%M:%S"), "ip": ip, "path": detail[:120],
           "ua": proto + "/honeypot", "method": proto, "attack": True,
           "label": f"{proto} probe", "sev": sev, "sid": sid,
           "classtype": "attempted-recon", "cc": geo["cc"], "country": geo["country"]}
    with LOCK:
        HITS.appendleft(hit); STATS["total"] += 1; STATS["attacks"] += 1
        SEV[sevnum] += 1; BY_TYPE[f"{proto} probe"] += 1
        BY_CLASS["attempted-recon"] += 1
        if geo["cc"] != "??": BY_GEO[geo["country"]] += 1
        EPS_TIMES.append(time.time())
    ddos_check(ip)
    update_profile(ip, proto, f"{proto} probe", sev)

# proto -> (port, sid, banner-bytes, mode)
#   mode 'line' = send banner, read a few lines, log creds/cmds
#   mode 'blob' = send banner, read one blob, log hex/ascii
TCP_PROTOS = {
    "FTP":   (21,   9000080, b"220 (vsFTPd 3.0.3)\r\n", "line"),
    "SMTP":  (25,   9000081, b"220 mail.lulz.local ESMTP Postfix\r\n", "line"),
    "REDIS": (6379, 9000082, b"", "line"),      # redis: no banner; attacker sends cmds
    "MYSQL": (3306, 9000083, None, "blob"),     # send a fake MySQL greeting packet
    "RDP":   (3389, 9000084, b"", "blob"),      # log the connection attempt
}

def _mysql_greeting():
    # minimal fake MySQL handshake v10 so scanners fingerprint it as MySQL
    payload = b"\x0a" + b"8.0.32-lulz\x00" + b"\x01\x00\x00\x00" + secrets.token_bytes(8) + b"\x00"
    hdr = bytes([len(payload) & 0xff, 0, 0, 0])
    return hdr + payload

# TCP honeypots must face the internet even when the HTTP app is behind a
# proxy on 127.0.0.1. Default them to 0.0.0.0; override with TCP_HOST.
TCP_HOST = os.environ.get("TCP_HOST", "0.0.0.0")

def tcp_listener(proto):
    port, sid, banner, mode = TCP_PROTOS[proto]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((TCP_HOST, port)); s.listen(50)
    except Exception as e:
        print(f"[!] {proto} listener could not bind :{port}: {e}"); return
    print(f"[*] {proto} honeypot on :{port}")
    while True:
        try:
            conn, addr = s.accept()
        except Exception:
            continue
        threading.Thread(target=_handle_tcp, args=(proto, sid, banner, mode, conn, addr[0]), daemon=True).start()

def _handle_tcp(proto, sid, banner, mode, conn, ip):
    detail = "connect"
    try:
        conn.settimeout(6)
        if proto == "MYSQL":
            conn.sendall(_mysql_greeting())
        elif banner:
            conn.sendall(banner)
        if mode == "line":
            got = []
            for _ in range(4):
                data = conn.recv(256)
                if not data: break
                got.append(data.decode("latin1", "replace").strip())
                # FTP/SMTP: politely prompt so they send creds
                if proto == "FTP": conn.sendall(b"331 password required\r\n")
                elif proto == "SMTP": conn.sendall(b"250 OK\r\n")
            detail = " | ".join(x for x in got if x)[:120] or "connect"
        else:  # blob
            data = conn.recv(512)
            if data:
                detail = data[:40].hex()
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass
    record_tcp(proto, ip, detail, sid)


if __name__ == "__main__":
    load_state()
    atexit.register(save_state)
    signal.signal(signal.SIGTERM, _graceful)   # systemd/pkill stop -> save
    signal.signal(signal.SIGINT, _graceful)    # ctrl-c -> save
    threading.Thread(target=_autosave, daemon=True).start()
    threading.Thread(target=_enrich_worker, daemon=True).start()  # OSINT enrichment
    # start TCP protocol honeypots (disable with TCP_HONEYPOTS=off)
    if os.environ.get("TCP_HONEYPOTS", "on").lower() != "off":
        for _proto in TCP_PROTOS:
            threading.Thread(target=tcp_listener, args=(_proto,), daemon=True).start()
    print(f"[*] LULZ honeypot listening on {HOST}:{PORT}  (UI: /  feed: /api/feed)")
    print(f"[*] geoip={'on' if GEOIP_ON else 'off'}  data={DATA_FILE}")
    try:
        ThreadingHTTPServer((HOST, PORT), H).serve_forever()
    except KeyboardInterrupt:
        save_state(); print("\n[*] saved + stopped.")
