#!/usr/bin/env python3
"""
HoneyWatch dashboard server.

Serves the dashboard and a single JSON API that aggregates data/attacks.jsonl in
real time. Attacker IPs are enriched with geolocation (cached on disk) so the map
can plot where attacks come from.

Pure standard library — run alongside honeypot.py:

    python3 server.py            # http://localhost:8080
    python3 server.py --port 9000

Then open http://localhost:8080 in a browser.
"""

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import geoip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_FILE = os.path.join(DATA_DIR, "attacks.jsonl")
DASHBOARD = os.path.join(BASE_DIR, "dashboard")

TOP_N = 10
FEED_N = 25


def read_events():
    events = []
    try:
        with open(LOG_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        pass
    return events


def build_stats():
    events = read_events()
    logins = [e for e in events if e.get("event") == "login_attempt"]

    countries = Counter()
    usernames = Counter()
    passwords = Counter()
    services = Counter()
    ips = Counter()
    points = {}   # ip -> {lat, lon, country, count}

    for e in logins:
        ip = e.get("ip", "")
        ips[ip] += 1
        services[e.get("service", "?")] += 1
        if e.get("username"):
            usernames[e["username"]] += 1
        if e.get("password"):
            passwords[e["password"]] += 1

        geo = geoip.lookup(ip)
        if geo and geo.get("lat") is not None:
            countries[geo.get("country") or "Unknown"] += 1
            node = points.setdefault(ip, {
                "ip": ip, "lat": geo["lat"], "lon": geo["lon"],
                "country": geo.get("country"), "count": 0,
            })
            node["count"] += 1

    # 24-hour timeline, hourly buckets.
    now = datetime.now(timezone.utc)
    buckets = [0] * 24
    labels = []
    for i in range(24):
        hour = now - timedelta(hours=23 - i)
        labels.append(hour.strftime("%H:00"))
    start = now - timedelta(hours=24)
    for e in logins:
        try:
            ts = datetime.fromisoformat(e["ts"])
        except (KeyError, ValueError):
            continue
        if ts >= start:
            idx = int((ts - start).total_seconds() // 3600)
            if 0 <= idx < 24:
                buckets[idx] += 1

    feed = []
    for e in reversed(logins[-FEED_N:]):
        geo = geoip.lookup(e.get("ip", "")) or {}
        feed.append({
            "ts": e.get("ts"),
            "ip": e.get("ip"),
            "service": e.get("service"),
            "username": e.get("username"),
            "password": e.get("password"),
            "country": geo.get("country"),
            "country_code": geo.get("country_code"),
        })

    return {
        "total_attacks": len(logins),
        "unique_ips": len(ips),
        "countries_hit": len(countries),
        "services": dict(services),
        "top_countries": countries.most_common(TOP_N),
        "top_usernames": usernames.most_common(TOP_N),
        "top_passwords": passwords.most_common(TOP_N),
        "timeline": {"labels": labels, "data": buckets},
        "map_points": list(points.values()),
        "feed": feed,
        "generated_at": now.isoformat(),
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep the console clean for the honeypot feed

    def _send(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] == "/api/stats":
            body = json.dumps(build_stats()).encode("utf-8")
            self._send(200, body, "application/json")
            return

        path = self.path.split("?")[0]
        if path == "/":
            path = "/index.html"
        target = os.path.normpath(os.path.join(DASHBOARD, path.lstrip("/")))
        if not target.startswith(DASHBOARD) or not os.path.isfile(target):
            self._send(404, b"Not found", "text/plain")
            return
        ctype = "text/html" if target.endswith(".html") else "application/octet-stream"
        with open(target, "rb") as fh:
            self._send(200, fh.read(), ctype)


def main():
    ap = argparse.ArgumentParser(description="HoneyWatch dashboard server")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    os.makedirs(DATA_DIR, exist_ok=True)
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"[+] Dashboard on http://localhost:{args.port}")
    print("[+] Serving live stats from", LOG_FILE)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Stopped.")


if __name__ == "__main__":
    main()
