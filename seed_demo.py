#!/usr/bin/env python3
"""
Seed HoneyWatch with realistic demo data.

Generates several hundred plausible login attempts spread over the last 24h, and
pre-fills the GeoIP cache so the map lights up instantly with no network calls.
Use this to produce screenshots/video for a write-up before (or instead of)
exposing a live honeypot.

    python3 seed_demo.py              # ~400 events
    python3 seed_demo.py --count 800

This only writes demo rows. Delete data/attacks.jsonl to start clean.
"""

import argparse
import json
import os
import random
from datetime import datetime, timezone, timedelta

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LOG_FILE = os.path.join(DATA_DIR, "attacks.jsonl")
CACHE_FILE = os.path.join(DATA_DIR, "geoip_cache.json")

# Regions that dominate real honeypot telemetry, with a representative city.
REGIONS = [
    ("China", "CN", "Beijing", 39.90, 116.40, 0.22),
    ("Russia", "RU", "Moscow", 55.75, 37.62, 0.14),
    ("United States", "US", "Ashburn", 39.04, -77.49, 0.12),
    ("Netherlands", "NL", "Amsterdam", 52.37, 4.90, 0.08),
    ("India", "IN", "Mumbai", 19.08, 72.88, 0.08),
    ("Brazil", "BR", "Sao Paulo", -23.55, -46.63, 0.07),
    ("Vietnam", "VN", "Hanoi", 21.03, 105.85, 0.06),
    ("Germany", "DE", "Frankfurt", 50.11, 8.68, 0.05),
    ("Indonesia", "ID", "Jakarta", -6.21, 106.85, 0.05),
    ("South Korea", "KR", "Seoul", 37.57, 126.98, 0.04),
    ("France", "FR", "Paris", 48.85, 2.35, 0.03),
    ("Iran", "IR", "Tehran", 35.69, 51.39, 0.03),
    ("Singapore", "SG", "Singapore", 1.35, 103.82, 0.03),
]

# Top credentials seen in the wild (public Mirai / brute-force wordlists).
USERNAMES = ["root", "admin", "user", "test", "ubuntu", "oracle", "pi",
             "postgres", "ftpuser", "guest", "administrator", "support",
             "git", "www-data", "default", "service"]
PASSWORDS = ["123456", "admin", "password", "root", "123456789", "12345",
             "1234", "qwerty", "admin123", "root123", "password123", "111111",
             "123123", "letmein", "changeme", "default", "P@ssw0rd", "toor",
             "raspberry", "1q2w3e4r"]
SERVICES = [("telnet", 2323), ("ssh", 2222), ("ftp", 2121)]


def rand_ip():
    # Avoid private / reserved / multicast first octets for realism.
    bad = {0, 10, 100, 127, 169, 172, 192, 198, 203} | set(range(224, 256))
    first = random.choice([n for n in range(1, 224) if n not in bad])
    return ".".join([str(first)] + [str(random.randint(1, 254)) for _ in range(3)])


def weighted_region():
    r = random.random()
    acc = 0
    for region in REGIONS:
        acc += region[5]
        if r <= acc:
            return region
    return REGIONS[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=400)
    args = ap.parse_args()
    os.makedirs(DATA_DIR, exist_ok=True)

    # Build a stable pool of attacker IPs (fewer IPs than events = repeat offenders).
    pool = []
    for _ in range(max(30, args.count // 6)):
        name, code, city, lat, lon, _ = weighted_region()
        pool.append((rand_ip(), name, code, city, lat, lon))

    cache = {}
    events = []
    now = datetime.now(timezone.utc)
    for _ in range(args.count):
        ip, name, code, city, lat, lon = random.choice(pool)
        # Pre-fill geo cache with slight jitter so overlapping IPs spread out.
        cache[ip] = {
            "country": name, "country_code": code, "city": city,
            "lat": round(lat + random.uniform(-1.5, 1.5), 4),
            "lon": round(lon + random.uniform(-1.5, 1.5), 4),
        }
        service, port = random.choice(SERVICES)
        ts = now - timedelta(seconds=random.randint(0, 24 * 3600))
        events.append({
            "ts": ts.isoformat(),
            "event": "login_attempt", "ip": ip, "port": port, "service": service,
            "username": random.choice(USERNAMES),
            "password": random.choice(PASSWORDS),
        })

    events.sort(key=lambda e: e["ts"])
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False) + "\n")

    existing = {}
    if os.path.exists(CACHE_FILE):
        try:
            existing = json.load(open(CACHE_FILE, encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    existing.update(cache)
    json.dump(existing, open(CACHE_FILE, "w", encoding="utf-8"), ensure_ascii=False)

    print(f"[+] Wrote {len(events)} demo events to {LOG_FILE}")
    print(f"[+] Pre-filled geo for {len(cache)} IPs")
    print("[+] Start the server:  python3 server.py   then open http://localhost:8080")


if __name__ == "__main__":
    main()
