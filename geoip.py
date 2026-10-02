#!/usr/bin/env python3
"""
GeoIP enrichment for attacker IPs.

Uses the free, key-less ip-api.com endpoint and caches every answer on disk so
the same IP is never looked up twice (and so the dashboard stays fast offline).

Pure standard library.
"""

import ipaddress
import json
import os
import urllib.request

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CACHE_FILE = os.path.join(DATA_DIR, "geoip_cache.json")

_cache = None


def _load():
    global _cache
    if _cache is None:
        try:
            with open(CACHE_FILE, encoding="utf-8") as fh:
                _cache = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            _cache = {}
    return _cache


def _save():
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as fh:
        json.dump(_cache, fh, ensure_ascii=False)


def _is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup(ip):
    """Return {country, country_code, city, lat, lon} or None for private/unknown IPs."""
    cache = _load()
    if ip in cache:
        return cache[ip]
    if not _is_public(ip):
        cache[ip] = None
        return None

    url = (f"http://ip-api.com/json/{ip}"
           "?fields=status,country,countryCode,city,lat,lon")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.load(resp)
    except Exception:
        return None  # don't cache transient failures

    if data.get("status") != "success":
        cache[ip] = None
    else:
        cache[ip] = {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }
    _save()
    return cache[ip]


if __name__ == "__main__":
    import sys
    for arg in sys.argv[1:]:
        print(arg, "->", lookup(arg))
