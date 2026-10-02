#!/usr/bin/env python3
"""
HoneyWatch — low-interaction credential honeypot.

Listens on one or more TCP ports, imitates a login prompt (Telnet / FTP / SSH
banners), and records every connection and credential an attacker tries. It never
authenticates anyone and never runs anything the attacker sends: it only captures.

Events are appended as JSON lines to data/attacks.jsonl.

Pure standard library — no pip install required.

    python3 honeypot.py                 # default ports 2323 (telnet) + 2121 (ftp)
    python3 honeypot.py --ports 23,21   # bind the real low ports (needs sudo)

DEPLOY RESPONSIBLY: run this on an isolated VPS you own, never on your home or
company network. Capturing traffic aimed at you is legal; probing others is not.
"""

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LOG_FILE = os.path.join(DATA_DIR, "attacks.jsonl")

# Per-port persona: how the fake service introduces itself.
SERVICES = {
    21:   ("ftp",    "220 ProFTPD 1.3.5 Server ready.\r\n", b"Name: ", b"Password: "),
    23:   ("telnet", "\r\nUbuntu 18.04.6 LTS\r\n", b"login: ", b"Password: "),
    22:   ("ssh",    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n", b"login: ", b"Password: "),
    2121: ("ftp",    "220 ProFTPD 1.3.5 Server ready.\r\n", b"Name: ", b"Password: "),
    2323: ("telnet", "\r\nUbuntu 18.04.6 LTS\r\n", b"login: ", b"Password: "),
    2222: ("ssh",    "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n", b"login: ", b"Password: "),
}

MAX_FIELD = 128          # cap how much we read per credential field
MAX_ATTEMPTS = 3         # offer this many logins before hanging up
READ_TIMEOUT = 20        # seconds to wait for attacker input

_log_lock = asyncio.Lock()


def _now():
    return datetime.now(timezone.utc).isoformat()


async def record(event: dict):
    """Append one event as a JSON line. Also echo to stdout so you can watch live."""
    event["ts"] = _now()
    line = json.dumps(event, ensure_ascii=False)
    async with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    tag = event.get("event")
    if tag == "login_attempt":
        print(f"[{event['ts']}] {event['ip']:<15} {event['service']:<6} "
              f"{event.get('username','')!r} / {event.get('password','')!r}")
    else:
        print(f"[{event['ts']}] {event['ip']:<15} {event['service']:<6} connect")


async def _read_field(reader, limit=MAX_FIELD):
    """Read a single line of attacker input, trimmed and size-capped."""
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)
    except asyncio.TimeoutError:
        return None
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace").strip("\r\n")
    # Strip stray telnet IAC control bytes some clients prepend.
    text = "".join(ch for ch in text if ch.isprintable())
    return text[:limit]


async def handle(reader, writer, port):
    service, banner, user_prompt, pass_prompt = SERVICES.get(
        port, ("tcp", "\r\n", b"login: ", b"Password: ")
    )
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    ip = peer[0]

    await record({"event": "connection", "ip": ip, "port": port, "service": service})

    try:
        writer.write(banner.encode())
        await writer.drain()

        for _ in range(MAX_ATTEMPTS):
            writer.write(user_prompt)
            await writer.drain()
            username = await _read_field(reader)
            if username is None:
                break

            writer.write(pass_prompt)
            await writer.drain()
            password = await _read_field(reader)
            if password is None:
                break

            await record({
                "event": "login_attempt", "ip": ip, "port": port,
                "service": service, "username": username, "password": password,
            })

            # Always reject — this is a leuvre, nobody gets in.
            msg = ("530 Login incorrect.\r\n" if service == "ftp"
                   else "\r\nLogin incorrect\r\n")
            writer.write(msg.encode())
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def serve(ports):
    os.makedirs(DATA_DIR, exist_ok=True)
    servers = []
    for port in ports:
        srv = await asyncio.start_server(
            lambda r, w, p=port: handle(r, w, p), "0.0.0.0", port
        )
        servers.append(srv)
        service = SERVICES.get(port, ("tcp",))[0]
        print(f"[+] HoneyWatch listening on 0.0.0.0:{port} ({service})")
    print(f"[+] Logging to {LOG_FILE}")
    print("[+] Waiting for scanners... (Ctrl-C to stop)\n")
    await asyncio.gather(*(s.serve_forever() for s in servers))


def main():
    ap = argparse.ArgumentParser(description="HoneyWatch credential honeypot")
    ap.add_argument("--ports", default="2323,2121",
                    help="comma-separated TCP ports to bind (default: 2323,2121)")
    args = ap.parse_args()
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    try:
        asyncio.run(serve(ports))
    except KeyboardInterrupt:
        print("\n[+] Stopped.")


if __name__ == "__main__":
    main()
