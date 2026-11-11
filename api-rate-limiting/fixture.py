#!/usr/bin/env python3
"""Synthetic login rate-limit fixture 1.0.0. Binds IPv4 loopback only."""
import argparse
import json
import math
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"
LIMIT = 5            # attempts allowed per key in one window
WINDOW = 60          # window length in seconds
ACCOUNTS = {"alice": "demo-passphrase-alice", "bob": "demo-passphrase-bob"}
TRUSTED_PROXIES = ()  # no reverse proxy sits in front of this fixture


def real_client_address(peer, forwarded_for, trusted=TRUSTED_PROXIES):
    """Use X-Forwarded-For only when the TCP peer is a known proxy."""
    if peer not in trusted or not forwarded_for:
        return peer
    for hop in reversed([h.strip() for h in forwarded_for.split(",")]):
        if hop not in trusted:
            return hop
    return peer


class Handler(BaseHTTPRequestHandler):
    server_version = "RateFixture/" + VERSION
    sys_version = ""

    def do_POST(self):
        if self.path != "/login":
            return self.reply(404, {"error": "not_found"})
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            data = json.loads(raw)
            username, password = str(data["username"]), str(data["password"])
        except (ValueError, KeyError, TypeError):
            return self.reply(400, {"error": "bad_request"})
        peer = self.client_address[0]
        forwarded = self.headers.get("X-Forwarded-For")
        if self.server.mode == "vulnerable":
            # Flaw: the key is whatever the client wrote in the header.
            key = forwarded if forwarded else peer
        else:
            # Fix: key on the targeted account plus the real peer address.
            key = (username, real_client_address(peer, forwarded))
        wait = self.server.limiter.hit(key)
        if wait:
            headers = {"Retry-After": str(wait)} if self.server.mode == "fixed" else {}
            return self.reply(429, {"error": "too_many_requests"}, headers)
        if ACCOUNTS.get(username) == password:
            return self.reply(200, {"status": "ok", "user": username})
        self.reply(401, {"error": "invalid_credentials"})

    def reply(self, status, payload, extra=None):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Limiter:
    """Fixed window: LIMIT attempts per key per WINDOW seconds."""

    def __init__(self):
        self.windows = {}

    def hit(self, key):
        """Return 0 if allowed, else whole seconds until the window ends."""
        now = time.monotonic()
        start, count = self.windows.get(key, (now, 0))
        if now - start >= WINDOW:
            start, count = now, 0
        count += 1
        self.windows[key] = (start, count)
        if count > LIMIT:
            return max(1, math.ceil(WINDOW - (now - start)))
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=8765, help="0 chooses a free local port")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    server.limiter = Limiter()
    print(json.dumps({"fixture_version": VERSION, "mode": args.mode,
                      "base_url": "http://127.0.0.1:" + str(server.server_port)}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
