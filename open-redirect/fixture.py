#!/usr/bin/env python3
"""Synthetic open-redirect fixture 1.0.0. Binds IPv4 loopback only.

GET /login?next=<value> answers 302 with a Location header, as an app does for a user
who is already signed in. No credentials exist. The fixture's configured site host is
site.example, a reserved name that is never contacted.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0.0"
SITE_HOST = "site.example"
DEFAULT = "/account"
DESTINATIONS = {"account": "/account", "billing": "/account/billing"}


def naive_slash(value):
    """Naive fix 1: the value must start with a slash."""
    return value if value.startswith("/") else DEFAULT


def naive_host(value):
    """Naive fix 2: the value must contain the site host."""
    return value if SITE_HOST in value else DEFAULT


def safe_next(value):
    """Real fix: keep only a same-site relative path, judged after parsing."""
    if any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in value):
        return DEFAULT
    parts = urlsplit(value)
    if parts.scheme or parts.netloc or not value.startswith("/") or value.startswith("//"):
        return DEFAULT
    return value


def destination(key):
    """Alternative fix: the client sends a short key, the server owns the URL."""
    return DESTINATIONS.get(key, DEFAULT)


class Handler(BaseHTTPRequestHandler):
    server_version = "RedirectFixture/" + VERSION
    sys_version = ""

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path != "/login":
            return self.reply(404, None)
        query = parse_qs(parts.query, keep_blank_values=True)
        value = query.get("next", [DEFAULT])[0]
        mode = self.server.mode
        if mode == "vulnerable":
            target = value
        elif mode == "naive-slash":
            target = naive_slash(value)
        elif mode == "naive-host":
            target = naive_host(value)
        else:
            target = destination(query["dest"][0]) if "dest" in query else safe_next(value)
        self.reply(302, target)

    def reply(self, status, location):
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("vulnerable", "naive-slash", "naive-host", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=8765, help="0 chooses a free local port")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    print(json.dumps({"fixture_version": VERSION, "mode": args.mode, "site_host": SITE_HOST,
                      "base_url": "http://127.0.0.1:" + str(server.server_port)}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
