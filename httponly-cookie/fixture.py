#!/usr/bin/env python3
"""Synthetic session-cookie fixture 1.0.0. Binds IPv4 loopback only."""
import argparse
import json
import secrets
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

VERSION = "1.0.0"
USERS = {"alice": "demo-password"}
COOKIE_NAME = {"vulnerable": "sid", "fixed": "__Host-sid"}


def session_cookie(mode, token):
    """Return the Set-Cookie header value for a new session."""
    if mode == "vulnerable":
        return "sid=" + token + "; Domain=example.test; Path=/"
    return "__Host-sid=" + token + "; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Lax"


class Handler(BaseHTTPRequestHandler):
    server_version = "CookieFixture/" + VERSION
    sys_version = ""

    def do_POST(self):
        if self.path != "/login":
            return self.reply(404, {"error": "not_found"})
        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        user = form.get("username", [""])[0]
        if USERS.get(user) is None or USERS[user] != form.get("password", [""])[0]:
            return self.reply(401, {"error": "invalid_credentials"})
        token = secrets.token_hex(16)
        self.server.sessions[token] = user
        self.reply(200, {"ok": True, "user": user},
                   [("Set-Cookie", session_cookie(self.server.mode, token))])

    def do_GET(self):
        if self.path != "/account":
            return self.reply(404, {"error": "not_found"})
        jar = SimpleCookie()
        jar.load(self.headers.get("Cookie", ""))
        morsel = jar.get(COOKIE_NAME[self.server.mode])
        user = self.server.sessions.get(morsel.value) if morsel else None
        if user is None:
            return self.reply(401, {"error": "authentication_required"})
        self.reply(200, {"user": user})

    def reply(self, status, payload, extra=()):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=8765, help="0 chooses a free local port")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    server.sessions = {}
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
