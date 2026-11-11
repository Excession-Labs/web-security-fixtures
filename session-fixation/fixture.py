#!/usr/bin/env python3
"""Session fixation fixture. Binds 127.0.0.1 only. Synthetic data only.

vulnerable mode: POST /login keeps the session ID the client sent.
fixed mode:      POST /login issues a new session ID and deletes the old one.
"""
import argparse
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {"victor": "demo-password-not-real"}
ACCOUNTS = {"victor": {"user": "victor", "note": "Victor synthetic account page"}}


class Handler(BaseHTTPRequestHandler):
    server_version = "fixture"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, body, cookie=None):
        data = (json.dumps(body, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        if cookie:
            self.send_header("Set-Cookie", "sid=" + cookie + "; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(data)

    def sid(self):
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == "sid":
                return value
        return None

    def do_GET(self):
        sessions = self.server.sessions
        if self.path == "/session":
            sid = secrets.token_hex(16)
            sessions[sid] = {"user": None}
            return self.reply(200, {"session": "anonymous"}, cookie=sid)
        if self.path == "/account":
            session = sessions.get(self.sid())
            if not session or not session["user"]:
                return self.reply(401, {"error": "authentication_required"})
            return self.reply(200, ACCOUNTS[session["user"]])
        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/login":
            return self.reply(404, {"error": "not_found"})
        length = int(self.headers.get("Content-Length", "0"))
        try:
            form = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "bad_request"})
        sessions = self.server.sessions
        old = self.sid()
        user = form.get("user")
        if USERS.get(user) is None or USERS[user] != form.get("password"):
            return self.reply(401, {"error": "invalid_credentials"})
        if old not in sessions:
            return self.reply(400, {"error": "no_session"})
        if self.server.mode == "fixed":
            del sessions[old]                      # invalidate the pre-login ID
            new = secrets.token_hex(16)            # issue a new ID at login
            sessions[new] = {"user": user}
            return self.reply(200, {"login": "ok", "user": user}, cookie=new)
        sessions[old]["user"] = user               # vulnerable: keep the old ID
        return self.reply(200, {"login": "ok", "user": user})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    server.sessions = {}
    print(json.dumps({"mode": args.mode, "base_url": "http://127.0.0.1:%d" % server.server_address[1]}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
