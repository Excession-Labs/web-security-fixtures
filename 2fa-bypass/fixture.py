#!/usr/bin/env python3
"""Synthetic two-step login (password, then 4-digit code) fixture 1.0.0.
Binds IPv4 loopback only. Demonstrates three MFA flaws and their fixes:
  1. step skipping: a password-only session already reaches /account
  2. no attempt limit on the emailed/texted code: unlimited guesses succeed
  3. the code is not bound to one session: another user's valid code completes
     a different user's login
All usernames, passwords and codes are synthetic test fixture values.
"""
import argparse
import json
import random
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.0.0"
MAX_ATTEMPTS = 5  # fixed mode: attempts before lockout

# Synthetic demo accounts. Not real credentials.
USERS = {
    "alice": "alice-demo-pw",
    "bob": "bob-demo-pw",
    "charlie": "charlie-demo-pw",
}


def new_code():
    # Four-digit synthetic one-time code. The brute-force demo excludes
    # 0000-0004 only so the fixed-mode lockout test (cap of 5 attempts,
    # guessed in ascending order from 0000) is reliably exercised on every
    # run; this exclusion is test-harness bookkeeping, not part of either
    # the vulnerable or fixed server logic.
    return "%04d" % random.SystemRandom().randrange(5, 10000)


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.sessions = {}
        self.last_issued_code = None
        self.counter = 0

    def create_session(self, user):
        with self.lock:
            self.counter += 1
            sid = "sess-%d-%s" % (self.counter, user)
            code = new_code()
            self.sessions[sid] = {
                "user": user,
                "code": code,
                "state": "pending_mfa",
                "attempts": 0,
                "locked": False,
                "used": False,
            }
            self.last_issued_code = code
            return sid, code


class Handler(BaseHTTPRequestHandler):
    server_version = "TwoStepFixture/" + VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw) if raw else {}

    def reply(self, status, payload):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def bearer(self):
        value = self.headers.get("Authorization", "")
        return value.removeprefix("Bearer ") if value.startswith("Bearer ") else None

    def do_POST(self):
        store = self.server.store
        if self.path == "/login":
            data = self._read_json()
            username = data.get("username")
            password = data.get("password")
            if USERS.get(username) != password:
                return self.reply(401, {"error": "invalid_credentials"})
            sid, _code = store.create_session(username)
            return self.reply(200, {"session": sid, "mfa_required": True})

        if self.path == "/verify-code":
            data = self._read_json()
            sid = data.get("session")
            code = data.get("code")
            with store.lock:
                session = store.sessions.get(sid)
                if session is None:
                    return self.reply(404, {"error": "unknown_session"})

                if self.server.mode == "vulnerable":
                    # Checks the code against the most recently issued code
                    # for ANY session, not the code stored for this session.
                    # No attempt counter, no lockout, no single-use mark.
                    if code == store.last_issued_code:
                        session["state"] = "authenticated"
                        return self.reply(200, {"status": "authenticated"})
                    return self.reply(401, {"error": "invalid_code"})

                # fixed mode
                if session["locked"]:
                    return self.reply(423, {"error": "locked", "attempts": session["attempts"]})
                if session["used"]:
                    return self.reply(409, {"error": "code_already_used"})
                if code != session["code"]:
                    session["attempts"] += 1
                    if session["attempts"] >= MAX_ATTEMPTS:
                        session["locked"] = True
                        return self.reply(423, {"error": "locked", "attempts": session["attempts"]})
                    return self.reply(401, {
                        "error": "invalid_code",
                        "attempts_remaining": MAX_ATTEMPTS - session["attempts"],
                    })
                session["state"] = "authenticated"
                session["used"] = True
                return self.reply(200, {"status": "authenticated"})

        return self.reply(404, {"error": "not_found"})

    def do_GET(self):
        store = self.server.store
        parsed = urlparse(self.path)

        if parsed.path == "/test-inbox":
            # Test-harness only: lets the legitimate owner of a session read
            # the code they were "sent", the way a tester reads their own
            # phone or inbox. Not part of the attack path in either mode.
            sid = parse_qs(parsed.query).get("session", [None])[0]
            with store.lock:
                session = store.sessions.get(sid)
            if session is None:
                return self.reply(404, {"error": "unknown_session"})
            return self.reply(200, {"code": session["code"]})

        if parsed.path == "/account":
            sid = self.bearer()
            with store.lock:
                session = store.sessions.get(sid)
                if session is None:
                    return self.reply(401, {"error": "authentication_required"})
                if self.server.mode == "fixed" and session["state"] != "authenticated":
                    return self.reply(403, {"error": "mfa_required"})
                return self.reply(200, {"user": session["user"], "account": "synthetic account data"})

        return self.reply(404, {"error": "not_found"})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=8765, help="0 chooses a free local port")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    server.store = Store()
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
