#!/usr/bin/env python3
"""Local CSRF fixture. Two roles, both bound to 127.0.0.1 only.

  --role target    a toy account service with a cookie session and a
                   state-changing "change email" endpoint
  --role attacker  a static server for two attacker pages that forge requests

Modes (target role only):
  vulnerable  no CSRF token, no Origin check, state change also on GET,
              cookie SameSite attribute chosen by the login request
  fixed       SameSite=Lax cookie, CSRF token, Origin check, POST only
"""
import argparse
import hmac
import html
import http.server
import json
import secrets
import sys
import threading
import urllib.parse

VERSION = "1.0.0"
HOST = "127.0.0.1"
START_EMAIL = "alice@example.test"
USERS = {"alice": START_EMAIL}  # synthetic, one user


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.email = START_EMAIL
        self.sessions = {}  # sid -> {"user": str, "csrf": str}
        self.log = []


def cookie_header(mode, samesite):
    """Build the Set-Cookie value for a new session id."""
    sid = secrets.token_hex(16)
    if mode == "fixed":
        return sid, f"sid={sid}; Path=/; HttpOnly; SameSite=Lax"
    if samesite == "none":
        return sid, f"sid={sid}; Path=/; SameSite=None; Secure"
    if samesite == "lax":
        return sid, f"sid={sid}; Path=/; SameSite=Lax"
    if samesite == "strict":
        return sid, f"sid={sid}; Path=/; SameSite=Strict"
    return sid, f"sid={sid}; Path=/"  # attribute left out


class Target(http.server.BaseHTTPRequestHandler):
    server_version = "CsrfFixture/1.0"

    def log_message(self, *args):
        pass

    # ---- helpers
    def reply(self, status, body, ctype="application/json", extra=()):
        data = (json.dumps(body) if ctype == "application/json" else body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def session(self):
        jar = self.headers.get("Cookie", "")
        for part in jar.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "sid":
                return self.server.state.sessions.get(value)
        return None

    def record(self):
        h = self.headers
        self.server.state.log.append({
            "method": self.command, "path": self.path.split("?")[0],
            "cookie_sent": "sid=" in h.get("Cookie", ""),
            "origin": h.get("Origin"), "referer": h.get("Referer"),
            "sec_fetch_site": h.get("Sec-Fetch-Site"),
            "sec_fetch_mode": h.get("Sec-Fetch-Mode"),
        })

    def change_email(self, new_email):
        self.server.state.email = new_email

    # ---- routes
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        state, mode = self.server.state, self.server.mode
        if url.path == "/_state":  # fixture control, not part of the app
            return self.reply(200, {"email": state.email, "log": state.log})
        if url.path == "/_reset":
            state.reset()
            return self.reply(200, {"reset": True})
        self.record()
        if url.path == "/login":
            user = q.get("user", ["alice"])[0]
            if user not in USERS:
                return self.reply(404, {"error": "unknown user"})
            sid, setc = cookie_header(mode, q.get("samesite", ["unset"])[0])
            state.sessions[sid] = {"user": user, "csrf": secrets.token_hex(16)}
            return self.reply(200, {"logged_in": user}, extra=[("Set-Cookie", setc)])
        sess = self.session()
        if sess is None:
            return self.reply(401, {"error": "login required"})
        if url.path == "/account":
            field = ""
            if mode == "fixed":
                field = f'<input type="hidden" name="csrf_token" value="{sess["csrf"]}">'
            page = (f'<!doctype html><p>Email: <span id="email">{html.escape(state.email)}</span></p>'
                    f'<form method="post" action="/account/email">{field}'
                    '<input name="email"><button>Save</button></form>')
            return self.reply(200, page, "text/html")
        if url.path == "/account/email/change":
            if mode == "fixed":  # state change over GET is refused
                return self.reply(405, {"error": "use POST"}, extra=[("Allow", "POST")])
            self.change_email(q.get("email", [""])[0])  # VULNERABLE: GET changes state
            return self.reply(200, {"email": state.email})
        return self.reply(404, {"error": "not found"})

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        self.record()
        sess = self.session()
        if sess is None:
            return self.reply(401, {"error": "login required"})
        if url.path != "/account/email":
            return self.reply(404, {"error": "not found"})
        if self.server.mode == "fixed":
            expected_origin = f"http://{self.headers.get('Host')}"
            if self.headers.get("Origin") != expected_origin:  # FIX 1: Origin check
                return self.reply(403, {"error": "bad origin"})
            sent = form.get("csrf_token", [""])[0]
            if not hmac.compare_digest(sent, sess["csrf"]):  # FIX 2: CSRF token
                return self.reply(403, {"error": "bad csrf token"})
        self.change_email(form.get("email", [""])[0])  # vulnerable mode: no check at all
        return self.reply(200, {"email": self.server.state.email})


ATTACK_POST = """<!doctype html><title>attacker post</title>
<form id="f" method="post" action="http://127.0.0.1:{port}/account/email">
<input type="hidden" name="email" value="attacker@evil.test"></form>
<script>document.getElementById('f').submit()</script>"""

ATTACK_GET = """<!doctype html><title>attacker get</title>
<script>location.href = 'http://127.0.0.1:{port}/account/email/change?email=attacker@evil.test'</script>"""


class Attacker(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        pages = {"/attack-post.html": ATTACK_POST, "/attack-get.html": ATTACK_GET}
        page = pages.get(self.path)
        if page is None:
            self.send_response(404)
            self.end_headers()
            return
        data = page.format(port=self.server.target_port).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--role", choices=("target", "attacker"), default="target")
    p.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--target-port", type=int, default=0, help="attacker role: port of the target")
    a = p.parse_args()
    handler = Target if a.role == "target" else Attacker
    server = http.server.ThreadingHTTPServer((HOST, a.port), handler)
    server.mode, server.state, server.target_port = a.mode, State(), a.target_port
    print(json.dumps({"role": a.role, "mode": a.mode, "host": HOST, "port": server.server_address[1]}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
