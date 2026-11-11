#!/usr/bin/env python3
"""Synthetic role-check fixture 1.0.0. Binds IPv4 loopback only."""
import argparse
import copy
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"
# Server-side session store: token -> identity and role.
SESSIONS = {
    "demo-user-token": {"name": "user", "role": "user"},
    "demo-admin-token": {"name": "admin", "role": "admin"},
}
RANK = {"user": 1, "admin": 2}
ACCOUNTS = {
    "acct-7": {"id": "acct-7", "email": "seven@example.test", "role": "user"},
    "acct-8": {"id": "acct-8", "email": "eight@example.test", "role": "user"},
    "acct-9": {"id": "acct-9", "email": "nine@example.test", "role": "user"},
    "acct-10": {"id": "acct-10", "email": "ten@example.test", "role": "user"},
}
AUDIT = [{"at": "2026-11-10T09:00:00Z", "event": "synthetic login", "who": "admin"}]

# Fixed mode: one role per route and method. Anything not listed is denied.
POLICY = {
    ("GET", "/api/me"): "user",
    ("GET", "/api/admin/users"): "admin",
    ("GET", "/api/admin/audit-log"): "admin",
    ("GET", "/api/admin/accounts/{id}"): "admin",
    ("DELETE", "/api/admin/accounts/{id}"): "admin",
    ("GET", "/api/admin/debug"): None,  # route exists, nobody wrote a policy yet
}


def route_key(path):
    match = re.fullmatch(r"/api/admin/accounts/([a-z0-9-]+)", path)
    return ("/api/admin/accounts/{id}", match.group(1)) if match else (path, None)


def h_me(server, user, arg):
    menu = ["Dashboard", "Reports"] + (["Users", "Audit log"] if user["role"] == "admin" else [])
    return 200, {"name": user["name"], "role": user["role"], "menu": menu}


def h_users(server, user, arg):
    return 200, {"accounts": sorted(server.accounts.values(), key=lambda a: a["id"])}


def h_audit(server, user, arg):
    return 200, {"events": AUDIT}


def h_account_get(server, user, arg):
    account = server.accounts.get(arg)
    return (200, account) if account else (404, {"error": "not_found"})


def h_account_delete(server, user, arg):
    return (204, None) if server.accounts.pop(arg, None) else (404, {"error": "not_found"})


def h_debug(server, user, arg):
    return 200, {"debug": "synthetic build info"}


HANDLERS = {
    ("GET", "/api/me"): h_me,
    ("GET", "/api/admin/users"): h_users,
    ("GET", "/api/admin/audit-log"): h_audit,
    ("GET", "/api/admin/accounts/{id}"): h_account_get,
    ("DELETE", "/api/admin/accounts/{id}"): h_account_delete,
    ("GET", "/api/admin/debug"): h_debug,
}


def legacy_checks(headers, method, key, user):
    """Vulnerable mode: checks written route by route. Three of them are wrong or missing."""
    if key == "/api/admin/audit-log":
        role = headers.get("X-Role") or user["role"]  # role read from a client header
        if role != "admin":
            return 403
    if (method, key) == ("GET", "/api/admin/accounts/{id}") and user["role"] != "admin":
        return 403
    # GET /api/admin/users: no check, the admin menu is only hidden in the UI.
    # DELETE /api/admin/accounts/{id}: GET is checked above, DELETE was never added.
    return None


def policy_gate(method, key, user):
    """Fixed mode: one deny-by-default check, role taken only from the server-side session."""
    required = POLICY.get((method, key))
    if required is None or RANK[user["role"]] < RANK[required]:
        return 403
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "RoleFixture/" + VERSION
    sys_version = ""

    def handle_method(self, method):
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        user = SESSIONS.get(token)
        if user is None:
            return self.reply(401, {"error": "authentication_required"})
        key, arg = route_key(self.path)
        handler = HANDLERS.get((method, key))
        if handler is None:
            return self.reply(404, {"error": "not_found"})
        if self.server.mode == "fixed":
            denied = policy_gate(method, key, user)
        else:
            denied = legacy_checks(self.headers, method, key, user)
        if denied:
            return self.reply(denied, {"error": "forbidden"})
        status, payload = handler(self.server, user, arg)
        self.reply(status, payload)

    def do_GET(self):
        self.handle_method("GET")

    def do_DELETE(self):
        self.handle_method("DELETE")

    def reply(self, status, payload):
        body = b"" if payload is None else (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
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
    server.accounts = copy.deepcopy(ACCOUNTS)
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
