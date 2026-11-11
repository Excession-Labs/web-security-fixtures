#!/usr/bin/env python3
"""Synthetic API checklist fixture 1.0.0. Binds IPv4 loopback only.

Four flaws in vulnerable mode, each fixed in fixed mode:
  API1 object level authorization    GET /notes/<id>
  API3 object property authorization PATCH /profile
  API4 unrestricted resource use     GET /search?limit=N
  API5 function level authorization  GET /admin/users
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.0.0"
TOKENS = {"demo-alice-token": "alice", "demo-bob-token": "bob",
          "demo-carol-token": "carol", "demo-admin-token": "admin"}
NOTES = {"alice-note": {"id": "alice-note", "owner": "alice", "text": "Alice synthetic note"},
         "bob-note": {"id": "bob-note", "owner": "bob", "text": "Bob synthetic note"}}
ROWS = [{"id": i, "title": "item-" + str(i)} for i in range(1, 501)]
MAX_LIMIT = 50
DEFAULT_LIMIT = 20
EDITABLE_FIELDS = {"display_name"}


def fresh_profiles():
    return {name: {"user": name, "display_name": name.capitalize(),
                   "role": "admin" if name == "admin" else "user"} for name in TOKENS.values()}


class Handler(BaseHTTPRequestHandler):
    server_version = "ChecklistFixture/" + VERSION
    sys_version = ""

    def identity(self):
        return TOKENS.get(self.headers.get("Authorization", "").removeprefix("Bearer "))

    def do_GET(self):
        who = self.identity()
        if who is None:
            return self.reply(401, {"error": "authentication_required"})
        url = urlparse(self.path)
        fixed = self.server.mode == "fixed"
        profiles = self.server.profiles
        if url.path.startswith("/notes/"):  # API1
            note = NOTES.get(url.path[len("/notes/"):])
            if note is None:
                return self.reply(404, {"error": "not_found"})
            if fixed and note["owner"] != who:
                return self.reply(403, {"error": "forbidden"})
            return self.reply(200, note)
        if url.path == "/profile":
            return self.reply(200, profiles[who])
        if url.path == "/admin/users":  # API5
            if fixed and profiles[who]["role"] != "admin":
                return self.reply(403, {"error": "forbidden"})
            return self.reply(200, {"users": sorted(profiles)})
        if url.path == "/search":  # API4
            raw = parse_qs(url.query).get("limit", [str(DEFAULT_LIMIT)])[0]
            if not raw.isdigit() or int(raw) < 1:
                return self.reply(400, {"error": "invalid_limit"})
            limit = int(raw)
            if fixed and limit > MAX_LIMIT:
                return self.reply(400, {"error": "limit_too_large", "max": MAX_LIMIT})
            items = ROWS[:limit]
            return self.reply(200, {"count": len(items), "items": items})
        self.reply(404, {"error": "not_found"})

    def do_PATCH(self):
        who = self.identity()
        if who is None:
            return self.reply(401, {"error": "authentication_required"})
        if urlparse(self.path).path != "/profile":
            return self.reply(404, {"error": "not_found"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            changes = json.loads(self.rfile.read(size) or b"{}")
            if not isinstance(changes, dict):
                raise ValueError
        except ValueError:
            return self.reply(400, {"error": "invalid_json"})
        if self.server.mode == "fixed":  # API3: allowlist of editable fields
            for field in changes:
                if field not in EDITABLE_FIELDS:
                    return self.reply(400, {"error": "unknown_field", "field": field})
        self.server.profiles[who].update(changes)
        self.reply(200, self.server.profiles[who])

    def reply(self, status, payload):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
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
    server.profiles = fresh_profiles()
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
