#!/usr/bin/env python3
"""Synthetic profile-update API fixture 1.0.0 for a mass assignment demo. Binds IPv4 loopback only."""
import argparse
import copy
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"
IDENTITIES = {"demo-alice-token": "alice", "demo-admin-token": "root"}
SEED_USERS = {
    "alice": {"id": "alice", "name": "Alice", "email": "alice@example.test", "bio": "",
              "role": "user", "credit": 0, "password_hash": "demo-hash-not-a-real-hash-alice"},
    "bob": {"id": "bob", "name": "Bob", "email": "bob@example.test", "bio": "",
            "role": "user", "credit": 0, "password_hash": "demo-hash-not-a-real-hash-bob"},
    "root": {"id": "root", "name": "Root", "email": "root@example.test", "bio": "",
             "role": "admin", "credit": 0, "password_hash": "demo-hash-not-a-real-hash-root"},
}
# Fixed mode: fields each role may write, and fields any response may contain.
WRITABLE = {
    "user": {"name", "email", "bio"},
    "admin": {"name", "email", "bio", "role", "credit"},
}
PUBLIC_FIELDS = ("id", "name", "email", "bio", "role", "credit")


class Handler(BaseHTTPRequestHandler):
    server_version = "ProfileFixture/" + VERSION
    sys_version = ""

    def caller(self):
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        user_id = IDENTITIES.get(token)
        return self.server.users[user_id] if user_id else None

    def serialize(self, user):
        if self.server.mode == "fixed":
            return {key: user[key] for key in PUBLIC_FIELDS}
        return dict(user)

    def do_GET(self):
        me = self.caller()
        if me is None:
            return self.reply(401, {"error": "authentication_required"})
        if self.path != "/profile":
            return self.reply(404, {"error": "not_found"})
        self.reply(200, self.serialize(me))

    def do_PATCH(self):
        me = self.caller()
        if me is None:
            return self.reply(401, {"error": "authentication_required"})
        if self.path == "/profile":
            target = me
        elif self.path.startswith("/users/"):
            if me["role"] != "admin":
                return self.reply(403, {"error": "forbidden"})
            target = self.server.users.get(self.path[len("/users/"):])
            if target is None:
                return self.reply(404, {"error": "not_found"})
        else:
            return self.reply(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
        except ValueError:
            return self.reply(400, {"error": "invalid_json"})
        if not isinstance(payload, dict):
            return self.reply(400, {"error": "invalid_json"})
        if self.server.mode == "fixed":
            rejected = sorted(set(payload) - WRITABLE[me["role"]])
            if rejected:
                return self.reply(400, {"error": "fields_not_writable", "fields": rejected})
        target.update(payload)
        self.reply(200, self.serialize(target))

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
    server.users = copy.deepcopy(SEED_USERS)
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
