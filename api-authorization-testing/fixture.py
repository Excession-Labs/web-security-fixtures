#!/usr/bin/env python3
"""Synthetic API authorization fixture 1.0.0. Binds IPv4 loopback only."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"
IDENTITIES = {"demo-alice-token": "alice", "demo-bob-token": "bob"}
OBJECTS = {
    "/objects/alice-note": {"id": "alice-note", "owner": "alice", "text": "Alice synthetic note"},
    "/objects/bob-note": {"id": "bob-note", "owner": "bob", "text": "Bob synthetic note"},
}


class Handler(BaseHTTPRequestHandler):
    server_version = "AuthzFixture/" + VERSION
    sys_version = ""

    def do_GET(self):
        identity = IDENTITIES.get(self.headers.get("Authorization", "").removeprefix("Bearer "))
        if identity is None:
            return self.reply(401, {"error": "authentication_required"})
        obj = OBJECTS.get(self.path)
        if obj is None:
            return self.reply(404, {"error": "not_found"})
        if self.server.mode == "fixed" and obj["owner"] != identity:
            return self.reply(403, {"error": "forbidden"})
        self.reply(200, obj)

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
