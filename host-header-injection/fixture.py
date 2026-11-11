#!/usr/bin/env python3
"""Synthetic password-reset fixture 1.0.0. Binds IPv4 loopback only.

Vulnerable mode builds the reset link's host from the request's Host header,
preferring X-Forwarded-Host when present. Fixed mode checks the Host header
against an allowlist and always builds the link from a configured canonical
origin. Instead of sending mail, both modes append the rendered message to
a local outbox file.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"
CANONICAL_ORIGIN = "https://app.example.test"
ALLOWED_HOSTS = {"app.example.test"}
# Synthetic demo account with a reset token issued at account creation.
# Public demo value; it has no meaning outside this fixture.
TOKENS = {"victim@example.test": "a93fd21c7e4b4f0f9d3b6c8a1e2f5d7c"}


class Handler(BaseHTTPRequestHandler):
    server_version = "ResetFixture/" + VERSION
    sys_version = ""

    def do_POST(self):
        if self.path != "/reset-password":
            return self.reply(404, {"error": "not_found"})
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self.reply(400, {"error": "invalid_json"})
        email = payload.get("email", "")
        host_header = self.headers.get("Host", "")
        forwarded_host = self.headers.get("X-Forwarded-Host")

        if self.server.mode == "fixed":
            if host_header not in ALLOWED_HOSTS:
                return self.reply(400, {"error": "unrecognized_host"})
            origin = CANONICAL_ORIGIN
        else:
            origin = "https://" + (forwarded_host or host_header)

        token = TOKENS.get(email)
        if token is None:
            # Negative control: do not reveal whether the account exists.
            return self.reply(202, {"status": "accepted"})

        link = origin + "/reset?token=" + token
        message = {"to": email, "subject": "Password reset", "body": "Reset your password: " + link}
        with open(self.server.outbox_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(message, sort_keys=True) + "\n")
        self.reply(202, {"status": "accepted"})

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
    parser.add_argument("--outbox", required=True, help="path to the outbox file this server appends to")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    server.outbox_path = args.outbox
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
