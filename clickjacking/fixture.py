#!/usr/bin/env python3
"""Synthetic clickjacking fixture 1.0.0. Binds IPv4 loopback only.

Role "target" serves an account page with a delete button and counts delete requests.
Role "attacker" serves a page that frames the target under a decoy button.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"

TARGET_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Synthetic account</title>
<style>body{margin:0;font:16px sans-serif}
#delete{position:absolute;left:100px;top:100px;width:200px;height:50px}</style></head>
<body><p style="margin:8px">Synthetic account settings</p>
<form method="post" action="/delete"><button id="delete" type="submit">Delete synthetic account</button></form>
</body></html>
"""

ATTACK_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Prize page</title>
<style>body{margin:0;font:16px sans-serif}
#decoy{position:absolute;left:100px;top:100px;width:200px;height:50px;z-index:1}
#frame{position:absolute;left:0;top:0;width:400px;height:300px;border:0;opacity:0;z-index:2}</style></head>
<body><button id="decoy" type="button">Claim your prize</button>
<iframe id="frame" src="__TARGET__/account" title="hidden target"></iframe>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ClickjackFixture/" + VERSION
    sys_version = ""

    def do_GET(self):
        if self.server.role == "attacker":
            if self.path == "/attack":
                return self.reply(200, "text/html", ATTACK_PAGE.replace("__TARGET__", self.server.target_url))
            return self.reply(404, "text/plain", "not found\n")
        if self.path == "/account":
            return self.reply(200, "text/html", TARGET_PAGE)
        if self.path == "/state":
            return self.reply(200, "application/json", json.dumps({"delete_requests": self.server.deletes}) + "\n")
        self.reply(404, "text/plain", "not found\n")

    def do_POST(self):
        if self.server.role == "target" and self.path == "/delete":
            self.server.deletes += 1
            return self.reply(200, "text/plain", "account deleted\n")
        self.reply(404, "text/plain", "not found\n")

    def reply(self, status, ctype, text):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self.server.role == "target" and self.server.mode == "fixed":
            # The fix: forbid every origin from framing target responses.
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("target", "attacker"), default="target")
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--target-url", default="")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.role, server.mode, server.target_url, server.deletes = args.role, args.mode, args.target_url, 0
    print(json.dumps({"role": args.role, "mode": args.mode,
                      "base_url": "http://127.0.0.1:%d" % server.server_address[1]}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
