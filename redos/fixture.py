#!/usr/bin/env python3
"""Synthetic ReDoS fixture 1.0.0. Binds IPv4 loopback only.

GET /validate?name=<text> checks a display name. The server is single-threaded
on purpose: one slow regex match delays every request queued behind it.
"""
import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0.0"
# Vulnerable: \w+ and the optional \s? can split one run of letters in many ways.
VULNERABLE_PATTERN = re.compile(r"^(\w+\s?)*$")
# Fixed: words are separated by exactly one space, so each input has one parse.
FIXED_PATTERN = re.compile(r"^\w+(?: \w+)*$")
MAX_LENGTH = 64


class Handler(BaseHTTPRequestHandler):
    server_version = "RedosFixture/" + VERSION
    sys_version = ""

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path != "/validate":
            return self.reply(404, {"error": "not_found"})
        name = parse_qs(url.query).get("name", [None])[0]
        if name is None:
            return self.reply(400, {"error": "missing_name"})
        fixed = self.server.mode == "fixed"
        if fixed and len(name) > MAX_LENGTH:
            return self.reply(413, {"error": "name_too_long", "max_length": MAX_LENGTH})
        pattern = FIXED_PATTERN if fixed else VULNERABLE_PATTERN
        started = time.perf_counter()
        matched = pattern.match(name) is not None
        match_ms = round((time.perf_counter() - started) * 1000, 3)
        if matched:
            return self.reply(200, {"valid": True, "length": len(name)}, match_ms)
        self.reply(400, {"valid": False, "length": len(name)}, match_ms)

    def reply(self, status, payload, match_ms=None):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if match_ms is not None:
            self.send_header("X-Regex-Ms", str(match_ms))
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
