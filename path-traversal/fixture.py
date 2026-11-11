#!/usr/bin/env python3
"""Local file-download fixture for a path traversal demonstration.

Modes: vulnerable (joins the name to the base directory), naive (strips "../"
once, then joins) and fixed (resolves the real path and checks it stays under
the base directory). Binds 127.0.0.1 only. All files are synthetic and live in
a temporary directory that this program creates and deletes.
"""
import argparse
import json
import os
import signal
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

VERSION = "1.0.0"
SECRET_TEXT = "SYNTHETIC-SECRET-0001: not a real credential\n"
PREFIX = "/files/"


def resolve_vulnerable(base, name):
    return os.path.join(base, name)


def resolve_naive(base, name):
    return os.path.join(base, name.replace("../", ""))


def resolve_fixed(base, name):
    root = os.path.realpath(base)
    target = os.path.realpath(os.path.join(root, name))
    if os.path.commonpath([root, target]) != root:
        return None
    return target


RESOLVERS = {"vulnerable": resolve_vulnerable, "naive": resolve_naive, "fixed": resolve_fixed}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def reply(self, status, body, ctype="text/plain; charset=utf-8"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        raw = self.path.split("?", 1)[0]
        if not raw.startswith(PREFIX):
            return self.reply(404, '{"error": "not_found"}\n', "application/json")
        name = unquote(raw[len(PREFIX):])  # decoded exactly once
        try:
            target = RESOLVERS[self.server.mode](self.server.base_dir, name)
            if target is None:
                return self.reply(403, '{"error": "forbidden"}\n', "application/json")
            if not os.path.isfile(target):
                return self.reply(404, '{"error": "not_found"}\n', "application/json")
            with open(target, "rb") as handle:
                return self.reply(200, handle.read())
        except ValueError:
            return self.reply(400, '{"error": "bad_name"}\n', "application/json")

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=sorted(RESOLVERS), required=True)
    parser.add_argument("--port", type=int, default=0, help="0 selects a free port")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    with tempfile.TemporaryDirectory(prefix="pt-fixture-") as tmp:
        base = os.path.join(tmp, "public")
        os.makedirs(os.path.join(base, "docs"))
        with open(os.path.join(base, "report.txt"), "w") as f:
            f.write("Quarterly report (synthetic)\n")
        with open(os.path.join(base, "docs", "guide.txt"), "w") as f:
            f.write("Guide inside a subdirectory (synthetic)\n")
        secret = os.path.join(tmp, "secret.txt")  # outside base, inside tmp
        with open(secret, "w") as f:
            f.write(SECRET_TEXT)
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
        server.mode, server.base_dir = args.mode, base
        print(json.dumps({"base_url": "http://127.0.0.1:%d" % server.server_address[1],
                          "mode": args.mode, "base_dir": base, "secret_path": secret,
                          "version": VERSION}), flush=True)
        try:
            server.serve_forever()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
