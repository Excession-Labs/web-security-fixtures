#!/usr/bin/env python3
"""Synthetic API token check, fixture 1.0.0. Binds IPv4 loopback only.

vulnerable mode: byte-by-byte comparison that returns at the first mismatch.
                 --delay-ms adds an ARTIFICIAL sleep after each matching byte.
fixed mode:      hmac.compare_digest. --delay-ms is accepted and ignored.
"""
import argparse
import hmac
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def insecure_equals(supplied, expected, delay_s):
    if len(supplied) != len(expected):
        return False
    for got, want in zip(supplied, expected):
        if got != want:
            return False  # early return: time depends on how many bytes matched
        if delay_s:
            time.sleep(delay_s)  # artificial per-byte cost, stated in the post
    return True


def token_ok(mode, supplied, expected, delay_s):
    if mode == "fixed":
        return hmac.compare_digest(supplied, expected)
    return insecure_equals(supplied, expected, delay_s)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    wbufsize = 65536  # send headers and body in one write

    def log_message(self, *args):
        pass

    def do_GET(self):
        header = self.headers.get("Authorization", "")
        supplied = header[7:].encode() if header.startswith("Bearer ") else b""
        if self.path == "/api/v1/me" and token_ok(
                self.server.mode, supplied, self.server.token.encode(), self.server.delay_s):
            status, body = 200, {"account": "demo-service", "note": "synthetic data"}
        else:
            status, body = 401, {"error": "invalid_token"}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), default="vulnerable")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--token", default="0123456789abcdef", help="synthetic demo token")
    parser.add_argument("--delay-ms", type=float, default=0.0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    server.mode, server.token, server.delay_s = args.mode, args.token, args.delay_ms / 1000.0
    print(json.dumps({"base_url": "http://127.0.0.1:%d" % server.server_address[1],
                      "mode": args.mode, "delay_ms": args.delay_ms}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
