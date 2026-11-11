#!/usr/bin/env python3
"""Toy OAuth authorization server for a PKCE experiment, version 1.0.0.

Binds IPv4 loopback only. One synthetic user, one synthetic public client.
Not an OAuth server for real use: it has no login page, no consent screen and
no token storage.
"""
import argparse
import base64
import hashlib
import hmac
import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, quote, urlsplit

VERSION = "1.0.0"
CLIENT_ID = "demo-public-app"
REDIRECT_URI = "demoapp://callback"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def s256(verifier):
    """RFC 7636 section 4.2: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))."""
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def make_pkce():
    """Client side, RFC 7636 section 4.1: 32 random octets, base64url encoded."""
    verifier = b64url(secrets.token_bytes(32))
    return verifier, s256(verifier)


class Handler(BaseHTTPRequestHandler):
    server_version = "PkceFixture/" + VERSION
    sys_version = ""

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path != "/authorize":
            return self.reply(404, {"error": "not_found"})
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if q.get("client_id") != CLIENT_ID or q.get("redirect_uri") != REDIRECT_URI:
            # RFC 6749 section 4.1.2.1: never redirect to an unregistered URI.
            return self.reply(400, {"error": "invalid_request", "error_description": "unknown client or redirect_uri"})
        if q.get("response_type") != "code":
            return self.redirect_error("unsupported_response_type", "only response_type=code", q)
        challenge = q.get("code_challenge")
        method = q.get("code_challenge_method", "plain")  # RFC 7636 section 4.3 default
        if self.server.mode == "fixed":
            if not challenge:
                return self.redirect_error("invalid_request", "code challenge required", q)
            if method != "S256":
                return self.redirect_error("invalid_request", "transform algorithm not supported", q)
        code = secrets.token_urlsafe(16)
        self.server.codes[code] = {"challenge": challenge, "method": method}
        params = "code=" + quote(code, safe="")
        if "state" in q:
            params += "&state=" + quote(q["state"], safe="")
        self.redirect(REDIRECT_URI + "?" + params)

    def do_POST(self):
        if urlsplit(self.path).path != "/token":
            return self.reply(404, {"error": "not_found"})
        length = int(self.headers.get("Content-Length", "0"))
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        if form.get("grant_type") != "authorization_code":
            return self.reply(400, {"error": "unsupported_grant_type"})
        # RFC 6749 section 10.5: codes are single use. Any attempt consumes the code.
        record = self.server.codes.pop(form.get("code", ""), None)
        if record is None or form.get("client_id") != CLIENT_ID or form.get("redirect_uri") != REDIRECT_URI:
            return self.reply(400, {"error": "invalid_grant"})
        if self.server.mode == "fixed":
            verifier = form.get("code_verifier", "")
            # RFC 7636 section 4.6: compare the transformed verifier with the stored challenge.
            ok = bool(verifier) and verifier.isascii() and hmac.compare_digest(s256(verifier), record["challenge"])
            if not ok:
                return self.reply(400, {"error": "invalid_grant"})
        self.reply(200, {"access_token": "demo-access-" + secrets.token_hex(6), "token_type": "Bearer"})

    def redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def redirect_error(self, error, description, q):
        params = "error=" + error + "&error_description=" + quote(description, safe="")
        if "state" in q:
            params += "&state=" + quote(q["state"], safe="")
        self.redirect(REDIRECT_URI + "?" + params)

    def reply(self, status, payload):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
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
    server.codes = {}
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
