#!/usr/bin/env python3
"""Synthetic SSRF fixture 1.0.0. Three roles, all bound to IPv4 loopback.

Roles:
  target   - stand-in for the "public" site a URL-preview feature is meant to fetch.
             Serves /article (200) and /redirect (302 to a URL given by --redirect-to).
  metadata - stand-in for an internal metadata service holding one synthetic secret.
             Serves /latest/meta-data/secret (200) and nothing else.
  preview  - the endpoint under test. Fetches a caller-supplied URL and reports what
             it found. --mode selects the defense: vulnerable, naive, or strict.

Hostname resolution for the symbolic name "target.test" is a fixed local table
instead of real DNS, so the whole fixture runs fully offline and deterministically.
Every other hostname (127.0.0.1, localhost, decimal/hex/octal IP forms) resolves
through the normal socket layer, which is why those forms still land on loopback.
"""
import argparse
import json
import socket
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

VERSION = "1.0.0"
SECRET = "synthetic-metadata-secret-7f3c9e21"
LOCAL_HOSTS = {"target.test": "127.0.0.1"}

_real_getaddrinfo = socket.getaddrinfo


def _patched_getaddrinfo(host, *args, **kwargs):
    host = LOCAL_HOSTS.get(host, host)
    return _real_getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _patched_getaddrinfo


def resolve(hostname):
    """Resolve a hostname to its first IPv4 address, using the patched lookup above."""
    infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
    return infos[0][4][0]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevents urllib from automatically following a 3xx response."""

    def redirect_request(self, *_args, **_kwargs):
        return None


class TargetHandler(BaseHTTPRequestHandler):
    server_version = "SsrfTarget/" + VERSION
    sys_version = ""

    def do_GET(self):
        if self.path == "/article":
            body = b"<html><title>Public Article</title><body>Ordinary public content.</body></html>"
            return self.reply(200, "text/html", body)
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", self.server.redirect_to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        return self.reply(404, "application/json", b'{"error": "not_found"}')

    def reply(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class MetadataHandler(BaseHTTPRequestHandler):
    server_version = "SsrfMetadata/" + VERSION
    sys_version = ""

    def do_GET(self):
        if self.path == "/latest/meta-data/secret":
            body = json.dumps({"credential": SECRET}).encode()
            return self.reply(200, body)
        return self.reply(404, b'{"error": "not_found"}')

    def reply(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class PreviewHandler(BaseHTTPRequestHandler):
    server_version = "SsrfPreview/" + VERSION
    sys_version = ""
    NAIVE_DENYLIST = {"127.0.0.1", "localhost", "0.0.0.0"}

    def do_GET(self):
        parsed_self = urlparse(self.path)
        if parsed_self.path != "/preview":
            return self.reply(404, {"error": "not_found"})
        query = parse_qs(parsed_self.query or "")
        url = query["url"][0] if "url" in query else None
        if not url:
            return self.reply(400, {"error": "missing_url"})
        return self.handle_preview(url)

    def handle_preview(self, url):
        mode = self.server.mode
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port

        if mode == "naive" and hostname in self.NAIVE_DENYLIST:
            return self.reply(403, {
                "mode": mode, "requested_url": url, "blocked": True,
                "reason": "denylisted_host", "requested_host": hostname,
                "resolved_ip": None, "upstream_status": None, "secret_leaked": False,
            })

        resolved_ip = None
        if mode == "strict":
            try:
                resolved_ip = resolve(hostname)
            except OSError:
                return self.reply(502, {
                    "mode": mode, "requested_url": url, "blocked": True,
                    "reason": "dns_error", "requested_host": hostname,
                    "resolved_ip": None, "upstream_status": None, "secret_leaked": False,
                })
            if (resolved_ip, port) not in self.server.allowlist:
                return self.reply(403, {
                    "mode": mode, "requested_url": url, "blocked": True,
                    "reason": "destination_not_allowlisted", "requested_host": hostname,
                    "resolved_ip": resolved_ip, "upstream_status": None, "secret_leaked": False,
                })

        opener = urllib.request.build_opener(NoRedirect) if mode == "strict" else urllib.request.build_opener()
        try:
            with opener.open(url, timeout=3) as upstream:
                status = upstream.status
                body = upstream.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read(4096) if exc.fp else b""
            body = raw.decode("utf-8", "replace")
        except OSError as exc:
            return self.reply(502, {
                "mode": mode, "requested_url": url, "blocked": False,
                "reason": "fetch_error:" + type(exc).__name__, "requested_host": hostname,
                "resolved_ip": resolved_ip, "upstream_status": None, "secret_leaked": False,
            })

        return self.reply(200, {
            "mode": mode, "requested_url": url, "blocked": False, "reason": None,
            "requested_host": hostname, "resolved_ip": resolved_ip,
            "upstream_status": status, "secret_leaked": SECRET in body,
            "body_preview": body[:200],
        })

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


def run_server(handler_cls, port, configure=None):
    server = HTTPServer(("127.0.0.1", port), handler_cls)
    if configure:
        configure(server)
    print(json.dumps({"fixture_version": VERSION,
                      "base_url": "http://127.0.0.1:" + str(server.server_port)}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("target", "metadata", "preview"), required=True)
    parser.add_argument("--port", type=int, default=0, help="0 chooses a free local port")
    parser.add_argument("--mode", choices=("vulnerable", "naive", "strict"), help="preview role only")
    parser.add_argument("--redirect-to", help="target role only: Location header for /redirect")
    parser.add_argument("--allow", action="append", default=[],
                        help="preview strict mode only: ip:port allowed as a fetch destination, repeatable")
    args = parser.parse_args()

    if args.role == "target":
        if not args.redirect_to:
            parser.error("--role target requires --redirect-to")
        run_server(TargetHandler, args.port, lambda s: setattr(s, "redirect_to", args.redirect_to))
    elif args.role == "metadata":
        run_server(MetadataHandler, args.port)
    else:
        if not args.mode:
            parser.error("--role preview requires --mode")
        allowlist = set()
        for entry in args.allow:
            ip, _, port_str = entry.rpartition(":")
            allowlist.add((ip, int(port_str)))
        run_server(PreviewHandler, args.port,
                   lambda s: (setattr(s, "mode", args.mode), setattr(s, "allowlist", allowlist)))


if __name__ == "__main__":
    main()
