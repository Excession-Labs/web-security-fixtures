#!/usr/bin/env python3
"""Synthetic HSTS fixture 1.0.0. One plain-HTTP and one TLS listener on 127.0.0.1.

The TLS certificate is self-signed, made with the openssl command at start-up in a
temporary directory. The private key is deleted as soon as the server has loaded it.
"""
import argparse
import json
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "1.0.0"
HOST = "hsts.test"  # resolved to 127.0.0.1 by curl --resolve; never a real name
PAGE = b"hsts fixture page: synthetic content\n"
YEAR = 31536000

# Header sent on HTTPS responses and on plain-HTTP responses, per mode.
POLICY = {
    "vulnerable": {"https": None, "http": None, "http_redirects": False},
    "short": {"https": "max-age=300", "http": None, "http_redirects": True},
    "misplaced": {"https": None, "http": "max-age=31536000; includeSubDomains", "http_redirects": True},
    "fixed": {"https": "max-age=%d; includeSubDomains" % YEAR, "http": None, "http_redirects": True},
}


def make_handler(mode, https_port_ref, scheme):
    policy = POLICY[mode]

    class Handler(BaseHTTPRequestHandler):
        server_version = "HstsFixture/" + VERSION
        sys_version = ""

        def do_GET(self):
            if scheme == "http" and policy["http_redirects"]:
                self.send_response(301)
                self.send_header("Location", "https://%s:%d%s" % (HOST, https_port_ref[0], self.path))
                self.send_header("Content-Length", "0")
                if policy["http"]:
                    self.send_header("Strict-Transport-Security", policy["http"])
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(PAGE)))
            if policy[scheme]:
                self.send_header("Strict-Transport-Security", policy[scheme])
            self.end_headers()
            self.wfile.write(PAGE)

        def log_message(self, *_args):
            pass

    return Handler


def make_context(workdir):
    cert, key = Path(workdir) / "cert.pem", Path(workdir) / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=" + HOST,
                    "-addext", "subjectAltName=DNS:" + HOST],
                   check=True, capture_output=True, timeout=30)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    key.unlink()  # the key now lives only in this process
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=sorted(POLICY), required=True)
    parser.add_argument("--http-port", type=int, default=0, help="0 chooses a free local port")
    parser.add_argument("--https-port", type=int, default=0, help="0 chooses a free local port")
    args = parser.parse_args()
    workdir = tempfile.mkdtemp(prefix="hsts-fixture-")
    try:
        context = make_context(workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    https_port_ref = [0]
    https = ThreadingHTTPServer(("127.0.0.1", args.https_port), make_handler(args.mode, https_port_ref, "https"))
    https.socket = context.wrap_socket(https.socket, server_side=True)
    https_port_ref[0] = https.server_port
    http = ThreadingHTTPServer(("127.0.0.1", args.http_port), make_handler(args.mode, https_port_ref, "http"))
    for server in (https, http):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(json.dumps({"fixture_version": VERSION, "mode": args.mode, "host": HOST,
                      "http_port": http.server_port, "https_port": https.server_port}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        http.shutdown()
        https.shutdown()


if __name__ == "__main__":
    sys.exit(main())
