#!/usr/bin/env python3
"""Local web server that publishes security.txt files, some broken and some correct.

Binds 127.0.0.1 only. Two modes:
  broken  five defective publications, one defect each
  fixed   the corrected file plus two valid variants used as controls
The files are synthetic. Every address uses the reserved example.com domain.
"""
import argparse
import datetime
import http.server
import json
import sys

VERSION = "1.0.0"
TEXT = "text/plain; charset=utf-8"


def future(days):
    stamp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    return stamp.strftime("%Y-%m-%dT%H:%M:%SZ")


def corrected():
    return ("# Synthetic security.txt for the local fixture\r\n"
            "Contact: mailto:security@example.com\r\n"
            "Contact: https://example.com/security/report\r\n"
            "Expires: " + future(180) + "\r\n"
            "Policy: https://example.com/security/policy\r\n"
            "Preferred-Languages: en\r\n")


def routes(mode):
    """Map request path to (status, content type, body)."""
    ok = lambda body, ctype=TEXT: (200, ctype, body)
    mail = "Contact: mailto:security@example.com\n"
    if mode == "broken":
        return {
            # Defect 1, wrong path: a valid file exists only at the legacy top-level path.
            "/security.txt": ok(mail + "Expires: " + future(180) + "\n"),
            # Defect 2, missing Expires.
            "/noexpires/.well-known/security.txt": ok(mail + "Policy: https://example.com/security/policy\n"),
            # Defect 3, expired date.
            "/expired/.well-known/security.txt": ok(mail + "Expires: 2025-01-01T00:00:00Z\n"),
            # Defect 4, http contact.
            "/httpcontact/.well-known/security.txt": ok("Contact: http://example.com/security/report\n" + "Expires: " + future(180) + "\n"),
            # Defect 5, served as HTML.
            "/html/.well-known/security.txt": ok(mail + "Expires: " + future(180) + "\n", "text/html; charset=utf-8"),
        }
    signed = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
              "# Synthetic: the signature block below is a placeholder, not a real signature\n"
              + mail + "Expires: " + future(180) + "\n"
              "-----BEGIN PGP SIGNATURE-----\n\nAAAAplaceholderAAAA\n-----END PGP SIGNATURE-----\n")
    return {
        "/.well-known/security.txt": ok(corrected()),
        "/minimal/.well-known/security.txt": ok(mail + "Expires: " + future(90) + "\n"),
        "/signed/.well-known/security.txt": ok(signed),
    }


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        status, ctype, body = self.server.table.get(self.path, (404, "text/plain; charset=utf-8", "not found\n"))
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("broken", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=0, help="0 selects a free port")
    args = parser.parse_args()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.table = routes(args.mode)
    print(json.dumps({"fixture_version": VERSION, "mode": args.mode,
                      "base_url": "http://127.0.0.1:%d" % server.server_address[1],
                      "paths": sorted(server.table)}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
