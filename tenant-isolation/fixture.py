#!/usr/bin/env python3
"""Synthetic multi-tenant API fixture 1.0.0. Binds IPv4 loopback only."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0.0"
# bearer value -> (user, tenant). Two tenants, two users each. All values are public demo data.
SESSIONS = {
    "demo-acme-alice": ("alice", "acme"), "demo-acme-amy": ("amy", "acme"),
    "demo-globex-bob": ("bob", "globex"), "demo-globex-bea": ("bea", "globex"),
}
INVOICES = [
    {"id": "acme-inv-1", "tenant": "acme", "customer": "Northwind Demo", "amount_cents": 12000},
    {"id": "acme-inv-2", "tenant": "acme", "customer": "Contoso Demo", "amount_cents": 8800},
    {"id": "globex-inv-1", "tenant": "globex", "customer": "Fabrikam Demo", "amount_cents": 45000},
    {"id": "globex-inv-2", "tenant": "globex", "customer": "Adatum Demo", "amount_cents": 3100},
]


class Handler(BaseHTTPRequestHandler):
    server_version = "TenantFixture/" + VERSION
    sys_version = ""

    def session(self):
        return SESSIONS.get(self.headers.get("Authorization", "").removeprefix("Bearer "))

    def do_GET(self):
        who = self.session()
        if who is None:
            return self.reply(401, {"error": "authentication_required"})
        user, tenant = who
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        if url.path == "/invoices":
            return self.list_invoices(tenant, query)
        if url.path == "/reports/usage":
            return self.report(tenant, user, url, query)
        if url.path.startswith("/exports/"):
            return self.get_export(tenant, url.path[len("/exports/"):])
        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        who = self.session()
        if who is None:
            return self.reply(401, {"error": "authentication_required"})
        user, tenant = who
        if self.path != "/exports":
            return self.reply(404, {"error": "not_found"})
        job_id = "exp-%04d" % (len(self.server.jobs) + 1)
        rows = [r for r in INVOICES if r["tenant"] == tenant]
        job = {"job_id": job_id, "tenant": tenant, "created_by": user, "status": "done", "rows": rows}
        self.server.jobs[job_id] = job
        self.reply(201, {"job_id": job_id, "status": "done", "tenant": tenant})

    # Gap 1: the list endpoint trusts a tenant_id query parameter in vulnerable mode.
    def list_invoices(self, tenant, query):
        if self.server.mode == "vulnerable":
            scope = query.get("tenant_id", [tenant])[0]
        else:
            scope = tenant  # tenant comes from the session only; the parameter is ignored
        needle = query.get("q", [""])[0]
        rows = [r for r in INVOICES if r["tenant"] == scope and needle in r["id"]]
        self.reply(200, {"invoices": rows})

    # Gap 2: the response cache key leaves out the tenant in vulnerable mode.
    def report(self, tenant, user, url, query):
        key = url.path + "?" + url.query
        if self.server.mode == "fixed":
            key = "tenant:" + tenant + ":" + key
        if key in self.server.cache:
            return self.reply(200, self.server.cache[key], {"X-Cache": "HIT"})
        period = query.get("period", ["2026-09"])[0]
        total = {"acme": 20800, "globex": 48100}[tenant]
        report = {"tenant": tenant, "period": period, "total_cents": total, "generated_for": user}
        self.server.cache[key] = report
        self.reply(200, report, {"X-Cache": "MISS"})

    # Gap 3: the export lookup by job ID has no tenant check in vulnerable mode.
    def get_export(self, tenant, job_id):
        job = self.server.jobs.get(job_id)
        if job is None or (self.server.mode == "fixed" and job["tenant"] != tenant):
            return self.reply(404, {"error": "not_found"})
        self.reply(200, job)

    def reply(self, status, payload, extra=None):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra or {}).items():
            self.send_header(name, value)
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
    server.cache = {}
    server.jobs = {}
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
