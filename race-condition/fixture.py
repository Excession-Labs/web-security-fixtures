#!/usr/bin/env python3
"""Synthetic single-use coupon fixture 1.0.0. Binds IPv4 loopback only.

Two modes against the same on-disk SQLite table (a temp file removed when the
process exits). Each request opens its own short-lived connection; sqlite3
connection objects are not safe to share between threads without extra
locking, and sharing one here would crash the handler rather than
demonstrate the application-level race this fixture is about.

  vulnerable - reads uses_remaining, sleeps for --delay seconds, then writes
               uses_remaining - 1 in a second statement, in a second
               connection. The sleep is an artificial widening of the real
               check-then-act window; it exists so a local demonstration
               can reproduce the race without needing network-level timing
               tricks.
  fixed      - a single conditional UPDATE does the check and the write in
               one SQLite statement: WHERE code = ? AND uses_remaining > 0.
               There is no separate read step and no window between a
               decision and a write for another request to land in.

Runs on http.server.ThreadingHTTPServer, so each HTTP connection is handled
on its own thread, the same concurrency model many small Python services use.
"""
import argparse
import json
import os
import sqlite3
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.0.0"

# Two independent coupons so a single-threaded control test does not consume
# the coupon used for the concurrent burst.
SEED_COUPONS = {
    "SAVE10": 1,     # used only for the concurrent burst
    "CONTROL1": 1,   # used only for the sequential positive/negative control
}


def connect(db_path):
    # timeout=5 sets SQLite's busy_timeout: a connection waits for another
    # connection's write lock instead of raising "database is locked".
    conn = sqlite3.connect(db_path, timeout=5, isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def make_db():
    fd, db_path = tempfile.mkstemp(prefix="coupon-fixture-", suffix=".sqlite3")
    os.close(fd)
    conn = connect(db_path)
    conn.execute("CREATE TABLE coupons (code TEXT PRIMARY KEY, uses_remaining INTEGER NOT NULL)")
    conn.executemany("INSERT INTO coupons (code, uses_remaining) VALUES (?, ?)", SEED_COUPONS.items())
    conn.close()
    return db_path


class CouponServer(ThreadingHTTPServer):
    # The default socketserver backlog (5) can refuse connections when
    # BURST_SIZE simultaneous clients all connect at once; raise it so the
    # demonstration is not limited by the TCP accept queue instead of by
    # the race itself.
    request_queue_size = 128
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    server_version = "CouponFixture/" + VERSION
    sys_version = ""

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/redeem":
            return self.reply(404, {"error": "not_found"})
        code = self.headers.get("X-Coupon-Code")
        if not code:
            return self.reply(400, {"error": "missing_coupon_code"})
        mode = self.server.mode
        delay = self.server.delay
        if mode == "vulnerable":
            check_conn = connect(self.server.db_path)
            try:
                row = check_conn.execute(
                    "SELECT uses_remaining FROM coupons WHERE code = ?", (code,)
                ).fetchone()
            finally:
                check_conn.close()
            if row is None:
                return self.reply(404, {"error": "unknown_coupon"})
            remaining = row[0]
            if remaining <= 0:
                return self.reply(409, {"error": "coupon_exhausted"})
            # Artificial delay between the check and the write, on a separate
            # connection from the one that will perform the write below.
            # This widens a real check-then-act window that would otherwise
            # be a few microseconds of socket and interpreter overhead, so a
            # handful of threads on one laptop can reliably land inside it.
            time.sleep(delay)
            write_conn = connect(self.server.db_path)
            try:
                write_conn.execute(
                    "UPDATE coupons SET uses_remaining = uses_remaining - 1 WHERE code = ?", (code,)
                )
            finally:
                write_conn.close()
            return self.reply(200, {"status": "redeemed", "code": code})
        else:  # fixed
            conn = connect(self.server.db_path)
            try:
                cur = conn.execute(
                    "UPDATE coupons SET uses_remaining = uses_remaining - 1 "
                    "WHERE code = ? AND uses_remaining > 0",
                    (code,),
                )
                if cur.rowcount == 1:
                    return self.reply(200, {"status": "redeemed", "code": code})
                exists = conn.execute(
                    "SELECT 1 FROM coupons WHERE code = ?", (code,)
                ).fetchone()
            finally:
                conn.close()
            if exists is None:
                return self.reply(404, {"error": "unknown_coupon"})
            return self.reply(409, {"error": "coupon_exhausted"})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/status":
            return self.reply(404, {"error": "not_found"})
        qs = parse_qs(parsed.query)
        code = (qs.get("code") or [None])[0]
        if not code:
            return self.reply(400, {"error": "missing_coupon_code"})
        conn = connect(self.server.db_path)
        try:
            row = conn.execute(
                "SELECT uses_remaining FROM coupons WHERE code = ?", (code,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return self.reply(404, {"error": "unknown_coupon"})
        return self.reply(200, {"code": code, "uses_remaining": row[0]})

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
    parser.add_argument("--delay", type=float, default=0.05,
                         help="vulnerable mode only: seconds slept between the check and the write")
    args = parser.parse_args()
    server = CouponServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    server.delay = args.delay
    server.db_path = make_db()
    print(json.dumps({
        "fixture_version": VERSION, "mode": args.mode, "delay_seconds": args.delay,
        "base_url": "http://127.0.0.1:" + str(server.server_port),
        "seed_coupons": SEED_COUPONS,
    }), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        try:
            os.remove(server.db_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
