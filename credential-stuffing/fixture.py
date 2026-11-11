#!/usr/bin/env python3
"""Synthetic credential stuffing fixture 1.0.0. Binds IPv4 loopback only.

All accounts, passwords, "leaked" pairs and second-factor secrets are generated
from a fixed seed. Nothing here is a real credential.
"""
import argparse
import hashlib
import hmac
import json
import random
import secrets
import struct
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"
SEED = 20261111
LOCKOUT_AFTER = 5       # failed attempts on ONE account before it locks
BUDGET_LIMIT = 10       # login attempts per client address per window (fixed mode)
BUDGET_WINDOW = 60      # seconds
CONTROLS = ("budget", "leaked", "mfa")


def sha1_hex(text):
    return hashlib.sha1(text.encode()).hexdigest()


def password_hash(password, salt):
    # Toy cost factor so the fixture runs fast. Real systems need a slow, tuned hash.
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000).hex()


def totp(secret, at=None, step=30, digits=6):
    """RFC 6238 TOTP with HMAC-SHA-1."""
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def build_data():
    """Deterministic synthetic data. The same seed always gives the same data."""
    rng = random.Random(SEED)

    def word(prefix):
        return prefix + "-" + "%08x" % rng.getrandbits(32)

    users = ["user%02d@example.test" % n for n in range(1, 61)]
    own = {u: word("own") for u in users}
    reuse_users = sorted(rng.sample(users, 12))
    reused = {u: word("reuse") for u in reuse_users}
    stale_users = sorted(rng.sample([u for u in users if u not in reused], 18))
    stale = {u: word("old") for u in stale_users}

    passwords = dict(own)
    passwords.update(reused)                      # these 12 users reused a leaked password

    pairs = [(u, reused[u]) for u in reuse_users]         # 12 pairs still valid
    pairs += [(u, stale[u]) for u in stale_users]         # 18 pairs for real users, password since changed
    pairs += [("ghost%03d@example.test" % n, word("ghost")) for n in range(1, 71)]  # 70 users we do not have
    rng.shuffle(pairs)

    # The defender's leaked-password corpus misses the passwords of three reuse accounts.
    gap_users = [reuse_users[3], reuse_users[7], reuse_users[11]]
    corpus = {sha1_hex(p) for (u, p) in pairs if u not in gap_users}
    corpus |= {sha1_hex(word("filler")) for _ in range(30)}

    salts = {u: rng.getrandbits(64).to_bytes(8, "big") for u in users}
    mfa_secrets = {u: rng.getrandbits(160).to_bytes(20, "big") for u in users}
    return {"users": users, "passwords": passwords, "pairs": pairs, "valid": reused,
            "gap_users": gap_users, "corpus": corpus, "salts": salts, "mfa_secrets": mfa_secrets}


class Handler(BaseHTTPRequestHandler):
    server_version = "StuffingFixture/" + VERSION
    sys_version = ""

    def do_GET(self):
        if self.path == "/_stats":   # fixture-only counters, used by verify.py
            s = self.server
            stats = dict(s.stats)
            stats["max_failures_on_one_account"] = max(s.failures.values(), default=0)
            stats["controls"] = sorted(s.controls)
            return self.reply(200, stats)
        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/login":
            return self.reply(404, {"error": "not_found"})
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = json.loads(raw)
            username, password, code = str(body["username"]), str(body["password"]), body.get("code")
        except (ValueError, KeyError, TypeError):
            return self.reply(400, {"error": "bad_request"})
        s = self.server
        s.stats["attempts"] += 1

        if "budget" in s.controls:
            # Budget keyed on the real peer address, across all accounts.
            client, now = self.client_address[0], time.monotonic()
            hits = [t for t in s.hits.get(client, []) if now - t < BUDGET_WINDOW]
            if len(hits) >= BUDGET_LIMIT:
                s.hits[client] = hits
                s.stats["budget_denials"] += 1
                retry = str(int(BUDGET_WINDOW - (now - hits[0])) + 1)
                return self.reply(429, {"error": "too_many_attempts"}, {"Retry-After": retry})
            hits.append(now)
            s.hits[client] = hits

        if s.failures.get(username, 0) >= LOCKOUT_AFTER:   # per-account lockout, in both modes
            s.stats["lockouts"] += 1
            return self.reply(423, {"error": "account_locked"})

        account = s.accounts.get(username)
        if account:
            correct = hmac.compare_digest(password_hash(password, account["salt"]), account["hash"])
        else:
            password_hash(password, b"\0" * 8)             # similar work for unknown users
            correct = False

        if correct and "leaked" in s.controls and sha1_hex(password) in s.corpus:
            # Right password, but it is in the leaked corpus: refuse, flag for reset, same answer as a wrong password.
            s.stats["leaked_denials"] += 1
            s.must_reset.add(username)
            correct = False

        if not correct:
            s.failures[username] = s.failures.get(username, 0) + 1
            return self.reply(401, {"error": "invalid_credentials"})

        if "mfa" in s.controls:
            if not code:
                s.stats["mfa_challenges"] += 1
                return self.reply(401, {"error": "second_factor_required"})
            now = time.time()
            if not any(hmac.compare_digest(totp(account["mfa_secret"], now + 30 * d), str(code)) for d in (-1, 0, 1)):
                s.failures[username] = s.failures.get(username, 0) + 1
                return self.reply(401, {"error": "invalid_code"})

        s.failures[username] = 0
        s.stats["sessions_issued"] += 1
        self.reply(200, {"status": "ok", "username": username, "session": secrets.token_hex(8)})

    def reply(self, status, payload, extra=None):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def make_server(port, controls):
    data = build_data()
    server = HTTPServer(("127.0.0.1", port), Handler)
    server.controls = set(controls)
    server.corpus = data["corpus"]
    server.accounts = {u: {"salt": data["salts"][u], "hash": password_hash(data["passwords"][u], data["salts"][u]),
                           "mfa_secret": data["mfa_secrets"][u]} for u in data["users"]}
    server.failures, server.hits, server.must_reset = {}, {}, set()
    server.stats = {"attempts": 0, "sessions_issued": 0, "lockouts": 0, "budget_denials": 0,
                    "leaked_denials": 0, "mfa_challenges": 0}
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--controls", default=None,
                        help="fixed mode only: comma list from budget,leaked,mfa (default: all three)")
    parser.add_argument("--port", type=int, default=8765, help="0 chooses a free local port")
    args = parser.parse_args()
    if args.mode == "vulnerable":
        if args.controls:
            parser.error("--controls only applies to --mode fixed")
        controls = []
    else:
        controls = args.controls.split(",") if args.controls else list(CONTROLS)
        if not set(controls) <= set(CONTROLS):
            parser.error("unknown control in --controls")
    server = make_server(args.port, controls)
    print(json.dumps({"fixture_version": VERSION, "mode": args.mode, "controls": sorted(controls),
                      "base_url": "http://127.0.0.1:" + str(server.server_port)}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main())
