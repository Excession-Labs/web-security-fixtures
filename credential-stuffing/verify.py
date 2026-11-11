#!/usr/bin/env python3
"""Run a synthetic credential stuffing test against fixture.py with real curl requests.

No external network targets. Every server binds 127.0.0.1 on an OS-assigned port.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import platform
import select
import shlex
import subprocess
import sys
import time

import fixture

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
CURL = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
        "--http1.1", "--connect-timeout", "1", "--max-time", "3"]

# name -> (fixture mode, controls, list order). "valid-first" puts the 12 working pairs at the top of the list.
CONFIGS = {
    "vulnerable": ("vulnerable", [], "list"),
    "fixed": ("fixed", ["budget", "leaked", "mfa"], "list"),
    "fixed-budget-only": ("fixed", ["budget"], "list"),
    "fixed-budget-only-valid-first": ("fixed", ["budget"], "valid-first"),
    "fixed-leaked-only": ("fixed", ["leaked"], "list"),
    "fixed-mfa-only": ("fixed", ["mfa"], "list"),
}


def ordered_pairs(data, order):
    pairs = data["pairs"]
    if order == "valid-first":
        return sorted(pairs, key=lambda pair: 0 if data["valid"].get(pair[0]) == pair[1] else 1)
    return pairs


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Server:
    def __init__(self, mode, controls):
        command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"]
        if controls:
            command += ["--controls", ",".join(controls)]
        self.command = command
        self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ready, _, _ = select.select([self.process.stdout], [], [], 5)
        if not ready:
            raise RuntimeError("Fixture did not start within five seconds")
        self.info = json.loads(self.process.stdout.readline())
        if not self.info["base_url"].startswith("http://127.0.0.1:"):
            raise RuntimeError("Fixture returned a non-loopback address")
        self.url = self.info["base_url"]
        self.port = self.url.rsplit(":", 1)[1]

    def stop(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def post_login(server, username, password, code=None):
    body = {"username": username, "password": password}
    if code is not None:
        body["code"] = code
    command = CURL + ["--request", "POST", "--header", "Content-Type: application/json",
                      "--data-binary", json.dumps(body, sort_keys=True), server.url + "/login"]
    started, tick = now(), time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=5)
    head, _, payload = result.stdout.partition("\n\n")
    return {"command": command, "raw": result.stdout, "started_at": started,
            "elapsed_ms": round((time.monotonic() - tick) * 1000, 3), "curl_exit_code": result.returncode,
            "status": int(head.splitlines()[0].split()[1]), "body": json.loads(payload)}


def get_stats(server):
    result = subprocess.run(CURL + [server.url + "/_stats"], capture_output=True, text=True, timeout=5)
    return json.loads(result.stdout.partition("\n\n")[2])


def model(data, controls, pairs):
    """Expected outcome of the stuffing run, computed from the data without the server."""
    valid, corpus = data["valid"], data["corpus"]
    allowed = fixture.BUDGET_LIMIT if "budget" in controls else len(pairs)
    out = {"attempts": len(pairs), "reached_password_check": allowed, "budget_denials": len(pairs) - allowed,
           "sessions_opened": 0, "pairs_confirmed": 0, "leaked_denials": 0}
    for user, password in pairs[:allowed]:
        if valid.get(user) != password:
            continue
        if "leaked" in controls and fixture.sha1_hex(password) in corpus:
            out["leaked_denials"] += 1
            continue
        out["pairs_confirmed"] += 1
        if "mfa" not in controls:
            out["sessions_opened"] += 1
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    data = fixture.build_data()
    pair_users = {u for u, _ in data["pairs"]}
    plain_users = [u for u in data["users"] if u not in pair_users]
    legit, victim = plain_users[0], plain_users[1]
    legit_leaked = [u for u in data["valid"] if u not in data["gap_users"]][0]

    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against locally spawned fixture servers",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["POST /login", "GET /_stats"],
                  "data": "Synthetic accounts and a synthetic leaked-pair list generated from a fixed seed"},
        "data_summary": {"accounts": len(data["users"]), "leaked_pairs": len(data["pairs"]),
                         "pairs_valid_today": len(data["valid"]),
                         "pairs_unknown_user": sum(1 for u, _ in data["pairs"] if u.startswith("ghost")),
                         "pairs_real_user_old_password": len(data["pairs"]) - len(data["valid"])
                         - sum(1 for u, _ in data["pairs"] if u.startswith("ghost")),
                         "corpus_digests": len(data["corpus"]), "valid_pairs_missing_from_corpus": len(data["gap_users"]),
                         "lockout_after_failures": fixture.LOCKOUT_AFTER,
                         "budget": {"attempts": fixture.BUDGET_LIMIT, "window_seconds": fixture.BUDGET_WINDOW},
                         "seed": fixture.SEED},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or Excession agent ran"},
        "checks": [], "stuffing_runs": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]

    def check(check_id, expected, observed, **extra):
        passed = expected == observed
        evidence["checks"].append(dict(id=check_id, expected=expected, observed=observed, passed=passed, **extra))
        if not passed:
            evidence["failures"].append(check_id)

    def single(server, name, config, username, password, code=None):
        reply = post_login(server, username, password, code)
        (args.output / (name + ".http")).write_text(reply["raw"])
        commands.append(shlex.join(reply["command"]))
        return reply

    def stuffing_run(config):
        mode, controls, order = CONFIGS[config]
        pairs = ordered_pairs(data, order)
        server = Server(mode, controls)
        try:
            commands.append("# Server: python3 fixture.py --mode " + mode
                            + (" --controls " + ",".join(controls) if controls else "") + " --port " + server.port)
            raw_parts, outcomes, started = [], [], now()
            for index, (user, password) in enumerate(pairs, 1):
                reply = post_login(server, user, password)
                commands.append(shlex.join(reply["command"]))
                raw_parts.append("### attempt %d\n%s" % (index, reply["raw"]))
                outcomes.append(reply)
            raw_name = "stuffing-" + config + ".http"
            (args.output / raw_name).write_text("\n".join(raw_parts))
            statuses = {}
            for reply in outcomes:
                key = str(reply["status"])
                statuses[key] = statuses.get(key, 0) + 1
            opened = sum(1 for r in outcomes if r["status"] == 200 and "session" in r["body"])
            confirmed = sum(1 for r in outcomes if r["status"] == 200 or r["body"].get("error") == "second_factor_required")
            stats = get_stats(server)
            observed = {"attempts": len(outcomes), "reached_password_check": len(outcomes) - statuses.get("429", 0),
                        "budget_denials": statuses.get("429", 0), "sessions_opened": opened,
                        "pairs_confirmed": confirmed, "leaked_denials": stats["leaked_denials"]}
            expected = model(data, controls, pairs)
            run = {"config": config, "mode": mode, "controls": controls, "list_order": order, "server": server.info,
                   "started_at": started, "finished_at": now(), "status_counts": statuses,
                   "server_stats": stats, "response_file": raw_name,
                   "response_sha256": digest(args.output / raw_name)}
            evidence["stuffing_runs"].append(run)
            check(config + "/stuffing-run", expected, observed, config=config)
            check(config + "/server-agrees-sessions", expected["sessions_opened"], stats["sessions_issued"], config=config)
            return server, stats
        except Exception:
            server.stop()
            raise

    try:
        # Controls on the vulnerable server.
        server = Server("vulnerable", [])
        try:
            commands.append("# Server: python3 fixture.py --mode vulnerable --port " + server.port)
            reply = single(server, "vulnerable-legit-signin", "vulnerable", legit, data["passwords"][legit])
            check("vulnerable/legit-signin", 200, reply["status"], positive_control=True)
            reply = single(server, "vulnerable-wrong-password", "vulnerable", legit, "not-the-password")
            check("vulnerable/wrong-password", 401, reply["status"], negative_control=True)
            statuses = []
            for n in range(1, fixture.LOCKOUT_AFTER + 2):
                reply = single(server, "vulnerable-lockout-guess-%d" % n, "vulnerable", victim, "wrong-guess-%d" % n)
                statuses.append(reply["status"])
            check("vulnerable/lockout-fires-on-one-account", [401] * fixture.LOCKOUT_AFTER + [423], statuses,
                  note="repeated guesses on ONE account lock it, so the defense works for the case it was built for")
        finally:
            server.stop()

        # Stuffing run against the vulnerable fixture, then the full fix.
        server, stats = stuffing_run("vulnerable")
        server.stop()
        check("vulnerable/lockout-never-fired", {"lockouts": 0, "max_failures_on_one_account": 1},
              {"lockouts": stats["lockouts"], "max_failures_on_one_account": stats["max_failures_on_one_account"]})

        server = Server("fixed", ["budget", "leaked", "mfa"])
        try:
            commands.append("# Server: python3 fixture.py --mode fixed --port " + server.port)
            reply = single(server, "fixed-legit-password-only", "fixed", legit, data["passwords"][legit])
            check("fixed/legit-password-only", [401, "second_factor_required"], [reply["status"], reply["body"].get("error")],
                  positive_control=True)
            code = fixture.totp(data["mfa_secrets"][legit])
            reply = single(server, "fixed-legit-signin", "fixed", legit, data["passwords"][legit], code)
            check("fixed/legit-signin-with-code", 200, reply["status"], positive_control=True)
            reply = single(server, "fixed-legit-wrong-code", "fixed", legit, data["passwords"][legit], "000000")
            check("fixed/legit-wrong-code", [401, "invalid_code"], [reply["status"], reply["body"].get("error")],
                  negative_control=True)
            reply = single(server, "fixed-wrong-password", "fixed", legit, "not-the-password")
            check("fixed/wrong-password", [401, "invalid_credentials"], [reply["status"], reply["body"].get("error")],
                  negative_control=True)
            code = fixture.totp(data["mfa_secrets"][legit_leaked])
            reply = single(server, "fixed-legit-user-with-leaked-password", "fixed", legit_leaked,
                           data["passwords"][legit_leaked], code)
            check("fixed/owner-of-leaked-password-refused", [401, "invalid_credentials"],
                  [reply["status"], reply["body"].get("error")],
                  note="the real owner of a reused, leaked password must reset it before signing in")
        finally:
            server.stop()

        server, stats = stuffing_run("fixed")
        try:
            code = fixture.totp(data["mfa_secrets"][legit])
            reply = single(server, "fixed-legit-after-attack-same-address", "fixed", legit, data["passwords"][legit], code)
            check("fixed/legit-user-same-address-during-attack", 429, reply["status"],
                  note="known cost: the budget is keyed on the address, so a user behind the same address is refused too")
        finally:
            server.stop()

        # The same list with one control at a time (budget off stands in for an attacker using many addresses).
        for config in ("fixed-budget-only", "fixed-budget-only-valid-first", "fixed-leaked-only", "fixed-mfa-only"):
            server, _ = stuffing_run(config)
            server.stop()
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))

    # Self-check of the TOTP code against the RFC 6238 SHA-1 test vector for T = 59 seconds.
    vector = fixture.totp(b"12345678901234567890", at=59, digits=8)
    check("totp/rfc6238-sha1-vector-t59", "94287082", vector)

    evidence["finished_at"] = now()
    evidence["all_checks_passed"] = not evidence["failures"] and len(evidence["checks"]) > 0
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["checks"]), "passed": evidence["all_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
