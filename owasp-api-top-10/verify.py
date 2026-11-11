#!/usr/bin/env python3
"""Run a 12-request API security checklist with curl against fixture.py in both modes.

Each case states the SECURE expectation. A vulnerable server is expected to fail
some cases; the fixed server is expected to pass all. Adapt CASES for your own API.
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

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
A, B, C, ADM = "demo-alice-token", "demo-bob-token", "demo-carol-token", "demo-admin-token"

# (id, risk, token, method, path, json body, secure status, secure body check description, check)
CASES = [
    ("alice-reads-own-note", "API1 control", A, "GET", "/notes/alice-note", None, 200,
     "body names alice-note", lambda b: b.get("id") == "alice-note"),
    ("bob-reads-alice-note", "API1", B, "GET", "/notes/alice-note", None, 403,
     "body has no note text", lambda b: "text" not in b),
    ("anonymous-reads-note", "API1 control", None, "GET", "/notes/alice-note", None, 401,
     "body has no note text", lambda b: "text" not in b),
    ("bob-edits-display-name", "API3 control", B, "PATCH", "/profile", {"display_name": "Bobby"}, 200,
     "display_name is Bobby", lambda b: b.get("display_name") == "Bobby"),
    ("bob-sets-own-role", "API3", B, "PATCH", "/profile", {"role": "admin"}, 400,
     "role is not changed to admin", lambda b: b.get("role") != "admin"),
    ("bob-reads-own-profile", "API3", B, "GET", "/profile", None, 200,
     "role is still user", lambda b: b.get("role") == "user"),
    ("carol-lists-admin-users", "API5", C, "GET", "/admin/users", None, 403,
     "body has no user list", lambda b: "users" not in b),
    ("admin-lists-admin-users", "API5 control", ADM, "GET", "/admin/users", None, 200,
     "body lists 4 users", lambda b: len(b.get("users", [])) == 4),
    ("anonymous-lists-admin-users", "API5 control", None, "GET", "/admin/users", None, 401,
     "body has no user list", lambda b: "users" not in b),
    ("alice-search-limit-50", "API4 control", A, "GET", "/search?limit=50", None, 200,
     "50 rows returned", lambda b: b.get("count") == 50),
    ("alice-search-limit-100000", "API4", A, "GET", "/search?limit=100000", None, 400,
     "fewer than 51 rows returned", lambda b: b.get("count", 0) <= 50),
    ("alice-search-bad-limit", "API4 control", A, "GET", "/search?limit=abc", None, 400,
     "body is invalid_limit", lambda b: b.get("error") == "invalid_limit"),
]
EXPECTED_VULNERABLE_FAILS = {"bob-reads-alice-note", "bob-sets-own-role", "bob-reads-own-profile",
                             "carol-lists-admin-users", "alice-search-limit-100000"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against two locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "data": "Synthetic identities, notes and rows; demo tokens only"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model ran"},
        "cases": [], "failures": [], "summary": {},
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]
    table = {}
    try:
        for mode in ("vulnerable", "fixed"):
            proc = subprocess.Popen([sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([proc.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(proc.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + startup["base_url"].rsplit(":", 1)[1])
                for cid, risk, token, method, path, body, want, desc, check in CASES:
                    cmd = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
                           "--connect-timeout", "1", "--max-time", "3", "--request", method]
                    if token:
                        cmd += ["--header", "Authorization: Bearer " + token]
                    if body is not None:
                        cmd += ["--header", "Content-Type: application/json", "--data", json.dumps(body)]
                    cmd.append(startup["base_url"] + path)
                    resp = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                    status = int(resp.stdout.splitlines()[0].split()[1])
                    parsed = json.loads(resp.stdout.split("\n\n", 1)[1])
                    secure = resp.returncode == 0 and status == want and bool(check(parsed))
                    raw = mode + "-" + cid + ".http"
                    (args.output / raw).write_text(resp.stdout)
                    commands.append(shlex.join(cmd))
                    table[(cid, mode)] = (status, secure)
                    evidence["cases"].append({
                        "id": mode + "/" + cid, "risk": risk, "command": cmd, "curl_exit_code": resp.returncode,
                        "secure_expected_status": want, "secure_body_check": desc,
                        "observed_status": status, "passes_secure_expectation": secure,
                        "response_file": raw, "response_sha256": digest(args.output / raw)})
                    failed = not secure
                    expected_fail = mode == "vulnerable" and cid in EXPECTED_VULNERABLE_FAILS
                    if failed != expected_fail:
                        evidence["failures"].append(mode + "/" + cid)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    lines = ["| Case | Risk | Secure status | Vulnerable | Fixed |", "|---|---|---|---|---|"]
    for cid, risk, _t, method, path, _b, want, _d, _c in CASES:
        row = [cid, risk, str(want)]
        for mode in ("vulnerable", "fixed"):
            status, ok = table.get((cid, mode), ("?", False))
            row.append(str(status) + (" PASS" if ok else " FAIL"))
        lines.append("| " + " | ".join(row) + " |")
    (args.output / "table.md").write_text("\n".join(lines) + "\n")
    count = lambda mode, val: sum(1 for (c, m), (s, ok) in table.items() if m == mode and ok == val)
    evidence["summary"] = {"vulnerable_pass": count("vulnerable", True), "vulnerable_fail": count("vulnerable", False),
                           "fixed_pass": count("fixed", True), "fixed_fail": count("fixed", False)}
    evidence["finished_at"] = now()
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 2 * len(CASES)
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print("\n".join(lines))
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "summary": evidence["summary"], "failures": evidence["failures"]}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
