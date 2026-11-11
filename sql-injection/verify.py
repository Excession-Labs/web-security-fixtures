#!/usr/bin/env python3
"""Run real curl requests against fixture.py in three modes; no external network targets."""
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

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
MODES = ("vulnerable", "bound", "fixed")
ALICE_HASH = hashlib.sha256(b"demo-alice-pw").hexdigest()
PRICE_ORDER = [4, 1, 3, 2]      # ids by ascending price
REVERSED_ORDER = [2, 3, 1, 4]   # ids by descending price


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def login(user, pw):
    return lambda ctx: {"method": "POST", "path": "/login", "json": {"username": user, "password": pw}}


def search(q, sort=None):
    params = [("q", q)] + ([("sort", sort)] if sort is not None else [])
    return lambda ctx: {"method": "GET", "path": "/search", "query": params}


def register(name):
    return lambda ctx: {"method": "POST", "path": "/register", "json": {"username": name}}


def history(ctx):
    return {"method": "GET", "path": "/history", "query": [("id", str(ctx["last_body"]["id"]))]}


def ids(body):
    return [r["id"] for r in body.get("results", [])]


def ok(user):
    return (200, lambda b: b == {"ok": True, "user": user}, "200 login as " + user)


DENIED = (401, lambda b: b == {"error": "invalid_credentials"}, "401 invalid_credentials")
DBERR = (500, lambda b: b == {"error": "database_error"}, "500 database_error")
BADSORT = (400, lambda b: b == {"error": "invalid_sort"}, "400 invalid_sort")
NO_ROWS = (200, lambda b: b == {"results": []}, "200 no rows")
CASES = [
    # (id, description, steps, expected-per-mode)  expected = list per step
    ("login-valid", "alice logs in with the right password", [login("alice", "demo-alice-pw")],
     {m: [ok("alice")] for m in MODES}),
    ("login-wrong-password", "alice with a wrong password", [login("alice", "wrong")],
     {m: [DENIED] for m in MODES}),
    ("login-apostrophe-name", "o'brien logs in with the right password", [login("o'brien", "demo-obrien-pw")],
     {"vulnerable": [DBERR], "bound": [ok("o'brien")], "fixed": [ok("o'brien")]}),
    ("login-bypass", "username alice'-- with a wrong password", [login("alice'--", "wrong")],
     {"vulnerable": [ok("alice")], "bound": [DENIED], "fixed": [DENIED]}),
    ("search-valid", "search for Widget", [search("Widget")],
     {m: [(200, lambda b: ids(b) == [2, 1], "200 two rows")] for m in MODES}),
    ("search-union", "UNION SELECT from the users table through q",
     [search("zzz' UNION SELECT id, username, pw_hash FROM users --")],
     {"vulnerable": [(200, lambda b: {r["name"] for r in b["results"]} == {"alice", "bob", "o'brien"}
                      and {r["price"] for r in b["results"]} >= {ALICE_HASH}, "200 users and hashes returned")],
      "bound": [NO_ROWS], "fixed": [NO_ROWS]}),
    ("sort-valid", "sort by price", [search("", "price")],
     {m: [(200, lambda b: ids(b) == PRICE_ORDER, "200 ids 4,1,3,2")] for m in MODES}),
    ("sort-unknown-column", "sort by a column that does not exist", [search("", "nosuchcolumn")],
     {"vulnerable": [DBERR], "bound": [DBERR], "fixed": [BADSORT]}),
    ("sort-oracle-true", "sort expression true when the first hash character of alice matches",
     [search("", "CASE WHEN (SELECT substr(pw_hash,1,1) FROM users WHERE username='alice')='" + ALICE_HASH[0]
             + "' THEN price ELSE -price END")],
     {"vulnerable": [(200, lambda b: ids(b) == PRICE_ORDER, "200 ids 4,1,3,2")],
      "bound": [(200, lambda b: ids(b) == PRICE_ORDER, "200 ids 4,1,3,2")], "fixed": [BADSORT]}),
    ("sort-oracle-false", "same expression with a wrong character",
     [search("", "CASE WHEN (SELECT substr(pw_hash,1,1) FROM users WHERE username='alice')='"
             + ("0" if ALICE_HASH[0] != "0" else "1") + "' THEN price ELSE -price END")],
     {"vulnerable": [(200, lambda b: ids(b) == REVERSED_ORDER, "200 ids 2,3,1,4")],
      "bound": [(200, lambda b: ids(b) == REVERSED_ORDER, "200 ids 2,3,1,4")], "fixed": [BADSORT]}),
    ("second-order-legit", "register carol, then read her history", [register("carol"), history],
     {m: [(201, lambda b: b["username"] == "carol", "201 registered"),
          (200, lambda b: b == {"orders": ["synthetic order C-1"], "user": "carol"}, "200 one order")] for m in MODES}),
    ("second-order-payload", "register a username holding SQL, then read its history",
     [register("x' OR '1'='1"), history],
     {"vulnerable": [(201, lambda b: b["username"] == "x' OR '1'='1", "201 registered"),
                     (200, lambda b: len(b["orders"]) == 3, "200 all three orders")],
      "bound": [(201, lambda b: b["username"] == "x' OR '1'='1", "201 registered"),
                (200, lambda b: b["orders"] == [], "200 no orders")],
      "fixed": [(201, lambda b: b["username"] == "x' OR '1'='1", "201 registered"),
                (200, lambda b: b["orders"] == [], "200 no orders")]}),
]
# Case ids that must hold in a safe server (policy), used for boundary_holds.
SECURE_EXPECT = {c[0]: c[3]["fixed"] for c in CASES}


def run_curl(base_url, req):
    cmd = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
           "--http1.1", "--connect-timeout", "1", "--max-time", "3"]
    if req["method"] == "GET":
        cmd += ["--request", "GET", "--get"]
        for k, v in req["query"]:
            cmd += ["--data-urlencode", k + "=" + v]
    else:
        cmd += ["--request", "POST", "--header", "Content-Type: application/json",
                "--data", json.dumps(req["json"])]
    cmd.append(base_url + req["path"])
    return cmd


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against three locally spawned fixture modes (in-memory sqlite3)",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET", "POST"],
                  "paths": ["/login", "/search", "/register", "/history"],
                  "data": "Synthetic users, products and orders; demo passwords are public test strings"},
        "versions": {"python": platform.python_version(), "sqlite3": __import__("sqlite3").sqlite_version,
                     "os": platform.system(), "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or agent ran"},
        "cases": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]
    try:
        for mode in MODES:
            server_command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"]
            process = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + startup["base_url"].rsplit(":", 1)[1])
                for case_id, description, steps, expected in CASES:
                    ctx = {}
                    for index, (step, (exp_status, check, exp_text)) in enumerate(zip(steps, expected[mode])):
                        req = step(ctx)
                        command = run_curl(startup["base_url"], req)
                        started, tick = now(), time.monotonic()
                        response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                        status = int(response.stdout.splitlines()[0].split()[1])
                        body = json.loads(response.stdout.split("\n\n", 1)[1])
                        ctx["last_body"] = body
                        passed = response.returncode == 0 and status == exp_status and bool(check(body))
                        secure_status, secure_check, secure_text = SECURE_EXPECT[case_id][index]
                        holds = status == secure_status and bool(secure_check(body))
                        label = case_id + ("" if len(steps) == 1 else "-step" + str(index + 1))
                        raw_name = mode + "-" + label + ".http"
                        (args.output / raw_name).write_text(response.stdout)
                        commands.append("# " + mode + "/" + label + ": " + description)
                        commands.append(shlex.join(command))
                        evidence["cases"].append({
                            "id": mode + "/" + label, "description": description, "started_at": started,
                            "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                            "server": startup, "command": command, "curl_exit_code": response.returncode,
                            "stderr": response.stderr, "request": {k: v for k, v in req.items()},
                            "secure_expected": secure_text, "demonstration_expected": exp_text,
                            "observed_status": status, "observed_body": body,
                            "matches_demonstration": passed, "secure_boundary_holds": holds,
                            "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                        })
                        if not passed:
                            evidence["failures"].append(mode + "/" + label)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    evidence["finished_at"] = now()
    total = len(evidence["cases"])
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and total == 42
    evidence["secure_boundary_failures"] = [c["id"] for c in evidence["cases"] if not c["secure_boundary_holds"]]
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": total, "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
