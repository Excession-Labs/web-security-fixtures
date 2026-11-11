#!/usr/bin/env python3
"""Run real curl requests against fixture.py in both modes; no external network targets."""
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
GOOD = {"alice": "demo-passphrase-alice", "bob": "demo-passphrase-bob"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan():
    """Scenarios: (name, mode, [(label, user, password, forwarded_for, expected_status)])."""
    wrong = ["wrong-guess-%02d" % n for n in range(1, 20)]
    same = [("try-%02d" % (i + 1), "alice", wrong[i], "203.0.113.7", 401 if i < 5 else 429)
            for i in range(6)]
    rot_v = [("try-%02d" % (i + 1), "alice", wrong[i], "198.51.100.%d" % (i + 1), 401) for i in range(19)]
    rot_v.append(("try-20", "alice", GOOD["alice"], "198.51.100.20", 200))
    rot_f = [("try-%02d" % (i + 1), "alice", wrong[i] if i < 19 else GOOD["alice"],
              "198.51.100.%d" % (i + 1), 401 if i < 5 else 429) for i in range(20)]
    return [
        ("same-header", "vulnerable", same),
        ("rotating-header", "vulnerable", rot_v),
        ("same-header", "fixed", same),
        ("rotating-header", "fixed", rot_f + [("bob-correct-after", "bob", GOOD["bob"], None, 200)]),
        ("controls", "fixed", [("alice-correct", "alice", GOOD["alice"], None, 200),
                               ("alice-wrong", "alice", "wrong-guess-01", None, 401),
                               ("bob-correct", "bob", GOOD["bob"], None, 200)]),
    ]


def parse(text):
    head, _, body = text.replace("\r\n", "\n").partition("\n\n")
    lines = head.splitlines()
    headers = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    return int(lines[0].split()[1]), headers, json.loads(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against locally spawned fixture servers, one fresh server per scenario",
        "limiter": {"limit": 5, "window_seconds": 60},
        "scope": {"hosts": ["127.0.0.1"], "methods": ["POST"], "paths": ["/login"],
                  "data": "Two synthetic accounts; all passwords are public demo values; X-Forwarded-For values are TEST-NET documentation addresses"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or agent ran"},
        "cases": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]
    try:
        for scenario, mode, steps in plan():
            process = subprocess.Popen([sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + startup["base_url"].rsplit(":", 1)[1])
                for label, user, password, forwarded, expected in steps:
                    payload = json.dumps({"username": user, "password": password})
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", "POST",
                               "--header", "Content-Type: application/json", "--data", payload]
                    if forwarded:
                        command += ["--header", "X-Forwarded-For: " + forwarded]
                    command.append(startup["base_url"] + "/login")
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status, headers, body = parse(response.stdout)
                    raw_name = "%s-%s-%s.http" % (mode, scenario, label)
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    passed = response.returncode == 0 and status == expected
                    if mode == "fixed" and status == 429:
                        passed = passed and headers.get("retry-after", "").isdigit()
                    if mode == "vulnerable" and status == 429:
                        passed = passed and "retry-after" not in headers
                    if status == 200:
                        passed = passed and body == {"status": "ok", "user": user}
                    evidence["cases"].append({
                        "id": mode + "/" + scenario + "/" + label, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "username": user, "x_forwarded_for": forwarded,
                        "expected_status": expected, "observed_status": status,
                        "retry_after": headers.get("retry-after"), "observed_body": body,
                        "matches_expectation": passed,
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    })
                    if not passed:
                        evidence["failures"].append(mode + "/" + scenario + "/" + label)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    total = sum(len(s) for _, _, s in plan())
    evidence["finished_at"] = now()
    evidence["all_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == total
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
