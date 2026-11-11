#!/usr/bin/env python3
"""Run twenty real curl requests against fixture.py; no external network targets."""
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
HASH = "demo-hash-not-a-real-hash-alice"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def has(body, **expected):
    return all(body.get(key) == value for key, value in expected.items())


# Each case: name, method, path, token, payload,
#   (vulnerable status, vulnerable check, vulnerable description),
#   (secure status, secure check, secure description).
CASES = [
    ("alice-get-before", "GET", "/profile", "demo-alice-token", None,
     (200, lambda b: has(b, role="user", credit=0, password_hash=HASH), "200, record includes password_hash"),
     (200, lambda b: has(b, role="user", credit=0) and "password_hash" not in b, "200, no password_hash")),
    ("alice-legit-update", "PATCH", "/profile", "demo-alice-token", {"name": "Alice Example", "bio": "Synthetic bio"},
     (200, lambda b: has(b, name="Alice Example", bio="Synthetic bio", role="user", credit=0), "200, name and bio updated"),
     (200, lambda b: has(b, name="Alice Example", bio="Synthetic bio", role="user", credit=0) and "password_hash" not in b,
      "200, name and bio updated, no password_hash")),
    ("alice-mass-assign", "PATCH", "/profile", "demo-alice-token", {"role": "admin", "credit": 9999},
     (200, lambda b: has(b, role="admin", credit=9999), "200, role admin and credit 9999 applied"),
     (400, lambda b: has(b, error="fields_not_writable", fields=["credit", "role"]), "400, fields rejected")),
    ("alice-get-after", "GET", "/profile", "demo-alice-token", None,
     (200, lambda b: has(b, role="admin", credit=9999), "200, escalation persisted"),
     (200, lambda b: has(b, name="Alice Example", role="user", credit=0), "200, role user and credit 0 unchanged")),
    ("alice-unknown-field", "PATCH", "/profile", "demo-alice-token", {"is_admin": True},
     (200, lambda b: has(b, is_admin=True), "200, unknown field stored"),
     (400, lambda b: has(b, error="fields_not_writable", fields=["is_admin"]), "400, unknown field rejected")),
    ("alice-mixed", "PATCH", "/profile", "demo-alice-token", {"bio": "Mixed attempt", "role": "admin"},
     (200, lambda b: has(b, bio="Mixed attempt"), "200, whole payload applied"),
     (400, lambda b: has(b, error="fields_not_writable", fields=["role"]), "400, whole request rejected")),
    ("alice-uses-role", "PATCH", "/users/bob", "demo-alice-token", {"credit": 1},
     (200, lambda b: has(b, id="bob", credit=1), "200, escalated role edits another user"),
     (403, lambda b: has(b, error="forbidden"), "403, admin endpoint denied")),
    ("admin-sets-credit", "PATCH", "/users/alice", "demo-admin-token", {"credit": 50},
     (200, lambda b: has(b, id="alice", credit=50), "200, credit 50"),
     (200, lambda b: has(b, id="alice", credit=50) and "password_hash" not in b, "200, credit 50, no password_hash")),
    ("alice-get-final", "GET", "/profile", "demo-alice-token", None,
     (200, lambda b: has(b, role="admin", credit=50, bio="Mixed attempt", is_admin=True),
      "200, role admin, bio and is_admin from attacker input"),
     (200, lambda b: has(b, name="Alice Example", bio="Synthetic bio", role="user", credit=50)
      and "password_hash" not in b and "is_admin" not in b, "200, legitimate edits kept, nothing else changed")),
    ("anonymous-patch", "PATCH", "/profile", None, {"bio": "x"},
     (401, lambda b: has(b, error="authentication_required"), "401"),
     (401, lambda b: has(b, error="authentication_required"), "401")),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against two locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET", "PATCH"], "paths": ["/profile", "/users/<id>"],
                  "data": "Three synthetic users; all tokens and the password_hash values are public demo strings"},
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
        for mode in ("vulnerable", "fixed"):
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
                for name, method, path, token, payload, vulnerable, secure in CASES:
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", method]
                    if token:
                        command += ["--header", "Authorization: Bearer " + token]
                    if payload is not None:
                        command += ["--header", "Content-Type: application/json",
                                    "--data", json.dumps(payload, separators=(",", ":"))]
                    command.append(startup["base_url"] + path)
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status = int(response.stdout.splitlines()[0].split()[1])
                    body = json.loads(response.stdout.split("\n\n", 1)[1])
                    expected_status, expected_check, expected_text = vulnerable if mode == "vulnerable" else secure
                    secure_status, secure_check, secure_text = secure
                    passed = (response.returncode == 0 and status == expected_status and expected_check(body))
                    boundary = status == secure_status and secure_check(body)
                    raw_name = mode + "-" + name + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    evidence["cases"].append({
                        "id": mode + "/" + name, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "method": method, "path": path,
                        "identity": token.removeprefix("demo-").removesuffix("-token") if token else None,
                        "request_body": payload,
                        "secure_expected": secure_text, "demonstration_expected": expected_text,
                        "observed_status": status, "observed_body": body,
                        "matches_demonstration": passed, "secure_policy_holds": boundary,
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    })
                    if not passed:
                        evidence["failures"].append(mode + "/" + name)
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
    evidence["policy_violations_in_vulnerable_mode"] = sorted(
        c["id"] for c in evidence["cases"] if c["id"].startswith("vulnerable/") and not c["secure_policy_holds"])
    evidence["policy_violations_in_fixed_mode"] = sorted(
        c["id"] for c in evidence["cases"] if c["id"].startswith("fixed/") and not c["secure_policy_holds"])
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 20
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
