#!/usr/bin/env python3
"""Run real curl requests (role x route x method matrix) against fixture.py; no external targets."""
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

# identity label -> (bearer token or None, extra header or None)
IDENTITIES = {
    "anonymous": (None, None),
    "user": ("demo-user-token", None),
    "user-forged-role": ("demo-user-token", "X-Role: admin"),
    "admin": ("demo-admin-token", None),
}
# (route label, method, path for each identity, secure status per identity, vulnerable status per identity)
# Order of identities: anonymous, user, user-forged-role, admin.
ROUTES = [
    ("me", "GET", ["/api/me"] * 4, [401, 200, 200, 200], [401, 200, 200, 200]),
    ("admin-users", "GET", ["/api/admin/users"] * 4, [401, 403, 403, 200], [401, 200, 200, 200]),
    ("admin-audit-log", "GET", ["/api/admin/audit-log"] * 4, [401, 403, 403, 200], [401, 403, 200, 200]),
    ("admin-account-get", "GET", ["/api/admin/accounts/acct-7"] * 4, [401, 403, 403, 200], [401, 403, 403, 200]),
    ("admin-account-delete", "DELETE",
     ["/api/admin/accounts/acct-7", "/api/admin/accounts/acct-8",
      "/api/admin/accounts/acct-9", "/api/admin/accounts/acct-10"],
     [401, 403, 403, 204], [401, 204, 204, 204]),
]
SUCCESS_KEY = {"me": "role", "admin-users": "accounts", "admin-audit-log": "events",
               "admin-account-get": "email"}


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
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET", "DELETE"],
                  "paths": ["/api/me", "/api/admin/users", "/api/admin/audit-log",
                            "/api/admin/accounts/{id}", "/api/admin/debug"],
                  "data": "Two synthetic sessions and four synthetic accounts; all tokens are public demo values"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or Excession agent ran"},
        "cases": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]
    # Flat case list: (name, identity, method, path, secure, vulnerable, success_key)
    cases = []
    for label, method, paths, secure, vulnerable in ROUTES:
        for i, identity in enumerate(IDENTITIES):
            cases.append((label + "/" + identity, identity, method, paths[i], secure[i], vulnerable[i],
                          SUCCESS_KEY.get(label)))
    # Impact check: did the user's DELETE really remove acct-8? Secure: still there (200).
    cases.append(("state-check/admin-reads-acct-8", "admin", "GET", "/api/admin/accounts/acct-8", 200, 404, "email"))
    # Deny by default: a route with no policy entry is denied even to the admin in fixed mode.
    cases.append(("unlisted-route/admin", "admin", "GET", "/api/admin/debug", 403, 200, "debug"))
    cases.append(("unlisted-route/user", "user", "GET", "/api/admin/debug", 403, 200, "debug"))
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
                for name, identity, method, path, secure_status, vulnerable_status, key in cases:
                    token, extra = IDENTITIES[identity]
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", method]
                    if token:
                        command += ["--header", "Authorization: Bearer " + token]
                    if extra:
                        command += ["--header", extra]
                    command.append(startup["base_url"] + path)
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status = int(response.stdout.splitlines()[0].split()[1])
                    raw_body = response.stdout.split("\n\n", 1)[1]
                    body = json.loads(raw_body) if raw_body.strip() else None
                    expected_demo = vulnerable_status if mode == "vulnerable" else secure_status
                    if expected_demo == 401:
                        body_ok = body == {"error": "authentication_required"}
                    elif expected_demo in (403, 404):
                        body_ok = body in ({"error": "forbidden"}, {"error": "not_found"})
                    elif expected_demo == 204:
                        body_ok = body is None
                    else:
                        body_ok = isinstance(body, dict) and key in body
                    passed = response.returncode == 0 and status == expected_demo and body_ok
                    raw_name = mode + "-" + name.replace("/", "-") + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    evidence["cases"].append({
                        "id": mode + "/" + name, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "identity": identity, "method": method, "path": path,
                        "secure_expected_status": secure_status,
                        "demonstration_expected_status": expected_demo, "observed_status": status,
                        "observed_body": body, "matches_demonstration": passed,
                        "authorization_boundary_holds": status == secure_status,
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
    expected_count = 2 * len(cases)
    evidence["boundary_failures_vulnerable"] = [c["id"] for c in evidence["cases"]
                                                if c["id"].startswith("vulnerable/") and not c["authorization_boundary_holds"]]
    evidence["boundary_failures_fixed"] = [c["id"] for c in evidence["cases"]
                                           if c["id"].startswith("fixed/") and not c["authorization_boundary_holds"]]
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == expected_count
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "boundary_failures_vulnerable": len(evidence["boundary_failures_vulnerable"]),
                      "boundary_failures_fixed": len(evidence["boundary_failures_fixed"]),
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
