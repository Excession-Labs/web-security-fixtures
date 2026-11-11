#!/usr/bin/env python3
"""Run 38 real curl requests (19 per mode) against fixture.py; no external network targets."""
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
TOKENS = {"alice": "demo-acme-alice", "amy": "demo-acme-amy", "bob": "demo-globex-bob", "bea": "demo-globex-bea"}
TENANT = {"alice": "acme", "amy": "acme", "bob": "globex", "bea": "globex", None: None}
LIST = "/invoices?q=inv&tenant_id="


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cases():
    """(id, endpoint, who, method, path, vulnerable_expect, fixed_expect, role)
    An expectation is (status, sorted tenants in the body, X-Cache value or None).
    role: attack (asks for the other tenant's data), control (legitimate use)."""
    A, G = ["acme"], ["globex"]
    return [
        ("list-alice-own", "list", "alice", "GET", LIST + "acme", (200, A, None), (200, A, None), "control"),
        ("list-bob-own", "list", "bob", "GET", LIST + "globex", (200, G, None), (200, G, None), "control"),
        ("list-alice-asks-globex", "list", "alice", "GET", LIST + "globex", (200, G, None), (200, A, None), "attack"),
        ("list-bob-asks-acme", "list", "bob", "GET", LIST + "acme", (200, A, None), (200, G, None), "attack"),
        ("list-anonymous", "list", None, "GET", LIST + "acme", (401, [], None), (401, [], None), "control"),
        ("cache-alice-fills-0901", "cache", "alice", "GET", "/reports/usage?period=2026-09", (200, A, "MISS"), (200, A, "MISS"), "control"),
        ("cache-bob-reads-0901", "cache", "bob", "GET", "/reports/usage?period=2026-09", (200, A, "HIT"), (200, G, "MISS"), "attack"),
        ("cache-bob-fills-1001", "cache", "bob", "GET", "/reports/usage?period=2026-10", (200, G, "MISS"), (200, G, "MISS"), "control"),
        ("cache-alice-reads-1001", "cache", "alice", "GET", "/reports/usage?period=2026-10", (200, G, "HIT"), (200, A, "MISS"), "attack"),
        ("cache-alice-repeats-0901", "cache", "alice", "GET", "/reports/usage?period=2026-09", (200, A, "HIT"), (200, A, "HIT"), "control"),
        ("cache-anonymous", "cache", None, "GET", "/reports/usage?period=2026-09", (401, [], None), (401, [], None), "control"),
        ("export-alice-creates", "export", "alice", "POST", "/exports", (201, A, None), (201, A, None), "control"),
        ("export-bob-creates", "export", "bob", "POST", "/exports", (201, G, None), (201, G, None), "control"),
        ("export-bob-fetches-alice-job", "export", "bob", "GET", "{alice_job}", (200, A, None), (404, [], None), "attack"),
        ("export-alice-fetches-bob-job", "export", "alice", "GET", "{bob_job}", (200, G, None), (404, [], None), "attack"),
        ("export-alice-fetches-own-job", "export", "alice", "GET", "{alice_job}", (200, A, None), (200, A, None), "control"),
        ("export-amy-fetches-alice-job", "export", "amy", "GET", "{alice_job}", (200, A, None), (200, A, None), "control"),
        ("export-unknown-job", "export", "alice", "GET", "/exports/exp-9999", (404, [], None), (404, [], None), "control"),
        ("export-anonymous", "export", None, "GET", "{alice_job}", (401, [], None), (401, [], None), "control"),
    ]


def tenants_in(value, found):
    if isinstance(value, dict):
        if "tenant" in value:
            found.add(value["tenant"])
        for item in value.values():
            tenants_in(item, found)
    elif isinstance(value, list):
        for item in value:
            tenants_in(item, found)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against two locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET", "POST"],
                  "paths": ["/invoices", "/reports/usage", "/exports", "/exports/<job_id>"],
                  "data": "Two synthetic tenants, two users each; all tokens are public demo values"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or agent ran"},
        "cases": [], "failures": [], "matrix": {},
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]
    try:
        for mode in ("vulnerable", "fixed"):
            command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            jobs = {}
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + startup["base_url"].rsplit(":", 1)[1])
                for name, endpoint, who, method, path, vuln, fixed, role in cases():
                    path = path.format(**{k: "/exports/" + v for k, v in jobs.items()})
                    expected_status, expected_tenants, expected_cache = vuln if mode == "vulnerable" else fixed
                    curl = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                            "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", method]
                    if who:
                        curl += ["--header", "Authorization: Bearer " + TOKENS[who]]
                    if method == "POST":
                        curl += ["--header", "Content-Type: application/json", "--data", "{}"]
                    curl.append(startup["base_url"] + path)
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(curl, capture_output=True, text=True, timeout=5)
                    head, body_text = response.stdout.split("\n\n", 1)
                    lines = head.splitlines()
                    status = int(lines[0].split()[1])
                    headers = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
                    body = json.loads(body_text)
                    seen = sorted(tenants_in(body, set()))
                    cache = headers.get("x-cache")
                    if name == "export-alice-creates":
                        jobs["alice_job"] = body["job_id"]
                    if name == "export-bob-creates":
                        jobs["bob_job"] = body["job_id"]
                    own = [TENANT[who]] if who else []
                    leaked = bool([t for t in seen if t not in own])
                    # Secure behaviour: no other tenant's data in the body and no cross-tenant 200.
                    boundary_holds = not leaked
                    passed = (response.returncode == 0 and status == expected_status
                              and seen == expected_tenants and cache == expected_cache)
                    raw_name = mode + "-" + name + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(curl))
                    evidence["cases"].append({
                        "id": mode + "/" + name, "endpoint": endpoint, "role": role,
                        "started_at": started, "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": curl, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "identity": who, "identity_tenant": TENANT[who],
                        "path": path, "expected": {"status": expected_status, "tenants_in_body": expected_tenants, "x_cache": expected_cache},
                        "observed": {"status": status, "tenants_in_body": seen, "x_cache": cache},
                        "cross_tenant_data_returned": leaked, "authorization_boundary_holds": boundary_holds,
                        "matches_demonstration": passed, "observed_body": body,
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    })
                    if role == "attack":
                        who_t = TENANT[who]
                        evidence["matrix"].setdefault(mode, {}).setdefault(who_t, {})[endpoint] = {
                            "status": status, "cross_tenant_data_returned": leaked}
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
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 38
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
