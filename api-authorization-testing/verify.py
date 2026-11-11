#!/usr/bin/env python3
"""Run eight real curl requests against fixture.py; no external network targets."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shlex
import subprocess
import sys
import time

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent


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
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET"],
                  "paths": ["/objects/alice-note", "/objects/bob-note"],
                  "data": "Two synthetic identities and notes; all tokens below are public demo values"},
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
    cases = [
        ("alice-own", "demo-alice-token", "/objects/alice-note", 200),
        ("bob-own", "demo-bob-token", "/objects/bob-note", 200),
        ("bob-reads-alice", "demo-bob-token", "/objects/alice-note", 403),
        ("unauthenticated", None, "/objects/alice-note", 401),
    ]
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
                for name, token, path, secure_status in cases:
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", "GET"]
                    if token:
                        command += ["--header", "Authorization: Bearer " + token]
                    command.append(startup["base_url"] + path)
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status = int(response.stdout.splitlines()[0].split()[1])
                    body = json.loads(response.stdout.split("\n\n", 1)[1])
                    expected_demo = 200 if mode == "vulnerable" and name == "bob-reads-alice" else secure_status
                    expected_body = ({"id": "bob-note", "owner": "bob", "text": "Bob synthetic note"}
                                     if name == "bob-own" else
                                     {"id": "alice-note", "owner": "alice", "text": "Alice synthetic note"})
                    if expected_demo == 403:
                        expected_body = {"error": "forbidden"}
                    elif expected_demo == 401:
                        expected_body = {"error": "authentication_required"}
                    passed = response.returncode == 0 and status == expected_demo and body == expected_body
                    raw_name = mode + "-" + name + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    evidence["cases"].append({
                        "id": mode + "/" + name, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "identity": token.removeprefix("demo-").removesuffix("-token") if token else None,
                        "path": path, "secure_expected_status": secure_status,
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
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 8
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
