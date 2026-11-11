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
from urllib.parse import urlsplit

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
CANONICAL_HOST = "app.example.test"
ATTACKER_HOST = "attacker.evil"
VICTIM_EMAIL = "victim@example.test"
UNKNOWN_EMAIL = "nobody@example.test"
VICTIM_TOKEN = "a93fd21c7e4b4f0f9d3b6c8a1e2f5d7c"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def link_host(link):
    return urlsplit(link).netloc if link else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against two locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["POST"], "paths": ["/reset-password"],
                  "data": "One synthetic account with a fixed demo reset token; all values below are public demo data"},
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

    # Each case: id, email, Host header value, X-Forwarded-Host value or None,
    # then the expected behaviour for each mode.
    cases = [
        {
            "id": "legit", "email": VICTIM_EMAIL, "host": CANONICAL_HOST, "xfh": None,
            "vulnerable": {"status": 202, "outbox_added": True, "link_host": CANONICAL_HOST},
            "fixed": {"status": 202, "outbox_added": True, "link_host": CANONICAL_HOST},
        },
        {
            "id": "forged-host", "email": VICTIM_EMAIL, "host": ATTACKER_HOST, "xfh": None,
            "vulnerable": {"status": 202, "outbox_added": True, "link_host": ATTACKER_HOST},
            "fixed": {"status": 400, "outbox_added": False, "link_host": None},
        },
        {
            "id": "forged-xfh", "email": VICTIM_EMAIL, "host": CANONICAL_HOST, "xfh": ATTACKER_HOST,
            "vulnerable": {"status": 202, "outbox_added": True, "link_host": ATTACKER_HOST},
            "fixed": {"status": 202, "outbox_added": True, "link_host": CANONICAL_HOST},
        },
        {
            "id": "unknown-email", "email": UNKNOWN_EMAIL, "host": CANONICAL_HOST, "xfh": None,
            "vulnerable": {"status": 202, "outbox_added": False, "link_host": None},
            "fixed": {"status": 202, "outbox_added": False, "link_host": None},
        },
    ]

    try:
        for mode in ("vulnerable", "fixed"):
            outbox_path = args.output / (mode + "-outbox.jsonl")
            outbox_path.write_text("")
            server_command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode,
                               "--port", "0", "--outbox", str(outbox_path)]
            process = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port "
                                 + startup["base_url"].rsplit(":", 1)[1] + " --outbox " + mode + "-outbox.jsonl")
                for case in cases:
                    expected = case[mode]
                    before_lines = outbox_path.read_text().splitlines()
                    body = json.dumps({"email": case["email"]}).encode()
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", "POST",
                               "--header", "Content-Type: application/json",
                               "--header", "Host: " + case["host"]]
                    if case["xfh"]:
                        command += ["--header", "X-Forwarded-Host: " + case["xfh"]]
                    command += ["--data-binary", body.decode(), startup["base_url"] + "/reset-password"]
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status = int(response.stdout.splitlines()[0].split()[1])
                    response_body = json.loads(response.stdout.split("\n\n", 1)[1])
                    after_lines = outbox_path.read_text().splitlines()
                    added = after_lines[len(before_lines):]
                    observed_link = None
                    if added:
                        observed_link = json.loads(added[-1])["body"].rsplit(": ", 1)[1]
                    observed_link_host = link_host(observed_link)
                    passed = (response.returncode == 0
                              and status == expected["status"]
                              and bool(added) == expected["outbox_added"]
                              and observed_link_host == expected["link_host"])
                    raw_name = mode + "-" + case["id"] + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    evidence["cases"].append({
                        "id": mode + "/" + case["id"], "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "request_host_header": case["host"],
                        "request_x_forwarded_host": case["xfh"], "email": case["email"],
                        "demonstration_expected_status": expected["status"], "observed_status": status,
                        "observed_body": response_body,
                        "expected_outbox_entry_added": expected["outbox_added"], "observed_outbox_entry_added": bool(added),
                        "expected_link_host": expected["link_host"], "observed_link_host": observed_link_host,
                        "observed_link": observed_link,
                        "token_in_link": (VICTIM_TOKEN in observed_link) if observed_link else False,
                        "matches_demonstration": passed,
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    })
                    if not passed:
                        evidence["failures"].append(mode + "/" + case["id"])
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
