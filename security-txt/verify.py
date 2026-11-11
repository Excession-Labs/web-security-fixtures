#!/usr/bin/env python3
"""Run check.py against a broken and a corrected local security.txt site; no external targets."""
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
EXAMPLE_NOW = "2026-11-10T00:00:00Z"

# (mode, case id, site prefix, expected ERROR rules). An empty list means check.py must pass.
SITE_CASES = [
    ("broken", "wrong-path", "", ["http-status"]),
    ("broken", "missing-expires", "/noexpires", ["expires-required"]),
    ("broken", "expired-date", "/expired", ["expires-stale"]),
    ("broken", "http-contact", "/httpcontact", ["https-only"]),
    ("broken", "html-content-type", "/html", ["content-type"]),
    ("fixed", "corrected-file", "", []),
    ("fixed", "control-minimal-file", "/minimal", []),
    ("fixed", "control-signed-structure", "/signed", []),
]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_check(args, output, name, commands):
    command = [sys.executable, "check.py"] + args
    text = subprocess.run(command, capture_output=True, text=True, timeout=15, cwd=ROOT)
    data = subprocess.run(command + ["--json"], capture_output=True, text=True, timeout=15, cwd=ROOT)
    (output / (name + ".txt")).write_text(text.stdout)
    (output / (name + ".json")).write_text(data.stdout)
    commands.append("python3 check.py " + shlex.join(args))
    findings = json.loads(data.stdout)["findings"]
    return text.returncode, [f["rule"] for f in findings if f["level"] == "ERROR"], name + ".txt"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "check.py run as a subprocess against two locally spawned fixture modes and one example file",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET"], "data": "Synthetic files; every address uses example.com"},
        "versions": {"python": platform.python_version(), "os": platform.system(), "architecture": platform.machine()},
        "sha256": {n: digest(ROOT / n) for n in ("fixture.py", "verify.py", "check.py", "security.txt.example")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "Scripted verification; no model or agent ran"},
        "cases": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded check.py commands; rerun verify.py to start fresh fixture servers.",
                "# The ports refer to the recorded run and are no longer listening."]
    try:
        for mode in ("broken", "fixed"):
            proc = subprocess.Popen([sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                if not select.select([proc.stdout], [], [], 5)[0]:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(proc.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + startup["base_url"].rsplit(":", 1)[1])
                for case_mode, case_id, prefix, expected in SITE_CASES:
                    if case_mode != mode:
                        continue
                    argv = ["--site", startup["base_url"] + prefix, "--allow-insecure-local"]
                    code, errors, raw = run_check(argv, args.output, mode + "-" + case_id, commands)
                    passed = errors == expected and code == (1 if expected else 0)
                    evidence["cases"].append({"id": mode + "/" + case_id, "server": startup, "site_prefix": prefix or "/",
                                              "expected_error_rules": expected, "observed_error_rules": errors,
                                              "check_exit_code": code, "matches_expectation": passed,
                                              "output_file": raw, "output_sha256": digest(args.output / raw)})
                    if not passed:
                        evidence["failures"].append(mode + "/" + case_id)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        argv = ["security.txt.example", "--now", EXAMPLE_NOW]
        code, errors, raw = run_check(argv, args.output, "example-file", commands)
        passed = errors == [] and code == 0
        evidence["cases"].append({"id": "example/copy-paste-file", "note": "Expires compared with a pinned clock " + EXAMPLE_NOW + " so a rerun stays valid after the example expires",
                                  "expected_error_rules": [], "observed_error_rules": errors, "check_exit_code": code,
                                  "matches_expectation": passed, "output_file": raw, "output_sha256": digest(args.output / raw)})
        if not passed:
            evidence["failures"].append("example/copy-paste-file")
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    evidence["finished_at"] = now()
    evidence["all_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == len(SITE_CASES) + 1
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
