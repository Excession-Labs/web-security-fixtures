#!/usr/bin/env python3
"""Run 24 real curl requests against fixture.py in three modes; loopback only."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import os
import platform
import select
import shlex
import subprocess
import sys
import time
from urllib.parse import quote

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
SECRET_MARKER = "SYNTHETIC-SECRET-0001"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# case id, URL suffix after /files/ (None = built from the secret path), expected (status, leaks) per mode
def build_cases(secret_path):
    absolute = quote(secret_path, safe="")
    return [
        ("legit-file", "report.txt", {"vulnerable": (200, False), "naive": (200, False), "fixed": (200, False)}),
        ("legit-subdir", "docs/guide.txt", {"vulnerable": (200, False), "naive": (200, False), "fixed": (200, False)}),
        ("missing-file", "nope.txt", {"vulnerable": (404, False), "naive": (404, False), "fixed": (404, False)}),
        ("dotdot", "../secret.txt", {"vulnerable": (200, True), "naive": (404, False), "fixed": (403, False)}),
        ("encoded-dotdot", "..%2fsecret.txt", {"vulnerable": (200, True), "naive": (404, False), "fixed": (403, False)}),
        ("absolute-path", absolute, {"vulnerable": (200, True), "naive": (200, True), "fixed": (403, False)}),
        ("nested-dotdot", "....//secret.txt", {"vulnerable": (404, False), "naive": (200, True), "fixed": (404, False)}),
        ("double-encoded", "%252e%252e%252fsecret.txt", {"vulnerable": (404, False), "naive": (404, False), "fixed": (404, False)}),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses (--path-as-is) against three locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET"], "path_prefix": "/files/",
                  "data": "Synthetic files in a temporary directory created and deleted by the fixture"},
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
        for mode in ("vulnerable", "naive", "fixed"):
            proc = subprocess.Popen([sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tmp_dir = None
            try:
                ready, _, _ = select.select([proc.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(proc.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                tmp_dir = os.path.dirname(startup["base_dir"])
                evidence.setdefault("servers", {})[mode] = startup
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + startup["base_url"].rsplit(":", 1)[1])
                for cid, suffix, expected in build_cases(startup["secret_path"]):
                    url = startup["base_url"] + "/files/" + suffix
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--path-as-is",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", "GET", url]
                    started = now()
                    tick = time.monotonic()
                    resp = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status = int(resp.stdout.splitlines()[0].split()[1])
                    body = resp.stdout.split("\n\n", 1)[1]
                    leaked = SECRET_MARKER in body
                    want_status, want_leak = expected[mode]
                    raw_name = mode + "-" + cid + ".http"
                    (args.output / raw_name).write_text(resp.stdout)
                    commands.append(shlex.join(command))
                    passed = resp.returncode == 0 and status == want_status and leaked == want_leak
                    evidence["cases"].append({
                        "id": mode + "/" + cid, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "port": int(startup["base_url"].rsplit(":", 1)[1]), "command": command,
                        "curl_exit_code": resp.returncode, "stderr": resp.stderr,
                        "expected_status": want_status, "expected_secret_disclosed": want_leak,
                        "observed_status": status, "secret_disclosed": leaked, "observed_body": body,
                        "matches_expected": passed, "response_file": raw_name,
                        "response_sha256": digest(args.output / raw_name),
                    })
                    if not passed:
                        evidence["failures"].append(mode + "/" + cid)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                if tmp_dir is not None and os.path.exists(tmp_dir):
                    evidence["failures"].append("temp directory not removed: " + mode)
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    evidence["finished_at"] = now()
    evidence["all_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 24
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
