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
LOGIN = json.dumps({"user": "victor", "password": "demo-password-not-real"})
BAD_LOGIN = json.dumps({"user": "victor", "password": "wrong-guess"})


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def curl(base, path, cookie=None, body=None):
    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
               "--connect-timeout", "1", "--max-time", "3"]
    if cookie:
        command += ["--cookie", "sid=" + cookie]
    if body is not None:
        command += ["--request", "POST", "--header", "Content-Type: application/json", "--data", body]
    else:
        command += ["--request", "GET"]
    command.append(base + path)
    return command


def parse(text):
    head, _, body = text.replace("\r\n", "\n").partition("\n\n")
    lines = head.splitlines()
    cookie = None
    for line in lines[1:]:
        if line.lower().startswith("set-cookie: sid="):
            cookie = line.split("=", 1)[1].split(";")[0]
    return int(lines[0].split()[1]), cookie, json.loads(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against two locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET", "POST"],
                  "paths": ["/session", "/login", "/account"],
                  "data": "One synthetic user and a made-up password; session IDs are random per run"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or agent ran"},
        "cases": [], "failures": [], "mode_summary": {},
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# Ports and session IDs refer to the recorded run; the servers are no longer listening."]
    try:
        for mode in ("vulnerable", "fixed"):
            process = subprocess.Popen([sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                base = startup["base_url"]
                if not base.startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + base.rsplit(":", 1)[1])
                state = {}

                def run(name, role, path, expected, cookie_key=None, body=None, check=None):
                    cookie = state.get(cookie_key) if cookie_key else None
                    command = curl(base, path, cookie, body)
                    started, tick = now(), time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status, set_cookie, parsed = parse(response.stdout)
                    raw_name = mode + "-" + name + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    passed = response.returncode == 0 and status == expected["demo"] and (check(set_cookie, parsed) if check else True)
                    evidence["cases"].append({
                        "id": mode + "/" + name, "role": role, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "sent_session_id": cookie, "set_cookie_session_id": set_cookie,
                        "secure_expected_status": expected["secure"], "demonstration_expected_status": expected["demo"],
                        "observed_status": status, "observed_body": parsed, "matches_demonstration": passed,
                        "boundary_holds": status == expected["secure"],
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    })
                    if not passed:
                        evidence["failures"].append(mode + "/" + name)
                    return set_cookie

                vuln = mode == "vulnerable"
                state["attacker"] = run("1-attacker-gets-session", "attacker", "/session", {"secure": 200, "demo": 200},
                                        check=lambda c, b: bool(c) and b == {"session": "anonymous"})
                run("2-attacker-before-login", "attacker", "/account", {"secure": 401, "demo": 401}, "attacker",
                    check=lambda c, b: b == {"error": "authentication_required"})
                run("3-victim-wrong-password", "victim", "/login", {"secure": 401, "demo": 401}, "attacker", BAD_LOGIN,
                    check=lambda c, b: c is None and b == {"error": "invalid_credentials"})
                login_cookie = run("4-victim-logs-in-with-fixed-id", "victim", "/login", {"secure": 200, "demo": 200},
                                   "attacker", LOGIN,
                                   check=lambda c, b: b == {"login": "ok", "user": "victor"} and
                                   ((c is None) if vuln else (c is not None and c != state["attacker"])))
                state["victim"] = login_cookie or state["attacker"]
                run("5-victim-own-session", "victim", "/account", {"secure": 200, "demo": 200}, "victim",
                    check=lambda c, b: b["user"] == "victor")
                run("6-attacker-after-login", "attacker", "/account",
                    {"secure": 401, "demo": 200 if vuln else 401}, "attacker",
                    check=(lambda c, b: b["user"] == "victor") if vuln else (lambda c, b: b == {"error": "authentication_required"}))
                evidence["mode_summary"][mode] = {
                    "session_id_changed_at_login": state["victim"] != state["attacker"],
                    "attacker_id_authenticated_after_login": evidence["cases"][-1]["observed_status"] == 200}
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
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 12
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
