#!/usr/bin/env python3
"""Run the two-step login fixture in vulnerable and fixed mode and record
real HTTP responses for three MFA flaws: step skipping, unlimited code
guesses, and a code not bound to one session. No external network targets.
Discrete scenario requests use curl as a subprocess. The brute-force guess
loop uses Python's standard-library http.client directly, because spawning
one curl process per guess would make a 4-digit search too slow to finish
in a reasonable test run; this is disclosed here and in the published post.
"""
import argparse
import datetime
import hashlib
import http.client
import json
import platform
import select
import shlex
import subprocess
import sys
import time
from pathlib import Path

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
CODE_SPACE_SIZE = 10000  # four synthetic digits, 0000-9999
MAX_ATTEMPTS = 5  # must match fixture.py's MAX_ATTEMPTS


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_curl(base_url, method, path, token=None, body=None):
    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", method]
    data = None
    if body is not None:
        data = json.dumps(body)
        command += ["--header", "Content-Type: application/json", "--data", data]
    if token:
        command += ["--header", "Authorization: Bearer " + token]
    command.append(base_url + path)
    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
    lines = response.stdout.split("\r\n\r\n", 1)
    if len(lines) == 1:
        lines = response.stdout.split("\n\n", 1)
    head = lines[0]
    status = int(head.splitlines()[0].split()[1])
    parsed_body = json.loads(lines[1]) if len(lines) > 1 and lines[1].strip() else None
    return {
        "command": command, "status": status, "body": parsed_body,
        "raw": response.stdout, "curl_exit_code": response.returncode, "stderr": response.stderr,
    }


def brute_force(host, port, session_id, limit=CODE_SPACE_SIZE):
    """Sequential 0000..limit-1 guesses over one kept-alive HTTP connection."""
    conn = http.client.HTTPConnection(host, port, timeout=3)
    attempts = 0
    final_status = None
    final_body = None
    started = time.monotonic()
    try:
        for value in range(limit):
            guess = "%04d" % value
            payload = json.dumps({"session": session_id, "code": guess})
            headers = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
            attempts += 1
            try:
                conn.request("POST", "/verify-code", body=payload, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
                status = resp.status
            except (http.client.HTTPException, ConnectionError, OSError):
                conn.close()
                conn = http.client.HTTPConnection(host, port, timeout=3)
                conn.request("POST", "/verify-code", body=payload, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
                status = resp.status
            final_status = status
            final_body = json.loads(raw) if raw else None
            if status in (200, 423):
                break
    finally:
        conn.close()
    elapsed = time.monotonic() - started
    return {
        "attempts": attempts, "elapsed_seconds": round(elapsed, 3),
        "final_status": final_status, "final_body": final_body,
        "code_space_size": limit,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses for scenario requests, a direct "
                  "standard-library HTTP connection for the brute-force guess loop, "
                  "against two locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET", "POST"],
                  "paths": ["/login", "/verify-code", "/account", "/test-inbox"],
                  "data": "Three synthetic demo accounts and 4-digit synthetic codes; "
                          "no production credentials"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or Excession agent ran"},
        "max_attempts_before_lockout": MAX_ATTEMPTS,
        "setup": {"vulnerable": [], "fixed": []},
        "cases": [], "brute_force": {}, "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening.",
                "# The brute-force guess loop used Python http.client directly; see results.json."]

    def record_case(mode, name, result, expected_status, note, save_file=True):
        passed = result["status"] == expected_status
        entry = {
            "id": mode + "/" + name, "expected_status": expected_status,
            "observed_status": result["status"], "observed_body": result["body"],
            "matches_expectation": passed, "note": note,
        }
        if save_file:
            raw_name = mode + "-" + name + ".http"
            (args.output / raw_name).write_text(result["raw"])
            entry["response_file"] = raw_name
            entry["response_sha256"] = digest(args.output / raw_name)
        evidence["cases"].append(entry)
        commands.append(shlex.join(result["command"]))
        if not passed:
            evidence["failures"].append(mode + "/" + name)
        return entry

    def record_setup(mode, name, result):
        commands.append(shlex.join(result["command"]))
        evidence["setup"][mode].append({
            "id": mode + "/" + name, "observed_status": result["status"], "observed_body": result["body"],
        })

    try:
        for mode in ("vulnerable", "fixed"):
            server_command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"]
            process = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                base_url = startup["base_url"]
                if not base_url.startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                host, port_str = base_url.rsplit(":", 1)
                host = host.rsplit("/", 1)[-1]
                port = int(port_str)
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + port_str)

                # --- step-skipping: password-only session reaching /account ---
                r = run_curl(base_url, "POST", "/login", body={"username": "alice", "password": "alice-demo-pw"})
                record_setup(mode, "login-alice-first", r)
                session_alice1 = r["body"]["session"]
                r = run_curl(base_url, "GET", "/account", token=session_alice1)
                record_case(mode, "account-before-mfa", r, 403 if mode == "fixed" else 200,
                            "GET /account using only the password-step session, before the code is verified")

                # --- positive control: completing the code legitimately still works ---
                r = run_curl(base_url, "POST", "/login", body={"username": "alice", "password": "alice-demo-pw"})
                record_setup(mode, "login-alice-second", r)
                session_alice2 = r["body"]["session"]
                r = run_curl(base_url, "GET", "/test-inbox?session=" + session_alice2)
                record_setup(mode, "read-own-code-alice", r)
                own_code = r["body"]["code"]
                r = run_curl(base_url, "POST", "/verify-code", body={"session": session_alice2, "code": own_code})
                record_case(mode, "own-code-login", r, 200,
                            "Alice submits her own correct code for her own session")
                r = run_curl(base_url, "GET", "/account", token=session_alice2)
                record_case(mode, "account-after-mfa", r, 200,
                            "GET /account after the code step is completed")

                # --- single use: replay the same correct code again ---
                r = run_curl(base_url, "POST", "/verify-code", body={"session": session_alice2, "code": own_code})
                record_case(mode, "replay-code", r, 409 if mode == "fixed" else 200,
                            "Resubmitting the same already-used code and session")

                # --- session binding: Bob's session completed with Alice's code ---
                r = run_curl(base_url, "POST", "/login", body={"username": "bob", "password": "bob-demo-pw"})
                record_setup(mode, "login-bob", r)
                session_bob = r["body"]["session"]
                r = run_curl(base_url, "POST", "/login", body={"username": "alice", "password": "alice-demo-pw"})
                record_setup(mode, "login-alice-third", r)
                session_alice3 = r["body"]["session"]
                r = run_curl(base_url, "GET", "/test-inbox?session=" + session_alice3)
                record_setup(mode, "read-own-code-alice-third", r)
                alice3_code = r["body"]["code"]
                r = run_curl(base_url, "POST", "/verify-code", body={"session": session_bob, "code": alice3_code})
                record_case(mode, "cross-session-code", r, 401 if mode == "fixed" else 200,
                            "Bob's pending session is submitted together with Alice's valid, unused code")

                # --- attempt limit: scripted sequential guessing ---
                r = run_curl(base_url, "POST", "/login", body={"username": "charlie", "password": "charlie-demo-pw"})
                record_setup(mode, "login-charlie", r)
                session_charlie = r["body"]["session"]
                bf = brute_force(host, port, session_charlie)
                evidence["brute_force"][mode] = bf
                summary_name = mode + "-brute-force-summary.json"
                (args.output / summary_name).write_text(json.dumps(bf, indent=2) + "\n")
                found = bf["final_status"] == 200
                if mode == "vulnerable" and not found:
                    evidence["failures"].append(mode + "/brute-force-did-not-find-code")
                if mode == "fixed" and found:
                    evidence["failures"].append(mode + "/brute-force-should-have-been-locked-out")
                if mode == "fixed" and bf["final_status"] != 423:
                    evidence["failures"].append(mode + "/brute-force-expected-lockout")
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
    evidence["all_checks_passed"] = not evidence["failures"]
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({
        "cases": len(evidence["cases"]), "passed": evidence["all_checks_passed"],
        "failures": evidence["failures"], "evidence": str(args.output / "results.json"),
    }))
    return 0 if evidence["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
