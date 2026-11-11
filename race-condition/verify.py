#!/usr/bin/env python3
"""Reproduce a check-then-act coupon race against fixture.py.

Concurrency method, stated plainly: the burst of N simultaneous redemption
requests is sent with Python threads (concurrent.futures.ThreadPoolExecutor)
calling urllib.request directly, not curl --parallel. Real curl subprocesses
are used for the sequential control requests and the final status check,
where there is no concurrency to preserve. No external network targets, no
real credentials; all coupon codes are fixed synthetic demo strings.

This script restarts a fresh fixture.py process (fresh in-memory database)
for every round, and runs several rounds per mode, so the published results
show the real spread of outcomes rather than one lucky or unlucky run.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import platform
import select
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
ROUNDS = 5
BURST_SIZE = 16
WIDENED_DELAY_SECONDS = 0.05
# Three condition groups: (label, mode, delay). "vulnerable-baseline" adds no
# artificial delay, so its only check-then-act window is ordinary socket and
# interpreter scheduling. "vulnerable-widened" adds WIDENED_DELAY_SECONDS
# between the check and the write, stated here and in the published post.
# "fixed" has no check-then-act window to widen.
CONDITIONS = [
    ("vulnerable-baseline", "vulnerable", 0.0),
    ("vulnerable-widened", "vulnerable", WIDENED_DELAY_SECONDS),
    ("fixed", "fixed", 0.0),
]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def curl(args_extra, url, token_header=None):
    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
               "--http1.1", "--connect-timeout", "1", "--max-time", "3"] + args_extra
    if token_header:
        command += ["--header", token_header]
    command.append(url)
    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
    status = int(response.stdout.splitlines()[0].split()[1])
    body = json.loads(response.stdout.split("\n\n", 1)[1])
    return command, response, status, body


def burst_request(base_url, code):
    req = urllib.request.Request(base_url + "/redeem", method="POST",
                                  headers={"X-Coupon-Code": code})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = json.loads(resp.read().decode())
            return {"status": resp.status, "body": body,
                     "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read().decode())
        return {"status": exc.code, "body": body,
                 "elapsed_ms": round((time.monotonic() - started) * 1000, 3)}


def start_server(mode, delay):
    command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode,
               "--port", "0", "--delay", str(delay)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([process.stdout], [], [], 5)
    if not ready:
        process.kill()
        raise RuntimeError("Fixture did not start within five seconds")
    startup = json.loads(process.stdout.readline())
    if not startup["base_url"].startswith("http://127.0.0.1:"):
        process.kill()
        raise RuntimeError("Fixture returned a non-loopback address")
    return process, startup, command


def stop_server(process):
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_round(label, mode, round_index, delay, output_dir):
    process, startup, server_command = start_server(mode, delay)
    round_record = {"label": label, "mode": mode, "delay_seconds": delay, "round": round_index,
                     "server": startup, "server_command": shlex.join(server_command), "steps": []}
    # Raw .http responses are saved only for round 0 of each condition, to
    # keep the evidence bundle to a representative sample rather than one
    # file per request across 15 rounds x 16 burst requests.
    save_raw = round_index == 0

    def record_step(step_id, cmd, resp, status, body, expected_status):
        entry = {"id": step_id, "command": shlex.join(cmd), "expected_status": expected_status,
                  "observed_status": status, "observed_body": body, "passed": status == expected_status}
        if save_raw:
            raw_name = f"{label}-{step_id}.http"
            (output_dir / raw_name).write_text(resp.stdout)
            entry["response_file"] = raw_name
            entry["response_sha256"] = digest(output_dir / raw_name)
        round_record["steps"].append(entry)

    try:
        base_url = startup["base_url"]

        # Negative control: unknown coupon.
        cmd, resp, status, body = curl(["--request", "GET"], base_url + "/status?code=NOPE")
        record_step("unknown-coupon", cmd, resp, status, body, 404)

        # Positive control: one sequential redemption succeeds.
        cmd, resp, status, body = curl(["--request", "POST"], base_url + "/redeem",
                                         "X-Coupon-Code: CONTROL1")
        record_step("control-first-redeem", cmd, resp, status, body, 200)

        # Negative control: the same sequential coupon, redeemed again, must be refused.
        cmd, resp, status, body = curl(["--request", "POST"], base_url + "/redeem",
                                         "X-Coupon-Code: CONTROL1")
        record_step("control-second-redeem", cmd, resp, status, body, 409)

        # The burst: BURST_SIZE simultaneous redemption attempts against one
        # single-use coupon that has never been touched in this round.
        with concurrent.futures.ThreadPoolExecutor(max_workers=BURST_SIZE) as pool:
            futures = [pool.submit(burst_request, base_url, "SAVE10") for _ in range(BURST_SIZE)]
            results = [f.result() for f in futures]
        successes = sum(1 for r in results if r["status"] == 200)
        round_record["burst"] = {
            "coupon": "SAVE10", "requests_sent": BURST_SIZE,
            "successful_200_count": successes,
            "expected_successful_count": 1,
            "results": results,
        }

        # Final state of the burst coupon: how many uses it has left.
        cmd, resp, status, body = curl(["--request", "GET"], base_url + "/status?code=SAVE10")
        record_step("burst-final-status", cmd, resp, status, body, status)
        round_record["final_uses_remaining"] = body.get("uses_remaining")
    finally:
        stop_server(process)
    return round_record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Concurrent burst via Python threads + urllib against a locally spawned fixture; "
                  "curl subprocesses for the sequential control requests and status checks",
        "parameters": {"rounds_per_condition": ROUNDS, "burst_size": BURST_SIZE,
                       "conditions": [{"label": label, "mode": mode, "delay_seconds": delay}
                                      for label, mode, delay in CONDITIONS],
                       "note": "vulnerable-widened adds an artificial sleep between the check and "
                               "the write, stated here and in the published post, so a handful of "
                               "local threads reliably land inside the window. vulnerable-baseline "
                               "adds no delay; fixed has no check-then-act window to widen."},
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET", "POST"],
                  "paths": ["/redeem", "/status"],
                  "data": "Two synthetic single-use coupon codes held in an in-memory SQLite table"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or Excession agent ran"},
        "rounds": [], "failures": [],
    }

    try:
        for label, mode, delay in CONDITIONS:
            for round_index in range(ROUNDS):
                record = run_round(label, mode, round_index, delay, args.output)
                evidence["rounds"].append(record)
                for step in record["steps"]:
                    if "passed" in step and not step["passed"]:
                        evidence["failures"].append(f"{label}/round{round_index}/{step['id']}")
                if label == "fixed" and record["burst"]["successful_200_count"] != 1:
                    evidence["failures"].append(
                        f"fixed/round{round_index}/burst-expected-exactly-one-success")
    except Exception as exc:
        import traceback
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
        evidence["traceback"] = traceback.format_exc()

    # Summaries used directly in the published post.
    evidence["summary"] = {
        label: {
            "successful_200_counts_by_round": [r["burst"]["successful_200_count"]
                                                for r in evidence["rounds"] if r["label"] == label],
            "final_uses_remaining_by_round": [r["final_uses_remaining"]
                                               for r in evidence["rounds"] if r["label"] == label],
        }
        for label, _mode, _delay in CONDITIONS
    }

    evidence["finished_at"] = now()
    evidence["all_demonstration_checks_passed"] = (
        not evidence["failures"] and len(evidence["rounds"]) == len(CONDITIONS) * ROUNDS
    )
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")

    commands_lines = ["#!/bin/sh",
                       "# Recorded commands; rerun verify.py to start fresh fixture servers.",
                       "# Server ports below refer to the finished run and are no longer listening."]
    for record in evidence["rounds"]:
        commands_lines.append(f"# {record['label']} round {record['round']}: {record['server_command']}")
        for step in record["steps"]:
            commands_lines.append(step["command"])
        commands_lines.append(
            f"# burst: {BURST_SIZE} concurrent Python-thread POST /redeem requests, coupon SAVE10")
    (args.output / "commands.sh").write_text("\n".join(commands_lines) + "\n")

    print(json.dumps({
        "rounds": len(evidence["rounds"]), "passed": evidence["all_demonstration_checks_passed"],
        "failures": evidence["failures"], "summary": evidence["summary"],
        "evidence": str(args.output / "results.json"),
    }))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
