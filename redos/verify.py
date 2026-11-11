#!/usr/bin/env python3
"""Time real curl requests against fixture.py in vulnerable and fixed mode.

Targets 127.0.0.1 only. Worst vulnerable request is about 3 s on the recording
machine. Every curl call has a hard 8 s limit, and the attack ladder stops
climbing when one request takes longer than 4 s.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import platform
import re
import select
import shlex
import subprocess
import sys
import time

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import fixture  # noqa: E402  (same directory; used for the in-process timing)

CURL_MAX_TIME = "8"
LADDER_STOP_SECONDS = 4.0
LADDER = [16, 18, 20, 22, 24, 26]
COLLATERAL_LENGTH = 24


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def curl_command(base_url, name):
    return ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
            "--connect-timeout", "1", "--max-time", CURL_MAX_TIME, "--get",
            "--data-urlencode", "name=" + name, base_url + "/validate"]


def parse(stdout):
    if not stdout.strip():
        return None, None, None
    head, _, body = stdout.partition("\n\n")
    status = int(head.splitlines()[0].split()[1])
    regex_ms = None
    for line in head.splitlines()[1:]:
        if line.lower().startswith("x-regex-ms:"):
            regex_ms = float(line.split(":", 1)[1])
    return status, (json.loads(body) if body.strip() else None), regex_ms


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against two locally spawned fixture modes",
        "timing_note": "Timings are observed wall-clock values from one machine and one run. They vary by machine and by run.",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET"], "paths": ["/validate"],
                  "data": "Synthetic display names built from the letter a and fixed demo words"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "patterns": {"vulnerable": fixture.VULNERABLE_PATTERN.pattern, "fixed": fixture.FIXED_PATTERN.pattern,
                     "fixed_max_length": fixture.MAX_LENGTH},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or agent ran"},
        "cases": [], "claims": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]

    def run_case(mode, base_url, case_id, name, expected, group):
        command = curl_command(base_url, name)
        started, tick = now(), time.monotonic()
        response = subprocess.run(command, capture_output=True, text=True, timeout=12)
        elapsed = round((time.monotonic() - tick) * 1000, 1)
        status, body, regex_ms = parse(response.stdout)
        raw_name = mode + "-" + case_id + ".http"
        (args.output / raw_name).write_text(response.stdout)
        commands.append(shlex.join(command))
        record = {"id": mode + "/" + case_id, "group": group, "started_at": started,
                  "input_length": len(name), "expected_status": expected, "observed_status": status,
                  "observed_body": body, "elapsed_ms": elapsed, "server_regex_ms": regex_ms,
                  "curl_exit_code": response.returncode, "timed_out": response.returncode == 28,
                  "stderr": response.stderr, "matches_expected": status == expected,
                  "response_file": raw_name, "response_sha256": digest(args.output / raw_name)}
        evidence["cases"].append(record)
        if not record["matches_expected"]:
            evidence["failures"].append(record["id"])
        return record

    controls = [  # (id, input, expected vulnerable, expected fixed, group)
        ("valid-name", "Ada Lovelace", 200, 200, "positive"),
        ("valid-longer-name", "Grace Brewster Murray Hopper of the Navy", 200, 200, "positive"),
        ("valid-26-letters", "a" * 26, 200, 200, "positive"),
        ("invalid-character", "bad!", 400, 400, "negative"),
        ("invalid-double-space", "Ada  Lovelace", 400, 400, "negative"),
        ("tab-separator", "Ada\tLovelace", 200, 400, "behaviour-change"),
        ("valid-64-letters", "a" * 64, 200, 200, "positive"),
        ("valid-65-letters", "a" * 65, 200, 413, "behaviour-change"),
    ]
    fixed_only = [
        ("attack-64-at-cap", "a" * 63 + "!", 400, "negative"),
        ("attack-1000", "a" * 999 + "!", 413, "negative"),
    ]
    try:
        for mode in ("vulnerable", "fixed"):
            process = subprocess.Popen([sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                base_url = startup["base_url"]
                if not base_url.startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + base_url.rsplit(":", 1)[1])
                for case_id, text, exp_v, exp_f, group in controls:
                    run_case(mode, base_url, case_id, text, exp_v if mode == "vulnerable" else exp_f, group)
                if mode == "fixed":
                    for case_id, text, expected, group in fixed_only:
                        run_case(mode, base_url, case_id, text, expected, group)
                # Attack ladder: "a" * n + "!" never matches, so a backtracking engine tries every split.
                for n in LADDER:
                    previous = [c for c in evidence["cases"] if c["id"].startswith(mode + "/attack-ladder-")]
                    if previous and previous[-1]["elapsed_ms"] / 1000 > LADDER_STOP_SECONDS:
                        evidence["cases"].append({"id": mode + "/attack-ladder-" + str(n), "group": "attack",
                                                  "skipped": "previous request took over %.0f s" % LADDER_STOP_SECONDS,
                                                  "matches_expected": True})
                        continue
                    run_case(mode, base_url, "attack-ladder-%02d" % n, "a" * n + "!", 400, "attack")
                # Collateral: a valid request sent while one attack request is being processed.
                attack_command = curl_command(base_url, "a" * COLLATERAL_LENGTH + "!")
                commands.append(shlex.join(attack_command))
                attack = subprocess.Popen(attack_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                time.sleep(0.2)
                run_case(mode, base_url, "collateral-valid-during-attack", "Ada Lovelace", 200, "collateral")
                attack_out, _ = attack.communicate(timeout=12)
                (args.output / (mode + "-collateral-attack.http")).write_text(attack_out)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))

    def case(case_id):
        return next((c for c in evidence["cases"] if c["id"] == case_id), None)

    def attack_times(mode):
        return [c["elapsed_ms"] for c in evidence["cases"]
                if c["id"].startswith(mode + "/attack-ladder-") and "elapsed_ms" in c]

    def claim(name, passed, detail):
        evidence["claims"].append({"claim": name, "passed": bool(passed), "detail": detail})
        if not passed:
            evidence["failures"].append("claim: " + name)

    vuln, fix = attack_times("vulnerable"), attack_times("fixed")
    if vuln and fix:
        claim("vulnerable attack time grows with input length", max(vuln) >= 500 and max(vuln) >= 10 * min(vuln),
              {"min_ms": min(vuln), "max_ms": max(vuln)})
        claim("fixed attack time stays under 500 ms", max(fix) < 500, {"max_ms": max(fix)})
    base_v, hit_v = case("vulnerable/valid-name"), case("vulnerable/collateral-valid-during-attack")
    base_f, hit_f = case("fixed/valid-name"), case("fixed/collateral-valid-during-attack")
    if base_v and hit_v and base_f and hit_f:
        claim("vulnerable server delays a valid request queued behind an attack", hit_v["elapsed_ms"] >= 250,
              {"baseline_ms": base_v["elapsed_ms"], "during_attack_ms": hit_v["elapsed_ms"]})
        claim("fixed server does not delay a valid request", hit_f["elapsed_ms"] < 250,
              {"baseline_ms": base_f["elapsed_ms"], "during_attack_ms": hit_f["elapsed_ms"]})
    # In-process check of the fixed pattern alone, without the length cap.
    text = "a" * 50000 + "!"
    tick = time.perf_counter()
    result = fixture.FIXED_PATTERN.match(text)
    pattern_ms = round((time.perf_counter() - tick) * 1000, 3)
    evidence["in_process_fixed_pattern"] = {"input_length": len(text), "matched": result is not None, "elapsed_ms": pattern_ms}
    claim("fixed pattern alone rejects a 50,001 character attack input in under 1 s",
          result is None and pattern_ms < 1000, {"elapsed_ms": pattern_ms})

    evidence["finished_at"] = now()
    checks = [c for c in evidence["cases"] if "skipped" not in c]
    evidence["all_checks_passed"] = not evidence["failures"] and len(checks) > 0
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"cases": len(checks), "claims": len(evidence["claims"]),
                      "passed": evidence["all_checks_passed"], "failures": evidence["failures"],
                      "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
