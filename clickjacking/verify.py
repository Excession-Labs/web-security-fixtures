#!/usr/bin/env python3
"""Check clickjacking fixture headers with curl and framing behavior with headless Chromium.

The browser step needs node and the playwright package: set PLAYWRIGHT_NODE_MODULES to a
node_modules directory that contains it (default: ./node_modules). Without it only headers are checked.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shlex
import shutil
import subprocess
import sys

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
NODE_MODULES = os.environ.get("PLAYWRIGHT_NODE_MODULES", str(Path.cwd() / "node_modules"))


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def start(role, mode, target_url=""):
    command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--role", role, "--mode", mode, "--port", "0"]
    if target_url:
        command += ["--target-url", target_url]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([process.stdout], [], [], 5)
    if not ready:
        process.kill()
        raise RuntimeError("Fixture did not start within five seconds")
    info = json.loads(process.stdout.readline())
    if not info["base_url"].startswith("http://127.0.0.1:"):
        process.kill()
        raise RuntimeError("Fixture returned a non-loopback address")
    return process, info["base_url"]


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def curl(args, method="GET"):
    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
               "--connect-timeout", "1", "--max-time", "3", "--request", method] + args
    result = subprocess.run(command, capture_output=True, text=True, timeout=5)
    return command, result


def header(raw, name):
    head = raw.split("\n\n", 1)[0]
    for line in head.split("\n")[1:]:
        if line.lower().startswith(name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    node = shutil.which("node")
    browser_ok = bool(node) and (Path(NODE_MODULES) / "playwright").is_dir()
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "curl for response headers; headless Chromium (Playwright) for framing and click-through",
        "scope": {"hosts": ["127.0.0.1"], "origins": "two loopback ports per scenario: target and attacker",
                  "data": "One synthetic account page with a counter of delete requests"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0],
                     "node": subprocess.check_output([node, "--version"], text=True).strip() if node else None},
        "browser_run": browser_ok,
        "sha256": {n: sha(ROOT / n) for n in ("fixture.py", "verify.py", "browser_check.cjs")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "Scripted run; no model or agent ran"},
        "cases": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded commands; ports belong to the finished run and are no longer listening."]

    def record(case_id, expected, observed, **extra):
        ok = expected == observed
        evidence["cases"].append({"id": case_id, "expected": expected, "observed": observed,
                                  "matches_expected": ok, **extra})
        if not ok:
            evidence["failures"].append(case_id)

    def browser(scenario, attacker_url, target_url):
        env = dict(os.environ, NODE_PATH=NODE_MODULES)
        command = [node, str(ROOT / "browser_check.cjs"), scenario, attacker_url, target_url]
        commands.append("NODE_PATH=<dir with playwright> node " + shlex.join(["browser_check.cjs"] + command[2:]))
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, env=env)
        return json.loads(result.stdout.strip().splitlines()[-1])

    try:
        for mode in ("vulnerable", "fixed"):
            # Header check with curl
            target, target_url = start("target", mode)
            try:
                commands.append("# target " + mode + " on " + target_url)
                command, res = curl([target_url + "/account"])
                commands.append(shlex.join(command))
                (args.output / (mode + "-account-headers.http")).write_text(res.stdout)
                status = int(res.stdout.splitlines()[0].split()[1])
                observed = {"status": status,
                            "content_security_policy": header(res.stdout, "Content-Security-Policy"),
                            "x_frame_options": header(res.stdout, "X-Frame-Options")}
                expected = ({"status": 200, "content_security_policy": None, "x_frame_options": None}
                            if mode == "vulnerable" else
                            {"status": 200, "content_security_policy": "frame-ancestors 'none'",
                             "x_frame_options": "DENY"})
                record(mode + "/curl-headers", expected, observed, server=target_url,
                       response_file=mode + "-account-headers.http", command=command)
            finally:
                stop(target)
            if not browser_ok:
                continue
            # Framed click from a second origin
            target, target_url = start("target", mode)
            attacker, attacker_url = start("attacker", mode, target_url)
            try:
                result = browser("framed", attacker_url, target_url)
                (args.output / (mode + "-framed-browser.json")).write_text(json.dumps(result, indent=2) + "\n")
                _, state = curl([target_url + "/state"])
                deletes = json.loads(state.stdout.split("\n\n", 1)[1])["delete_requests"]
                (args.output / (mode + "-framed-state.http")).write_text(state.stdout)
                rendered = bool(result.get("frame_has_delete_button"))
                expected = ({"frame_rendered": True, "delete_requests": 1} if mode == "vulnerable"
                            else {"frame_rendered": False, "delete_requests": 0})
                record(mode + "/browser-framed-click", expected,
                       {"frame_rendered": rendered, "delete_requests": deletes},
                       target=target_url, attacker=attacker_url, frame_url=result.get("frame_url"),
                       console=result.get("console"), browser=result.get("browser"),
                       browser_file=mode + "-framed-browser.json", state_file=mode + "-framed-state.http")
            finally:
                stop(attacker)
                stop(target)
            # Positive control: legitimate top-level use
            target, target_url = start("target", mode)
            try:
                result = browser("direct", "", target_url)
                (args.output / (mode + "-direct-browser.json")).write_text(json.dumps(result, indent=2) + "\n")
                _, state = curl([target_url + "/state"])
                deletes = json.loads(state.stdout.split("\n\n", 1)[1])["delete_requests"]
                (args.output / (mode + "-direct-state.http")).write_text(state.stdout)
                record(mode + "/browser-direct-click", {"button_present": True, "delete_requests": 1},
                       {"button_present": bool(result.get("top_level_has_delete_button")), "delete_requests": deletes},
                       target=target_url, browser_file=mode + "-direct-browser.json",
                       state_file=mode + "-direct-state.http")
            finally:
                stop(target)
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    evidence["finished_at"] = now()
    expected_cases = 6 if browser_ok else 2
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == expected_cases
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "browser_run": browser_ok,
                      "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
