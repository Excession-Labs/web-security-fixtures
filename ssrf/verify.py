#!/usr/bin/env python3
"""Run twelve real curl requests against fixture.py's preview endpoint; no external network targets."""
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
import urllib.parse

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent

# requested_url is filled in once the target and metadata ports are known.
CASES = [
    ("legit", "http://target.test:{target}/article"),
    ("literal", "http://127.0.0.1:{metadata}/latest/meta-data/secret"),
    ("encoded", "http://2130706433:{metadata}/latest/meta-data/secret"),
    ("redirect", "http://target.test:{target}/redirect"),
]

# (mode, case) -> expected preview-endpoint status and whether the synthetic secret
# should appear in the upstream body. This is the behaviour the fixture is built to show.
EXPECTED = {
    ("vulnerable", "legit"): (200, False),
    ("vulnerable", "literal"): (200, True),
    ("vulnerable", "encoded"): (200, True),
    ("vulnerable", "redirect"): (200, True),
    ("naive", "legit"): (200, False),
    ("naive", "literal"): (403, False),
    ("naive", "encoded"): (200, True),
    ("naive", "redirect"): (200, True),
    ("strict", "legit"): (200, False),
    ("strict", "literal"): (403, False),
    ("strict", "encoded"): (403, False),
    ("strict", "redirect"): (200, False),
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def start(cmd, label):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([process.stdout], [], [], 5)
    if not ready:
        process.kill()
        raise RuntimeError(label + " did not start within five seconds")
    startup = json.loads(process.stdout.readline())
    if not startup["base_url"].startswith("http://127.0.0.1:"):
        process.kill()
        raise RuntimeError(label + " returned a non-loopback address")
    return process, startup


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)

    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against a locally spawned preview endpoint, "
                  "which itself fetches a locally spawned target or metadata server",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET"],
                  "paths": ["/preview", "/article", "/redirect", "/latest/meta-data/secret"],
                  "data": "One synthetic metadata secret and one synthetic public article; "
                          "no external hosts, no real credentials"},
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

    metadata_process = target_process = None
    try:
        metadata_process, metadata_info = start(
            [sys.executable, "-u", str(ROOT / "fixture.py"), "--role", "metadata", "--port", "0"],
            "metadata server")
        metadata_port = int(metadata_info["base_url"].rsplit(":", 1)[1])
        commands.append("# Server: python3 fixture.py --role metadata --port " + str(metadata_port))

        redirect_to = "http://127.0.0.1:" + str(metadata_port) + "/latest/meta-data/secret"
        target_process, target_info = start(
            [sys.executable, "-u", str(ROOT / "fixture.py"), "--role", "target", "--port", "0",
             "--redirect-to", redirect_to],
            "target server")
        target_port = int(target_info["base_url"].rsplit(":", 1)[1])
        commands.append("# Server: python3 fixture.py --role target --port " + str(target_port) +
                         " --redirect-to " + redirect_to)

        urls = {name: template.format(target=target_port, metadata=metadata_port) for name, template in CASES}

        for mode in ("vulnerable", "naive", "strict"):
            preview_command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--role", "preview",
                                "--port", "0", "--mode", mode]
            if mode == "strict":
                preview_command += ["--allow", "127.0.0.1:" + str(target_port)]
            preview_process, preview_info = start(preview_command, "preview server (" + mode + ")")
            preview_port = int(preview_info["base_url"].rsplit(":", 1)[1])
            commands.append("# Server: python3 fixture.py --role preview --port " + str(preview_port) +
                             " --mode " + mode +
                             (" --allow 127.0.0.1:" + str(target_port) if mode == "strict" else ""))
            try:
                for case_name, target_url in urls.items():
                    preview_url = ("http://127.0.0.1:" + str(preview_port) + "/preview?url=" +
                                   urllib.parse.quote(target_url, safe=""))
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3",
                               "--request", "GET", preview_url]
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status = int(response.stdout.splitlines()[0].split()[1])
                    body = json.loads(response.stdout.split("\n\n", 1)[1])
                    expected_status, expected_secret_leaked = EXPECTED[(mode, case_name)]
                    passed = (response.returncode == 0 and status == expected_status and
                              body.get("secret_leaked") == expected_secret_leaked)
                    raw_name = mode + "-" + case_name + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    evidence["cases"].append({
                        "id": mode + "/" + case_name, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "mode": mode, "requested_url": target_url,
                        "command": command, "curl_exit_code": response.returncode, "stderr": response.stderr,
                        "expected_preview_status": expected_status,
                        "expected_secret_leaked": expected_secret_leaked,
                        "observed_preview_status": status, "observed_body": body,
                        "matches_demonstration": passed,
                        "attack_succeeded": bool(body.get("secret_leaked")),
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    })
                    if not passed:
                        evidence["failures"].append(mode + "/" + case_name)
            finally:
                stop(preview_process)
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        if target_process:
            stop(target_process)
        if metadata_process:
            stop(metadata_process)

    evidence["finished_at"] = now()
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 12
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
