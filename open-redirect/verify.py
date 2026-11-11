#!/usr/bin/env python3
"""Run real curl requests against fixture.py in four modes; no external network targets."""
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
from urllib.parse import urljoin, urlsplit

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
SITE = "site.example"
BASE = "http://" + SITE + "/login"
EVIL = "https://evil.test/phish"

# (mode, id, parameter, value, expected Location, expected: the browser leaves the site)
CASES = [
    ("vulnerable", "local-path", "next", "/account", "/account", False),
    ("vulnerable", "external-url", "next", EVIL, EVIL, True),
    ("naive-slash", "local-path", "next", "/account", "/account", False),
    ("naive-slash", "external-url", "next", EVIL, "/account", False),
    ("naive-slash", "double-slash", "next", "//evil.test/phish", "//evil.test/phish", True),
    ("naive-slash", "backslash", "next", "/\\evil.test/phish", "/\\evil.test/phish", True),
    ("naive-slash", "tab-slash", "next", "/\t/evil.test/phish", "/\t/evil.test/phish", True),
    ("naive-host", "same-site-url", "next", "https://site.example/account", "https://site.example/account", False),
    ("naive-host", "external-url", "next", EVIL, "/account", False),
    ("naive-host", "lookalike-host", "next", "https://site.example.evil.test/phish",
     "https://site.example.evil.test/phish", True),
    ("naive-host", "host-in-query", "next", "https://evil.test/?site.example",
     "https://evil.test/?site.example", True),
    ("naive-host", "userinfo", "next", "https://site.example@evil.test/phish",
     "https://site.example@evil.test/phish", True),
    ("fixed", "local-path", "next", "/account", "/account", False),
    ("fixed", "local-path-with-query", "next", "/account/billing?tab=invoices",
     "/account/billing?tab=invoices", False),
    ("fixed", "external-url", "next", EVIL, "/account", False),
    ("fixed", "same-site-absolute-url", "next", "https://site.example/account", "/account", False),
    ("fixed", "double-slash", "next", "//evil.test/phish", "/account", False),
    ("fixed", "backslash", "next", "/\\evil.test/phish", "/account", False),
    ("fixed", "tab-slash", "next", "/\t/evil.test/phish", "/account", False),
    ("fixed", "lookalike-host", "next", "https://site.example.evil.test/phish", "/account", False),
    ("fixed", "host-in-query", "next", "https://evil.test/?site.example", "/account", False),
    ("fixed", "userinfo", "next", "https://site.example@evil.test/phish", "/account", False),
    ("fixed", "allowlist-key", "dest", "billing", "/account/billing", False),
    ("fixed", "allowlist-unknown-url", "dest", EVIL, "/account", False),
]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def browser_host(location):
    """Model of WHATWG URL resolution for a Location value (not a browser).

    Strip leading and trailing C0 control or space, remove tab and newline, treat a
    backslash like a slash, then resolve against the page URL.
    """
    value = location.strip("".join(chr(i) for i in range(33)))
    value = "".join(c for c in value if c not in "\t\r\n")
    cut = min([i for i in (value.find("?"), value.find("#")) if i >= 0] or [len(value)])
    value = value[:cut].replace("\\", "/") + value[cut:]
    return urlsplit(urljoin(BASE, value)).hostname


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against four locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET"], "paths": ["/login"],
                  "configured_site_host": SITE,
                  "data": "Synthetic redirect targets. evil.test and site.example are reserved names and are never contacted"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "browser_model": "browser_host_modeled applies the WHATWG URL rules in browser_host(); no browser ran",
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or Excession agent ran"},
        "cases": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]
    try:
        for mode in ("vulnerable", "naive-slash", "naive-host", "fixed"):
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
                for case_mode, name, param, value, expected_location, expected_escape in CASES:
                    if case_mode != mode:
                        continue
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--get",
                               "--data-urlencode", param + "=" + value, startup["base_url"] + "/login"]
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    head = response.stdout.split("\n\n", 1)[0].split("\n")
                    status = int(head[0].split()[1])
                    locations = [line.split(": ", 1)[1] for line in head[1:] if line.lower().startswith("location:")]
                    location = locations[0] if locations else None
                    host = browser_host(location) if location is not None else None
                    escapes = host is not None and host != SITE
                    passed = (response.returncode == 0 and status == 302 and location == expected_location
                              and escapes == expected_escape)
                    raw_name = mode + "-" + name + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    evidence["cases"].append({
                        "id": mode + "/" + name, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "parameter": param, "input": value,
                        "server_side_urlsplit_netloc": urlsplit(value).netloc,
                        "observed_status": status, "observed_location": location,
                        "expected_location": expected_location,
                        "browser_host_modeled": host, "leaves_site": escapes,
                        "expected_leaves_site": expected_escape,
                        "matches_demonstration": passed, "redirect_boundary_holds": not escapes,
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
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == len(CASES)
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
