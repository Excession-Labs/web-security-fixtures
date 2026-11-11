#!/usr/bin/env python3
"""Run 24 real curl requests against four fixture.py configurations; no external network targets.

Needs python3 and curl. It creates a temporary virtual environment and installs the pinned
graphql-core release from PyPI into it (the only network access). Use --venv DIR to reuse one.
"""
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
import tempfile
import time
import venv

VERSION = "1.0.0"
GRAPHQL_CORE = "3.2.14"
ROOT = Path(__file__).resolve().parent
BOB_EMAIL = "bob@example.invalid"

# name, token, query
CASES = [
    ("introspect", "demo-alice-token", '{ __schema { queryType { fields { name } } } }'),
    ("guess-typo", "demo-alice-token", '{ adminUsrRecord(id: "bob") { id } }'),
    ("call-by-name", "demo-alice-token", '{ adminUserRecord(id: "bob") { id email ssn_last4 } }'),
    ("own-profile", "demo-alice-token", '{ me { id email } }'),
    ("admin-call", "demo-admin-token", '{ adminUserRecord(id: "bob") { id email ssn_last4 } }'),
    ("anonymous-call", None, '{ adminUserRecord(id: "bob") { id } }'),
]
# configuration name -> (introspection, authz, expected outcome per case)
CONFIGS = {
    "A-vulnerable": ("on", "off", ["lists:adminUserRecord", "suggests:adminUserRecord", "disclosed:" + BOB_EMAIL,
                                   "own:alice@example.invalid", "disclosed:" + BOB_EMAIL, "401"]),
    "B-introspection-off": ("off", "off", ["blocked", "suggests:adminUserRecord", "disclosed:" + BOB_EMAIL,
                                           "own:alice@example.invalid", "disclosed:" + BOB_EMAIL, "401"]),
    "C-authz-only": ("on", "on", ["lists:adminUserRecord", "suggests:adminUserRecord", "forbidden",
                                  "own:alice@example.invalid", "disclosed:" + BOB_EMAIL, "401"]),
    "D-authz-and-introspection-off": ("off", "on", ["blocked", "suggests:adminUserRecord", "forbidden",
                                                    "own:alice@example.invalid", "disclosed:" + BOB_EMAIL, "401"]),
}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify(name, status, body):
    """Reduce one response to a short outcome label."""
    if status == 401:
        return "401"
    errors = body.get("errors") or []
    messages = " | ".join(e.get("message", "") for e in errors)
    data = body.get("data") or {}
    if name == "introspect":
        if "introspection has been disabled" in messages:
            return "blocked"
        fields = [f["name"] for f in data["__schema"]["queryType"]["fields"]]
        return "lists:adminUserRecord" if "adminUserRecord" in fields else "lists:none"
    if name == "guess-typo":
        return "suggests:adminUserRecord" if "Did you mean 'adminUserRecord'" in messages else "no suggestion"
    if name == "own-profile":
        return "own:" + data["me"]["email"]
    record = data.get("adminUserRecord")
    if record and record.get("email"):
        return "disclosed:" + record["email"]
    if any(e.get("extensions", {}).get("code") == "FORBIDDEN" for e in errors):
        return "forbidden"
    return "other"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    parser.add_argument("--venv", type=Path, help="existing venv with graphql-core %s installed" % GRAPHQL_CORE)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    tmp = tempfile.TemporaryDirectory(prefix="gql-venv-")
    try:
        if args.venv:
            python = str(args.venv / "bin" / "python")
        else:
            venv.EnvBuilder(with_pip=True).create(tmp.name)
            python = str(Path(tmp.name) / "bin" / "python")
            subprocess.run([python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check",
                            "graphql-core==" + GRAPHQL_CORE], check=True, timeout=300)
        evidence = {
            "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
            "method": "Real curl POST requests against four locally spawned fixture configurations",
            "scope": {"hosts": ["127.0.0.1"], "methods": ["POST"], "paths": ["/graphql"],
                      "data": "Three synthetic identities and records; all tokens are public demo values"},
            "versions": {"python": platform.python_version(), "os": platform.system(),
                         "architecture": platform.machine(), "graphql_core_pinned": GRAPHQL_CORE,
                         "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
            "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
            "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
            "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or Excession agent ran"},
            "cases": [], "failures": [],
        }
        commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                    "# These ephemeral ports refer to the recorded run and are no longer listening."]
        for config, (introspection, authz, expected) in CONFIGS.items():
            server_command = [python, "-u", str(ROOT / "fixture.py"), "--introspection", introspection,
                              "--authz", authz, "--port", "0"]
            process = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 10)
                if not ready:
                    raise RuntimeError("Fixture did not start within ten seconds")
                startup = json.loads(process.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                evidence["versions"]["graphql_core_installed"] = startup["graphql_core"]
                commands.append("# Server: python3 fixture.py --introspection %s --authz %s --port %s"
                                % (introspection, authz, startup["base_url"].rsplit(":", 1)[1]))
                for (name, token, query), want in zip(CASES, expected):
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
                               "--http1.1", "--connect-timeout", "1", "--max-time", "3", "--request", "POST",
                               "--header", "Content-Type: application/json"]
                    if token:
                        command += ["--header", "Authorization: Bearer " + token]
                    command += ["--data", json.dumps({"query": query}), startup["base_url"] + "/graphql"]
                    started = now()
                    tick = time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status = int(response.stdout.splitlines()[0].split()[1])
                    body = json.loads(response.stdout.split("\n\n", 1)[1])
                    outcome = classify(name, status, body)
                    raw_name = config + "-" + name + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    passed = response.returncode == 0 and outcome == want
                    case = {
                        "id": config + "/" + name, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "identity": token.removeprefix("demo-").removesuffix("-token") if token else None,
                        "query": query, "expected_outcome": want, "observed_outcome": outcome,
                        "observed_http_status": status, "observed_body": body,
                        "matches_demonstration": passed,
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    }
                    if name == "call-by-name":
                        case["secure_expected_outcome"] = "forbidden"
                        case["authorization_boundary_holds"] = outcome == "forbidden"
                    evidence["cases"].append(case)
                    if not passed:
                        evidence["failures"].append(config + "/" + name)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        tmp.cleanup()
    evidence["finished_at"] = now()
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 24
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
