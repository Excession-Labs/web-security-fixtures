#!/usr/bin/env python3
"""Run 12 PKCE flows (six per mode) with real curl requests against fixture.py."""
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
from urllib.parse import parse_qs, quote, urlencode, urlsplit

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from fixture import CLIENT_ID, REDIRECT_URI, make_pkce, s256  # noqa: E402

VERSION = "1.0.0"
# RFC 7636 Appendix B test vector.
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

ISSUED = "token_issued"
DENIED = "token_denied:invalid_grant"
AUTHZ_ERROR = "authorize_error:invalid_request"

# name, how the client starts, what the redeeming party sends, secure outcome, outcome in vulnerable mode
CASES = [
    ("legit-s256", "s256", "verifier", ISSUED, ISSUED),
    ("intercept-no-verifier", "s256", "none", DENIED, ISSUED),
    ("intercept-guessed-verifier", "s256", "guess", DENIED, ISSUED),
    ("intercept-challenge-as-verifier", "s256", "challenge", DENIED, ISSUED),
    ("legacy-client-no-pkce", "none", "none", AUTHZ_ERROR, ISSUED),
    ("plain-method", "plain", "verifier", AUTHZ_ERROR, ISSUED),
]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def curl(command):
    base = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include",
            "--http1.1", "--connect-timeout", "1", "--max-time", "3"]
    full = base + command
    response = subprocess.run(full, capture_output=True, text=True, timeout=5)
    head, _, body = response.stdout.partition("\n\n")
    lines = head.splitlines()
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    return full, response, int(lines[0].split()[1]), headers, body


def run_case(base_url, mode, name, start, redeem, secure, demo_outcome, out, commands):
    verifier, challenge = make_pkce()
    state = "demo-state-" + name
    params = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "state": state}
    if start == "s256":
        params.update(code_challenge=challenge, code_challenge_method="S256")
    elif start == "plain":
        # plain: the challenge equals the verifier (RFC 7636 section 4.2)
        params.update(code_challenge=verifier, code_challenge_method="plain")
    case = {"id": mode + "/" + name, "started_at": now(), "client_start": start, "redeemer_sends": redeem,
            "server": base_url, "steps": []}
    tick = time.monotonic()
    url = base_url + "/authorize?" + urlencode(params, quote_via=quote)
    steps = []

    def record(step, command, status, headers, body, response):
        raw = mode + "-" + name + "-" + step + ".http"
        (out / raw).write_text(response.stdout)
        commands.append(shlex.join(command))
        steps.append({"step": step, "command": command, "curl_exit_code": response.returncode,
                      "stderr": response.stderr, "status": status, "response_file": raw,
                      "response_sha256": digest(out / raw)})

    command, response, status, headers, body = curl(["--request", "GET", url])
    record("authorize", command, status, headers, body, response)
    location = urlsplit(headers.get("location", ""))
    returned = {k: v[0] for k, v in parse_qs(location.query).items()}
    case["authorize"] = {"status": status, "location_scheme": location.scheme,
                         "returned_params": sorted(returned),
                         "error": returned.get("error"), "state_echoed": returned.get("state") == state}
    outcome = None
    if "code" in returned:
        form = {"grant_type": "authorization_code", "code": returned["code"],
                "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI}
        if redeem == "verifier":
            form["code_verifier"] = verifier
        elif redeem == "guess":
            form["code_verifier"] = make_pkce()[0]
        elif redeem == "challenge":
            form["code_verifier"] = challenge
        command, response, status, headers, body = curl(["--request", "POST", "--data", urlencode(form),
                                                         base_url + "/token"])
        record("token", command, status, headers, body, response)
        payload = json.loads(body)
        case["token"] = {"status": status, "body_keys": sorted(payload), "error": payload.get("error")}
        if status == 200 and payload.get("access_token", "").startswith("demo-access-"):
            outcome = ISSUED
        elif status == 400 and payload.get("error") == "invalid_grant":
            outcome = DENIED
        else:
            outcome = "unexpected:" + str(status)
    elif returned.get("error") == "invalid_request":
        outcome = AUTHZ_ERROR
    else:
        outcome = "unexpected-authorize:" + str(status)
    expected = demo_outcome if mode == "vulnerable" else secure
    case.update({
        "steps": steps, "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
        "secure_expected_outcome": secure, "demonstration_expected_outcome": expected,
        "observed_outcome": outcome, "matches_demonstration": outcome == expected
        and all(s["curl_exit_code"] == 0 for s in steps),
        "boundary_holds": outcome == secure,
    })
    return case


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against two locally spawned fixture modes",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["GET", "POST"], "paths": ["/authorize", "/token"],
                  "data": "One synthetic public client; verifiers, codes and tokens are one-time demo values"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "HTTP verification was scripted; no model or Excession agent ran"},
        "rfc7636_appendix_b_vector": {"verifier": RFC_VERIFIER, "expected_challenge": RFC_CHALLENGE,
                                      "computed_challenge": s256(RFC_VERIFIER),
                                      "matches": s256(RFC_VERIFIER) == RFC_CHALLENGE},
        "cases": [], "failures": [],
    }
    if not evidence["rfc7636_appendix_b_vector"]["matches"]:
        evidence["failures"].append("rfc7636-appendix-b-vector")
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening.",
                "# Each flow uses its own authorization code, which the server consumes on first use."]
    try:
        for mode in ("vulnerable", "fixed"):
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
                for name, start, redeem, secure, demo in CASES:
                    commands.append("# Flow: " + name)
                    case = run_case(startup["base_url"], mode, name, start, redeem, secure, demo,
                                    args.output, commands)
                    evidence["cases"].append(case)
                    if not case["matches_demonstration"]:
                        evidence["failures"].append(case["id"])
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
