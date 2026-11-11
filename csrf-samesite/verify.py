#!/usr/bin/env python3
"""Run curl (and optionally real Chromium) against fixture.py. Loopback only."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import shlex
import subprocess
import sys
import urllib.request

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
NEW_EMAIL = "alice-new@example.test"
ATTACK_EMAIL = "attacker@evil.test"
START = "alice@example.test"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def start(role, mode, target_port=0):
    cmd = [sys.executable, "-u", str(ROOT / "fixture.py"), "--role", role, "--mode", mode, "--port", "0"]
    if target_port:
        cmd += ["--target-port", str(target_port)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([proc.stdout], [], [], 5)
    if not ready:
        proc.kill()
        raise RuntimeError("server did not start")
    return proc, json.loads(proc.stdout.readline())["port"]


def control(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=3) as r:
        return json.loads(r.read())


def curl(args, out_file):
    base = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
            "--connect-timeout", "1", "--max-time", "3", "--output", str(out_file)]
    full = base + args
    subprocess.run(full, check=True)
    text = out_file.read_text()
    status = int(text.split(" ", 2)[1])
    return status, text, "curl " + " ".join(shlex.quote(a) for a in full[1:] if a not in ("--output", str(out_file)))


def run_curl_cases(mode, port, outdir, commands):
    target = f"http://127.0.0.1:{port}"
    evil = "http://localhost:9"  # an Origin value for a page on another site; nothing listens there
    cases = []
    # name, method, path, origin, send_cookie, token ('page' = real, 'wrong', None), body email,
    # expected for the secure policy (status, email after), expected in vulnerable mode
    spec = [
        ("view-account", "GET", "/account", None, True, None, None, (200, START), (200, START)),
        ("legit-post", "POST", "/account/email", target, True, "page", NEW_EMAIL, (200, NEW_EMAIL), (200, NEW_EMAIL)),
        ("forged-post-no-token", "POST", "/account/email", evil, True, None, ATTACK_EMAIL, (403, START), (200, ATTACK_EMAIL)),
        ("forged-post-stolen-token", "POST", "/account/email", evil, True, "page", ATTACK_EMAIL, (403, START), (200, ATTACK_EMAIL)),
        ("same-origin-no-token", "POST", "/account/email", target, True, None, ATTACK_EMAIL, (403, START), (200, ATTACK_EMAIL)),
        ("same-origin-wrong-token", "POST", "/account/email", target, True, "wrong", ATTACK_EMAIL, (403, START), (200, ATTACK_EMAIL)),
        ("forged-post-no-cookie", "POST", "/account/email", evil, False, None, ATTACK_EMAIL, (401, START), (401, START)),
        ("forged-get", "GET", "/account/email/change?email=" + ATTACK_EMAIL, None, True, None, None, (405, START), (200, ATTACK_EMAIL)),
    ]
    for name, method, path, origin, with_cookie, token, email, secure, vuln in spec:
        control(port, "/_reset")
        status, login, cmd = curl([target + "/login?user=alice&samesite=none"], outdir / f"{mode}-login-{name}.http")
        sid = re.search(r"sid=([0-9a-f]+)", login).group(1)
        csrf = ""
        if token == "page":
            _, page, _ = curl(["--header", f"Cookie: sid={sid}", target + "/account"], outdir / f"{mode}-page-{name}.http")
            m = re.search(r'name="csrf_token" value="([0-9a-f]+)"', page)
            csrf = m.group(1) if m else "no-token-field-in-vulnerable-page"
        elif token == "wrong":
            csrf = "0" * 32
        args = ["--request", method]
        if with_cookie:
            args += ["--header", f"Cookie: sid={sid}"]
        if origin:
            args += ["--header", f"Origin: {origin}"]
        if method == "POST":
            body = "email=" + email + (("&csrf_token=" + csrf) if token else "")
            args += ["--header", "Content-Type: application/x-www-form-urlencoded", "--data", body]
        args.append(target + path)
        status, text, cmd = curl(args, outdir / f"{mode}-{name}.http")
        email_after = control(port, "/_state")["email"]
        expected_here = secure if mode == "fixed" else vuln
        cases.append({
            "mode": mode, "case": name, "method": method, "path": path, "origin_header": origin,
            "cookie_sent": with_cookie, "token": "valid" if token == "page" else token,
            "secure_expected": {"status": secure[0], "email_after": secure[1]},
            "expected_in_this_mode": {"status": expected_here[0], "email_after": expected_here[1]},
            "observed": {"status": status, "email_after": email_after},
            "matches_expectation": (status, email_after) == expected_here,
            "boundary_holds": (status, email_after) == secure,
            "response_file": f"{mode}-{name}.http",
            "response_sha256": hashlib.sha256((outdir / f"{mode}-{name}.http").read_bytes()).hexdigest(),
        })
        commands.append(f"# {mode} / {name}\n{cmd}")
    return cases


def run_browser(mode, tport, aport, node_modules, wait):
    env = dict(os.environ, NODE_PATH=str(node_modules))
    r = subprocess.run(["node", str(ROOT / "browser_test.cjs"), mode, str(tport), str(aport), str(wait)],
                       capture_output=True, text=True, timeout=wait + 120, env=env)
    if r.returncode != 0:
        raise RuntimeError("browser test failed: " + r.stderr[-500:])
    return json.loads(r.stdout)


# What the MDN Set-Cookie page documents. Cookie sent? for cross-site POST form / cross-site top-level GET.
DOCUMENTED = {"none": (True, True), "lax": (False, True), "strict": (False, False)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    ap.add_argument("--node-modules", type=Path, help="directory that contains playwright; enables the browser test")
    ap.add_argument("--wait-seconds", type=int, default=0, help="also test a Lax-by-default cookie that is this many seconds old (use 125)")
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    curl_version = subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses, and real Chromium through Playwright when --node-modules is given",
        "scope": {"hosts": ["127.0.0.1", "localhost (attacker page only)"], "data": "one synthetic user, synthetic email addresses"},
        "versions": {"python": platform.python_version(), "os": platform.system(), "architecture": platform.machine(), "curl": curl_version},
        "sha256": {n: digest(ROOT / n) for n in ("fixture.py", "verify.py", "browser_test.cjs")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "scripted; no model or agent ran"},
        "curl_cases": [], "browser": {}, "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands. Ports belong to the finished run; use verify.py for fresh servers."]
    procs = []
    try:
        for mode in ("vulnerable", "fixed"):
            tproc, tport = start("target", mode)
            procs.append(tproc)
            commands.append(f"# Server: python3 fixture.py --role target --mode {mode} --port {tport}")
            evidence["curl_cases"] += run_curl_cases(mode, tport, args.output, commands)
            if args.node_modules:
                aproc, aport = start("attacker", mode, tport)
                procs.append(aproc)
                control(tport, "/_reset")
                result = run_browser(mode, tport, aport, args.node_modules, args.wait_seconds)
                result.update({"target_origin": f"http://127.0.0.1:{tport}", "attacker_origin": f"http://localhost:{aport}"})
                evidence["browser"][mode] = result
                evidence["versions"]["browser"] = result["browser"]
                aproc.terminate()
            tproc.terminate()
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
            p.wait(timeout=3)
    for c in evidence["curl_cases"]:
        if not c["matches_expectation"]:
            evidence["failures"].append(f"curl {c['mode']}/{c['case']}")
    if not args.node_modules:
        evidence["browser"] = {"skipped": "no --node-modules given"}
    else:
        for mode, res in evidence["browser"].items():
            for c in res["cases"]:
                if mode == "vulnerable":
                    post_exp, get_exp = DOCUMENTED.get(c["requested_samesite"], (None, None))
                    if c.get("cookie_age_seconds", 0) > 120:
                        post_exp = False  # past the two-minute window MDN describes
                    exp = post_exp if c["attack"] == "post" else get_exp
                    seen = c["request_seen"]["cookie_sent"] if c["request_seen"] else None
                    c["documented_cookie_sent"] = exp
                    c["observed_cookie_sent"] = seen
                    c["email_changed_by_attacker"] = c["email_after"] == ATTACK_EMAIL
                    c["matches_documented"] = None if exp is None else exp == seen
                else:
                    c["email_changed_by_attacker"] = c["email_after"] == ATTACK_EMAIL
                    if c["attack"] == "legitimate-form":
                        if c["email_after"] != NEW_EMAIL:
                            evidence["failures"].append("browser fixed legitimate-form")
                    elif c["email_changed_by_attacker"]:
                        evidence["failures"].append(f"browser fixed {c['attack']}")
    evidence["finished_at"] = now()
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    summary = {"checks": len(evidence["curl_cases"]), "passed": not evidence["failures"], "failures": evidence["failures"]}
    print(json.dumps(summary))
    print("evidence:", args.output)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
