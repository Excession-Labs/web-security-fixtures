#!/usr/bin/env python3
"""Record Set-Cookie headers from fixture.py with curl, audit each attribute, model cookie rules."""
import argparse
import datetime
import email.message
import hashlib
import json
import platform
import select
import shlex
import subprocess
import sys
import time
import urllib.request
from http.cookiejar import CookieJar
from http.cookies import SimpleCookie
from pathlib import Path

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
APP_HOST = "app.example.test"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_set_cookie(header):
    parts = [p.strip() for p in header.split(";")]
    name, _, value = parts[0].partition("=")
    attrs = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        attrs[key.strip().lower()] = val.strip()
    return {"name": name, "value": value, "attrs": attrs}


def prefix_problem(cookie):
    """Return why a browser would reject a __Host- or __Secure- cookie, or None (6265bis draft rules)."""
    name, attrs = cookie["name"], cookie["attrs"]
    if name.startswith(("__Secure-", "__Host-")) and "secure" not in attrs:
        return "prefix needs Secure"
    if name.startswith("__Host-"):
        if "domain" in attrs:
            return "__Host- forbids Domain"
        if attrs.get("path") != "/":
            return "__Host- needs Path=/"
    return None


def audit(header):
    cookie = parse_set_cookie(header)
    attrs = cookie["attrs"]
    problems = []
    if "httponly" not in attrs:
        problems.append("missing HttpOnly")
    if "secure" not in attrs:
        problems.append("missing Secure")
    if "samesite" not in attrs:
        problems.append("SameSite not set")
    if "domain" in attrs:
        problems.append("Domain=" + attrs["domain"] + " shares cookie with subdomains")
    if not cookie["name"].startswith("__Host-"):
        problems.append("no __Host- prefix")
    return {"name": cookie["name"], "attributes": attrs, "problems": problems,
            "prefix_rejection": prefix_problem(cookie)}


def jar_sends(headers, set_url, request_url):
    """Ask Python's http.cookiejar (de-facto Netscape cookie rules, not a browser) whether it would send the cookie."""
    message = email.message.Message()
    for header in headers:
        message["Set-Cookie"] = header
    response = type("Response", (), {"info": lambda self: message})()
    jar = CookieJar()
    jar.extract_cookies(response, urllib.request.Request(set_url))
    request = urllib.request.Request(request_url)
    jar.add_cookie_header(request)
    return request.get_header("Cookie")


def script_visible(headers):
    """Names a script could read if a browser applied RFC 6265 section 4.1.2.6. Python has no script API."""
    names = []
    for header in headers:
        jar = SimpleCookie()
        jar.load(header)
        names += [name for name, morsel in jar.items() if not morsel["httponly"]]
    return names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against two locally spawned fixture modes, then header audit and Python cookie-rule models",
        "scope": {"hosts": ["127.0.0.1 (curl --resolve maps " + APP_HOST + " to it)"],
                  "methods": ["GET", "POST"], "paths": ["/login", "/account"],
                  "data": "One synthetic user and a random in-memory session id; the password is a public demo value"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "Verification was scripted; no model or Excession agent ran"},
        "cases": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# These ephemeral ports refer to the recorded run and are no longer listening."]

    def record(case_id, kind, expected, observed, extra=None):
        ok = expected == observed
        entry = {"id": case_id, "kind": kind, "expected": expected, "observed": observed, "matches": ok}
        entry.update(extra or {})
        evidence["cases"].append(entry)
        if not ok:
            evidence["failures"].append(case_id)

    expected_problems = {
        "vulnerable": ["missing HttpOnly", "missing Secure", "SameSite not set",
                       "Domain=example.test shares cookie with subdomains", "no __Host- prefix"],
        "fixed": [],
    }
    cookie_name = {"vulnerable": "sid", "fixed": "__Host-sid"}
    try:
        for mode in ("vulnerable", "fixed"):
            process = subprocess.Popen([sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                port = startup["base_url"].rsplit(":", 1)[1]
                base = "http://" + APP_HOST + ":" + port
                commands.append("# Server: python3 fixture.py --mode " + mode + " --port " + port)
                state = {}

                def run(name, method, path, expected_status, expected_body, cookie=None, form=None):
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
                               "--connect-timeout", "1", "--max-time", "3",
                               "--resolve", APP_HOST + ":" + port + ":127.0.0.1", "--request", method]
                    if cookie:
                        command += ["--header", "Cookie: " + cookie]
                    if form:
                        command += ["--data", form]
                    command.append(base + path)
                    started, tick = now(), time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    head, _, body = response.stdout.partition("\n\n")
                    lines = head.splitlines()
                    status = int(lines[0].split()[1])
                    set_cookies = [l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("set-cookie:")]
                    raw_name = mode + "-" + name + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    observed = {"status": status, "body": json.loads(body), "set_cookie_count": len(set_cookies)}
                    expected = {"status": expected_status, "body": expected_body,
                                "set_cookie_count": 1 if name == "login-ok" else 0}
                    record(mode + "/" + name, "curl", expected, observed, {
                        "started_at": started, "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "server": startup, "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "set_cookie_headers": set_cookies,
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name)})
                    return set_cookies

                headers = run("login-ok", "POST", "/login", 200, {"ok": True, "user": "alice"},
                              form="username=alice&password=demo-password")
                bad = run("login-bad-password", "POST", "/login", 401, {"error": "invalid_credentials"},
                          form="username=alice&password=wrong")
                value = parse_set_cookie(headers[0])["value"] if headers else ""
                name = cookie_name[mode]
                run("account-with-session", "GET", "/account", 200, {"user": "alice"}, cookie=name + "=" + value)
                run("account-no-cookie", "GET", "/account", 401, {"error": "authentication_required"})
                run("account-forged-session", "GET", "/account", 401, {"error": "authentication_required"},
                    cookie=name + "=" + "0" * 32)

                audited = audit(headers[0])
                record(mode + "/audit", "audit", {"problems": expected_problems[mode]},
                       {"problems": audited["problems"]},
                       {"set_cookie_header_with_value_masked": headers[0].replace(value, "<session-id>"),
                        "attributes": audited["attributes"]})
                simple = SimpleCookie()
                simple.load(headers[0])
                morsel = simple[name]
                record(mode + "/parser-crosscheck", "audit",
                       {"httponly": "httponly" in audited["attributes"], "secure": "secure" in audited["attributes"],
                        "samesite": audited["attributes"].get("samesite", ""),
                        "domain": audited["attributes"].get("domain", "")},
                       {"httponly": bool(morsel["httponly"]), "secure": bool(morsel["secure"]),
                        "samesite": morsel["samesite"], "domain": morsel["domain"]})
                http_url = base + "/account"
                sends = {
                    "same-host-http": jar_sends(headers, base + "/login", http_url),
                    "same-host-https": jar_sends(headers, base + "/login", "https://" + APP_HOST + "/account"),
                    "sibling-host-https": jar_sends(headers, base + "/login", "https://other.example.test/account"),
                    "unrelated-host-https": jar_sends(headers, base + "/login", "https://unrelated.test/account"),
                }
                want = {"vulnerable": {"same-host-http": True, "same-host-https": True,
                                       "sibling-host-https": True, "unrelated-host-https": False},
                        "fixed": {"same-host-http": False, "same-host-https": True,
                                  "sibling-host-https": False, "unrelated-host-https": False}}[mode]
                record(mode + "/cookiejar-model", "model", want, {k: v is not None for k, v in sends.items()},
                       {"note": "Python http.cookiejar applies Domain and Secure send rules (Netscape-style, per the Python docs); it is not a browser",
                        "cookie_header_masked": {k: (v.replace(value, "<session-id>") if v else None)
                                                 for k, v in sends.items()}})
                record(mode + "/script-visible-model", "model",
                       [] if mode == "fixed" else ["sid"], script_visible(headers),
                       {"note": "Our model of RFC 6265 section 4.1.2.6; only a browser enforces document.cookie"})
                if bad:
                    evidence["failures"].append(mode + "/login-bad-password set a cookie")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        vectors = [
            ("__Host-id=1; Secure", "__Host- needs Path=/"),
            ("__Host-id=1; Secure; Path=/; Domain=example.test", "__Host- forbids Domain"),
            ("__Secure-id=1", "prefix needs Secure"),
            ("__Host-id=1; Secure; Path=/", None),
        ]
        record("audit-selftest", "selftest", [v[1] for v in vectors],
               [prefix_problem(parse_set_cookie(v[0])) for v in vectors],
               {"vectors": [v[0] for v in vectors], "note": "Headers modelled on the MDN Set-Cookie prefix examples"})
        invalid = "__Host-x=1; Domain=example.test; Path=/"
        record("cookiejar-ignores-prefix", "model", {"sent_to_sibling": True, "audit_rejects": True},
               {"sent_to_sibling": jar_sends([invalid], "https://app.example.test/", "https://other.example.test/") is not None,
                "audit_rejects": prefix_problem(parse_set_cookie(invalid)) is not None},
               {"note": "http.cookiejar keeps a __Host- cookie that has a Domain attribute; only the audit and a prefix-aware browser reject it"})
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    evidence["finished_at"] = now()
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == 20
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
