#!/usr/bin/env python3
"""Check Strict-Transport-Security headers on fixture.py with real curl requests.

Starts the fixture in four modes on 127.0.0.1, records headers over plain HTTP and
over TLS (curl -k, self-signed certificate), parses them with a small RFC 6797
parser and compares the findings with the expected ones. No external targets.
"""
import argparse
import calendar
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

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
PRELOAD_MIN = 31536000  # hstspreload.org: max-age must be at least one year

# ---------------------------------------------------------------- parser


def parse_sts(value):
    """Parse one Strict-Transport-Security value per RFC 6797 section 6.1."""
    result = {"valid": False, "max_age": None, "include_subdomains": False, "preload": False, "problems": []}
    seen = set()
    for raw in value.split(";"):
        raw = raw.strip()
        if not raw:
            continue  # the grammar allows empty directives
        name, _, val = raw.partition("=")
        name, val = name.strip().lower(), val.strip()
        if name in seen:
            result["problems"].append("directive %s appears twice" % name)
            result["max_age"] = None
            return result
        seen.add(name)
        if name == "max-age":
            if len(val) >= 2 and val[0] == val[-1] == '"':
                val = val[1:-1]
            if not val.isdigit():
                result["problems"].append("max-age is not a number")
                return result
            result["max_age"] = int(val)
        elif name == "includesubdomains":
            result["include_subdomains"] = True
        elif name == "preload":
            result["preload"] = True
        # unrecognized directives are ignored (RFC 6797 section 6.1)
    if result["max_age"] is None:
        result["problems"].append("max-age is missing")
        return result
    result["valid"] = True
    return result


def audit(https_sts, http_sts, http_status):
    """Return finding codes for one site. https_sts and http_sts are lists of raw header values."""
    findings = []
    parsed = parse_sts(https_sts[0]) if https_sts else None
    if not https_sts:
        findings.append("missing-header")
    elif not parsed["valid"]:
        findings.append("malformed-header")
    else:
        if parsed["max_age"] < PRELOAD_MIN:
            findings.append("max-age-short")
        if not parsed["include_subdomains"]:
            findings.append("missing-includeSubDomains")
    if http_sts:
        findings.append("header-over-http")
    if http_status not in (301, 302, 307, 308):
        findings.append("http-serves-content")
    return findings


PARSER_CASES = [
    ("max-age=31536000; includeSubDomains", True, 31536000, True, False),
    ("max-age=31536000; includeSubDomains; preload", True, 31536000, True, True),
    ("Max-Age=31536000", True, 31536000, False, False),
    ('max-age="31536000"', True, 31536000, False, False),
    ("max-age=300", True, 300, False, False),
    ("max-age=0", True, 0, False, False),
    ("max-age=31536000;", True, 31536000, False, False),
    ("max-age=31536000; unknown=1", True, 31536000, False, False),
    ("includeSubDomains", False, None, True, False),
    ("max-age=abc", False, None, False, False),
    ("max-age=1; max-age=2", False, None, False, False),
]

EXPECTED = {
    "vulnerable": {"https_sts": None, "http_status": 200, "http_sts": None,
                   "findings": ["missing-header", "http-serves-content"],
                   "cache_https": False, "upgrade": False},
    "short": {"https_sts": "max-age=300", "http_status": 301, "http_sts": None,
              "findings": ["max-age-short", "missing-includeSubDomains"],
              "cache_https": True, "upgrade": True},
    "misplaced": {"https_sts": None, "http_status": 301, "http_sts": "max-age=31536000; includeSubDomains",
                  "findings": ["missing-header", "header-over-http"],
                  "cache_https": False, "upgrade": False},
    "fixed": {"https_sts": "max-age=31536000; includeSubDomains", "http_status": 301, "http_sts": None,
              "findings": [], "cache_https": True, "upgrade": True},
}

# ---------------------------------------------------------------- helpers


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def split_response(text):
    head = text.replace("\r\n", "\n").split("\n\n", 1)[0].splitlines()
    status = int(head[0].split()[1]) if head and head[0].startswith("HTTP/") else None
    headers = [tuple(line.split(":", 1)) for line in head[1:] if ":" in line]
    sts = [v.strip() for k, v in headers if k.strip().lower() == "strict-transport-security"]
    location = [v.strip() for k, v in headers if k.strip().lower() == "location"]
    return status, sts, location


def read_cache(path):
    """Return (entries, ttl_seconds) from a curl HSTS cache file."""
    entries = []
    if path.exists():
        for line in path.read_text().splitlines():
            if line and not line.startswith("#"):
                host, _, expiry = line.partition(" ")
                stamp = calendar.timegm(time.strptime(expiry.strip('"'), "%Y%m%d %H:%M:%S"))
                entries.append({"host": host, "expires_epoch": stamp})
    return entries


def curl(args, url, resolve):
    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
               "--insecure", "--connect-timeout", "1", "--max-time", "3", "--request", "GET",
               "--resolve", resolve] + args + [url]
    tick = time.time()
    done = subprocess.run(command, capture_output=True, text=True, timeout=6)
    return command, done, tick


# ---------------------------------------------------------------- main


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    try:
        args.output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        sys.exit("refusing to reuse existing output directory: " + str(args.output))
    out = args.output
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl subprocesses against fixture.py in four modes, plus a parser self-test",
        "scope": {"hosts": ["127.0.0.1 (name hsts.test pinned with curl --resolve)"], "methods": ["GET"],
                  "paths": ["/"], "data": "One synthetic page; self-signed certificate made at run time"},
        "limits": "curl -k skips certificate checks. curl --hsts is curl's own cache, not a browser.",
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0],
                     "openssl": subprocess.check_output(["openssl", "version"], text=True).strip()},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(out)),
        "agent_execution": {"executed": False, "note": "Scripted; no model or Excession agent ran"},
        "preload_min_max_age": PRELOAD_MIN,
        "cases": [], "parser_cases": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# The ports refer to the recorded run and are no longer listening."]

    def check(label, expected, observed):
        ok = expected == observed
        if not ok:
            evidence["failures"].append("%s: expected %r, observed %r" % (label, expected, observed))
        return ok

    try:
        for mode, want in EXPECTED.items():
            process = subprocess.Popen([sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 10)
                if not ready:
                    raise RuntimeError("Fixture did not start within ten seconds")
                startup = json.loads(process.stdout.readline())
                host, http_port, https_port = startup["host"], startup["http_port"], startup["https_port"]
                commands.append("# Server: python3 fixture.py --mode %s (http %d, https %d)" % (mode, http_port, https_port))
                cache_a, cache_b = out / (mode + "-curl-cache-after-https.txt"), out / (mode + "-curl-cache-after-http.txt")
                results = {}

                # 1. HTTPS request with a fresh curl HSTS cache
                cmd, done, tick = curl(["--hsts", str(cache_a)], "https://%s:%d/" % (host, https_port),
                                       "%s:%d:127.0.0.1" % (host, https_port))
                (out / (mode + "-https.http")).write_text(done.stdout)
                commands.append(shlex.join(cmd))
                status, sts, _ = split_response(done.stdout)
                results["https"] = (status, sts)
                entries = read_cache(cache_a)
                ttl = entries[0]["expires_epoch"] - round(tick) if entries else None

                # 2. Plain HTTP request with a different fresh cache
                cmd, done, _ = curl(["--hsts", str(cache_b)], "http://%s:%d/" % (host, http_port),
                                    "%s:%d:127.0.0.1" % (host, http_port))
                (out / (mode + "-http.http")).write_text(done.stdout)
                commands.append(shlex.join(cmd))
                http_status, http_sts, http_location = split_response(done.stdout)
                entries_b = read_cache(cache_b)

                # 3. Plain HTTP request with the cache that step 1 filled
                cmd, done3, _ = curl(["--verbose", "--hsts", str(cache_a)], "http://%s:%d/" % (host, http_port),
                                     "%s:%d:127.0.0.1" % (host, http_port))
                (out / (mode + "-http-with-cache.txt")).write_text(
                    "exit code: %d\nstdout bytes: %d\n--- stderr ---\n%s" % (done3.returncode, len(done3.stdout), done3.stderr))
                commands.append(shlex.join(cmd))
                upgraded = "Switched from HTTP to HTTPS due to HSTS" in done3.stderr

                findings = audit(sts, http_sts, http_status)
                observed = {
                    "https_status": status, "https_sts": sts[0] if sts else None,
                    "http_status": http_status, "http_sts": http_sts[0] if http_sts else None,
                    "http_location": http_location[0] if http_location else None,
                    "findings": findings,
                    "curl_cache_after_https_entries": [e["host"] for e in entries], "curl_cache_ttl_seconds": ttl,
                    "curl_cache_after_http_entries": [e["host"] for e in entries_b],
                    "curl_upgraded_http_request": upgraded,
                    "curl_upgrade_response_bytes": len(done3.stdout),
                }
                expected_case = {
                    "https_status": 200, "https_sts": want["https_sts"], "http_status": want["http_status"],
                    "http_sts": want["http_sts"], "findings": want["findings"],
                    "curl_cache_has_host": want["cache_https"], "curl_cache_after_http_empty": True,
                    "curl_upgraded_http_request": want["upgrade"],
                }
                parsed_https = parse_sts(sts[0]) if sts else None
                if want["cache_https"]:
                    ttl_ok = ttl is not None and abs(ttl - parsed_https["max_age"]) <= 5
                else:
                    ttl_ok = ttl is None
                checks = {
                    "https_status": check(mode + "/https_status", 200, status),
                    "https_sts": check(mode + "/https_sts", want["https_sts"], observed["https_sts"]),
                    "http_status": check(mode + "/http_status", want["http_status"], http_status),
                    "http_location": check(mode + "/http_location",
                                           None if want["http_status"] == 200 else "https://%s:%d/" % (host, https_port),
                                           observed["http_location"]),
                    "http_sts": check(mode + "/http_sts", want["http_sts"], observed["http_sts"]),
                    "findings": check(mode + "/findings", want["findings"], findings),
                    "curl_cache_has_host": check(mode + "/curl_cache", want["cache_https"], bool(entries)),
                    "curl_cache_ttl_matches_max_age": check(mode + "/curl_cache_ttl", True, ttl_ok),
                    "curl_cache_after_http_empty": check(mode + "/curl_cache_http", [], observed["curl_cache_after_http_entries"]),
                    "curl_upgraded_http_request": check(mode + "/curl_upgrade", want["upgrade"], upgraded),
                    "upgrade_sent_no_http_response": check(mode + "/upgrade_bytes", want["upgrade"], len(done3.stdout) == 0),
                }
                evidence["cases"].append({
                    "id": mode, "server": startup, "expected": expected_case, "observed": observed,
                    "checks": checks, "matches": all(checks.values()),
                    "files": [mode + "-https.http", mode + "-http.http", mode + "-http-with-cache.txt",
                              cache_a.name, cache_b.name],
                })
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for value, valid, max_age, subdomains, preload in PARSER_CASES:
            got = parse_sts(value)
            ok = (got["valid"], got["max_age"], got["include_subdomains"], got["preload"]) == (valid, max_age, subdomains, preload)
            if not ok:
                evidence["failures"].append("parser: " + value)
            evidence["parser_cases"].append({"header": value, "expected_valid": valid, "observed": got, "matches": ok})
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    evidence["finished_at"] = now()
    total = sum(len(c["checks"]) for c in evidence["cases"]) + len(evidence["parser_cases"])
    evidence["check_count"] = total
    evidence["all_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == len(EXPECTED)
    (out / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (out / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": total, "passed": evidence["all_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(out / "results.json")}))
    return 0 if evidence["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
