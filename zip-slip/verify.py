#!/usr/bin/env python3
"""Upload eight archives to fixture.py in two modes, then run the same archives through
Python's own extraction. Everything happens inside a temporary folder that is removed at the end."""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import select
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import warnings
import zipfile

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
PAYLOAD = b"synthetic marker, written by the zip-slip fixture\n"

# id, archive kind, members (type, name, link target), class
CASES = [
    ("zip-benign", "zip", [("dir", "docs/", None), ("file", "docs/readme.txt", None)], "ok"),
    ("zip-inside-dotdot", "zip", [("file", "docs/../notes.txt", None)], "ok"),
    ("zip-dotdot", "zip", [("file", "../outside/pwned-zip-dotdot.txt", None)], "escape"),
    ("zip-absolute", "zip", [("file", "{outside}/pwned-zip-absolute.txt", None)], "escape"),
    ("tar-benign", "tar", [("dir", "reports", None), ("file", "reports/summary.txt", None)], "ok"),
    ("tar-dotdot", "tar", [("file", "../outside/pwned-tar-dotdot.txt", None)], "escape"),
    ("tar-absolute", "tar", [("file", "{outside}/pwned-tar-absolute.txt", None)], "escape"),
    ("tar-symlink", "tar", [("link", "link", "../outside"), ("file", "link/pwned-tar-symlink.txt", None)], "escape"),
]
# member the fixed server must name in its refusal, and the file that escapes in vulnerable mode
REFUSED = {"zip-dotdot": "../outside/pwned-zip-dotdot.txt", "zip-absolute": "{outside}/pwned-zip-absolute.txt",
           "tar-dotdot": "../outside/pwned-tar-dotdot.txt", "tar-absolute": "{outside}/pwned-tar-absolute.txt",
           "tar-symlink": "link -> ../outside"}
LANDS = {"zip-dotdot": "outside/pwned-zip-dotdot.txt", "zip-absolute": "outside/pwned-zip-absolute.txt",
         "tar-dotdot": "outside/pwned-tar-dotdot.txt", "tar-absolute": "outside/pwned-tar-absolute.txt",
         "tar-symlink": "outside/pwned-tar-symlink.txt"}
OK_FILES = {"zip-benign": "uploads/docs/readme.txt", "zip-inside-dotdot": "uploads/notes.txt",
            "tar-benign": "uploads/reports/summary.txt"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(kind, members, outside):
    names = [(t, n.replace("{outside}", outside), l) for t, n, l in members]
    buf = io.BytesIO()
    if kind == "zip":
        with zipfile.ZipFile(buf, "w") as zf:
            for t, n, _l in names:
                zf.writestr(n, b"" if t == "dir" else PAYLOAD)
    else:
        with tarfile.open(fileobj=buf, mode="w:") as tf:
            for t, n, l in names:
                info = tarfile.TarInfo(n)
                data = b""
                if t == "dir":
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                elif t == "link":
                    info.type, info.linkname, info.mode = tarfile.SYMTYPE, l, 0o777
                else:
                    info.size, info.mode = len(PAYLOAD), 0o644
                    data = PAYLOAD
                tf.addfile(info, io.BytesIO(data) if data else None)
    return buf.getvalue(), [n for _t, n, _l in names]


def snapshot(top):
    seen = {}
    for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, top)
            seen[rel] = "link" if os.path.islink(full) else ("dir" if os.path.isdir(full) else "file")
    return seen


def stdlib_run(base, number, archive_id, kind, members, label, runner):
    sandbox = Path(base) / ("stdlib-%02d" % number)
    (sandbox / "uploads").mkdir(parents=True)
    (sandbox / "outside").mkdir()
    sandbox_real = os.path.realpath(sandbox)
    data, names = build(kind, members, sandbox_real + "/outside")
    before = snapshot(base)
    outcome, error, caught = "extracted", None, []
    with warnings.catch_warnings(record=True) as seen_warnings:
        warnings.simplefilter("always")
        try:
            runner(data, str(sandbox / "uploads"))
        except Exception as exc:  # the exception type is the evidence
            refusals = ("OutsideDestinationError", "AbsolutePathError", "LinkOutsideDestinationError", "AbsoluteLinkError")
            outcome = "refused" if type(exc).__name__ in refusals else "error"
            error = type(exc).__name__ + ": " + str(exc).replace(sandbox_real, "<sandbox>")
        caught = [w.category.__name__ + ": " + str(w.message)[:120] for w in seen_warnings]
    after = snapshot(base)
    prefix = sandbox.name + os.sep
    new = sorted(r[len(prefix):] for r, k in after.items() if r not in before and r.startswith(prefix) and k != "dir")
    escaped = [r for r in new if not r.startswith("uploads" + os.sep)]
    return {"archive": archive_id, "method": label, "outcome": outcome, "exception": error,
            "new_files": new, "escaped_files": escaped, "warnings": caught}


def tar_runner(**kwargs):
    def run(data, dest):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            tf.extractall(dest, **kwargs)
    return run


def zip_runner(data, dest):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    base = os.path.realpath(tempfile.mkdtemp(prefix="zipslip-run-"))
    has_filters = hasattr(tarfile, "data_filter")
    evidence = {
        "schema_version": 1, "fixture_version": VERSION, "started_at": now(),
        "method": "Real curl uploads to two locally spawned fixture modes, then the same archives through Python's own extraction",
        "scope": {"hosts": ["127.0.0.1"], "methods": ["POST"], "paths": ["/upload/zip", "/upload/tar"],
                  "writes": "only inside a temporary folder that verify.py creates and removes",
                  "data": "Synthetic marker files only"},
        "versions": {"python": platform.python_version(), "os": platform.system(), "architecture": platform.machine(),
                     "curl": subprocess.check_output(["curl", "--version"], text=True).splitlines()[0],
                     "tarfile_has_filters": has_filters,
                     "tarfile_default_filter": str(getattr(tarfile.TarFile, "extraction_filter", "n/a"))},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "Scripted checks only; no model or agent ran"},
        "cases": [], "stdlib": [], "failures": [],
    }
    commands = ["#!/bin/sh", "# Recorded curl commands; rerun verify.py to start fresh fixture servers.",
                "# The ports and temporary folders refer to the recorded run and no longer exist."]
    archive_dir = Path(base) / "archives"
    archive_dir.mkdir()
    try:
        for mode in ("vulnerable", "fixed"):
            root = Path(base) / ("zipslip-" + mode)
            root.mkdir()
            outside = os.path.realpath(root) + "/outside"
            server_command = [sys.executable, "-u", str(ROOT / "fixture.py"), "--mode", mode, "--root", str(root), "--port", "0"]
            process = subprocess.Popen(server_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready:
                    raise RuntimeError("Fixture did not start within five seconds")
                startup = json.loads(process.stdout.readline())
                if not startup["base_url"].startswith("http://127.0.0.1:"):
                    raise RuntimeError("Fixture returned a non-loopback address")
                commands.append("# Server: python3 fixture.py --mode " + mode + " --root <temporary zipslip-" + mode + " folder> --port " + startup["base_url"].rsplit(":", 1)[1])
                for case_id, kind, members, klass in CASES:
                    data, names = build(kind, members, outside)
                    archive = archive_dir / (mode + "-" + case_id + "." + kind)
                    archive.write_bytes(data)
                    before = snapshot(base)
                    command = ["curl", "--noproxy", "*", "--silent", "--show-error", "--include", "--http1.1",
                               "--connect-timeout", "1", "--max-time", "3", "--request", "POST",
                               "--header", "Content-Type: application/octet-stream",
                               "--data-binary", "@" + str(archive), startup["base_url"] + "/upload/" + kind]
                    started, tick = now(), time.monotonic()
                    response = subprocess.run(command, capture_output=True, text=True, timeout=5)
                    status = int(response.stdout.splitlines()[0].split()[1])
                    body = json.loads(response.stdout.split("\n\n", 1)[1])
                    after = snapshot(base)
                    mine = "zipslip-" + mode + os.sep
                    new = sorted(r for r in after if r not in before and after[r] != "dir")
                    new_rel = [r[len(mine):] for r in new if r.startswith(mine)]
                    stray = [r for r in new if not r.startswith(mine) and not r.startswith("archives" + os.sep)]
                    escaped = [r for r in new_rel if not r.startswith("uploads" + os.sep)]
                    if klass == "ok":
                        want_status, want_files, want_escape = 200, [OK_FILES[case_id]], []
                        want_body = {"extracted": [n for _t, n, _l in members], "status": "ok"}
                    elif mode == "vulnerable":
                        want_status, want_files, want_escape = 200, [LANDS[case_id]], [LANDS[case_id]]
                        want_body = {"extracted": [n.replace("{outside}", outside) for _t, n, _l in members], "status": "ok"}
                        if case_id == "tar-symlink":
                            want_files = sorted(["uploads/link", LANDS[case_id]])
                    else:
                        want_status, want_files, want_escape = 400, [], []
                        want_body = {"error": "member_outside_destination", "member": REFUSED[case_id].replace("{outside}", outside)}
                    landed = ""
                    if want_escape and escaped:
                        landed = (Path(base) / ("zipslip-" + mode) / escaped[0]).read_bytes().decode()
                    passed = (response.returncode == 0 and status == want_status and body == want_body
                              and new_rel == sorted(want_files) and escaped == want_escape and not stray
                              and (not want_escape or landed == PAYLOAD.decode()))
                    raw_name = mode + "-" + case_id + ".http"
                    (args.output / raw_name).write_text(response.stdout)
                    commands.append(shlex.join(command))
                    secure_status = 200 if klass == "ok" else 400
                    evidence["cases"].append({
                        "id": mode + "/" + case_id, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3), "server": startup,
                        "archive_kind": kind, "archive_members": [n for _t, n, _l in
                                                                  [(t, nm.replace("{outside}", outside), l) for t, nm, l in members]],
                        "archive_sha256": digest(archive), "command": command, "curl_exit_code": response.returncode,
                        "stderr": response.stderr, "secure_expected_status": secure_status,
                        "demonstration_expected_status": want_status, "observed_status": status, "observed_body": body,
                        "new_files": new_rel, "escaped_files": escaped, "stray_files": stray,
                        "boundary_holds": status == secure_status and not escaped,
                        "matches_demonstration": passed,
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    })
                    if not passed:
                        evidence["failures"].append(mode + "/" + case_id)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        number = 0
        for case_id, kind, members, klass in CASES:
            methods = [("zipfile.extractall", zip_runner)] if kind == "zip" else [
                ("tarfile.extractall (no filter argument)", tar_runner())]
            if kind == "tar" and has_filters:
                methods += [("tarfile.extractall(filter='data')", tar_runner(filter="data")),
                            ("tarfile.extractall(filter='fully_trusted')", tar_runner(filter="fully_trusted"))]
            for label, runner in methods:
                number += 1
                row = stdlib_run(base, number, case_id, kind, members, label, runner)
                row["class"] = klass
                evidence["stdlib"].append(row)
                if klass == "escape":
                    must_hold = ("fully_trusted" not in label) and ("no filter" not in label or sys.version_info >= (3, 14))
                    if "fully_trusted" in label and not row["escaped_files"]:
                        evidence["failures"].append("stdlib " + case_id + " " + label + ": expected an escape")
                    if must_hold and row["escaped_files"]:
                        evidence["failures"].append("stdlib " + case_id + " " + label + ": unexpected escape")
                elif row["outcome"] != "extracted" or not row["new_files"]:
                    evidence["failures"].append("stdlib " + case_id + " " + label + ": benign archive not extracted")
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        shutil.rmtree(base, ignore_errors=True)
    evidence["temporary_folder_removed"] = not os.path.exists(base)
    evidence["finished_at"] = now()
    evidence["all_demonstration_checks_passed"] = (not evidence["failures"] and len(evidence["cases"]) == 16
                                                    and evidence["temporary_folder_removed"])
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "stdlib_runs": len(evidence["stdlib"]),
                      "passed": evidence["all_demonstration_checks_passed"], "failures": evidence["failures"],
                      "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
