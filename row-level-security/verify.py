#!/usr/bin/env python3
"""Run three row level security mistakes and their fixes against a throwaway PostgreSQL cluster."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
import time

import fixture

ROOT = Path(__file__).resolve().parent
VIOLATION = 'new row violates row-level security policy for table "invoices"'
ACME = "SET app.tenant_id = 'acme';\n"
ALL_ROWS = "SELECT id, tenant_id, amount FROM invoices ORDER BY id;\n"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Each case: name, role, SQL, expected text in vulnerable mode, expected text in fixed mode,
# and the text that means the isolation boundary held (None when no boundary applies).
def cases_for(group):
    if group == "m1":
        return [
            ("tenant-reads-all", "app_user", ACME + ALL_ROWS, "(4 rows)", "(2 rows)", "(2 rows)"),
            ("tenant-reads-own-with-where", "app_user",
             ACME + "SELECT id, tenant_id, amount FROM invoices WHERE tenant_id = 'acme' ORDER BY id;\n",
             "(2 rows)", "(2 rows)", "(2 rows)"),
        ]
    if group == "m2":
        return [
            ("rls-flags", "postgres",
             "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'invoices';\n",
             " t              | f", " t              | t", None),
            ("app-user-reads", "app_user", ACME + ALL_ROWS, "(2 rows)", "(2 rows)", "(2 rows)"),
            ("owner-reads", "app_owner", ACME + ALL_ROWS, "(4 rows)", "(2 rows)", "(2 rows)"),
            ("superuser-reads", "postgres", ACME + ALL_ROWS, "(4 rows)", "(4 rows)", None),
        ]
    if group == "m3":
        return [
            ("policies", "postgres",
             "SELECT policyname, cmd, with_check FROM pg_policies WHERE tablename = 'invoices' "
             "AND cmd <> 'SELECT' ORDER BY policyname;\n",
             "(amount >= 0)", "tenant_id = current_setting", None),
            ("insert-other-tenant", "app_user",
             ACME + "INSERT INTO invoices VALUES (5, 'globex', 999);\n", "INSERT 0 1", VIOLATION, VIOLATION),
            ("update-move-row-with-where", "app_user",
             ACME + "UPDATE invoices SET tenant_id = 'globex' WHERE id = 1;\n", VIOLATION, VIOLATION, VIOLATION),
            ("insert-own-row", "app_user",
             ACME + "INSERT INTO invoices VALUES (6, 'acme', 10);\n", "INSERT 0 1", "INSERT 0 1", "INSERT 0 1"),
            ("update-own-amount", "app_user",
             ACME + "UPDATE invoices SET amount = 300 WHERE id = 2;\n", "UPDATE 1", "UPDATE 1", "UPDATE 1"),
            ("insert-negative-amount", "app_user",
             ACME + "INSERT INTO invoices VALUES (7, 'acme', -5);\n", VIOLATION, VIOLATION, VIOLATION),
            ("update-move-visible-rows-no-where", "app_user",
             ACME + "UPDATE invoices SET tenant_id = 'globex';\n", "UPDATE 3", VIOLATION, VIOLATION),
            ("final-table-superuser", "postgres", ALL_ROWS, "(6 rows)", "(5 rows)", None),
        ]
    if group == "m3c":
        return [
            ("insert-other-tenant", "app_user",
             ACME + "INSERT INTO invoices VALUES (5, 'globex', 999);\n", VIOLATION, VIOLATION, VIOLATION),
            ("update-move-visible-rows-no-where", "app_user",
             ACME + "UPDATE invoices SET tenant_id = 'globex';\n", VIOLATION, VIOLATION, VIOLATION),
        ]
    raise KeyError(group)


PLAN = [
    ("m1", "vulnerable", fixture.M1_VULNERABLE), ("m1", "fixed", fixture.M1_FIXED),
    ("m2", "vulnerable", fixture.M2_VULNERABLE), ("m2", "fixed", fixture.M2_FIXED),
    ("m3", "vulnerable", fixture.M3_VULNERABLE), ("m3", "fixed", fixture.M3_FIXED),
    ("m3c", "vulnerable", fixture.M3_USING_ONLY),  # control: USING-only FOR ALL policy
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("rerun"), help="new evidence directory")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    evidence = {
        "schema_version": 1, "fixture_version": fixture.VERSION, "started_at": now(),
        "method": "Real psql sessions against a throwaway PostgreSQL cluster created by initdb",
        "scope": {"hosts": ["unix socket in a temp directory; no TCP listener"],
                  "data": "One synthetic invoices table with two tenants, acme and globex"},
        "versions": {"python": platform.python_version(), "os": platform.system(),
                     "architecture": platform.machine(),
                     "psql": subprocess.check_output([fixture.find_bin("psql"), "--version"], text=True).strip(),
                     "postgres": subprocess.check_output([fixture.find_bin("postgres"), "--version"], text=True).strip()},
        "sha256": {name: digest(ROOT / name) for name in ("fixture.py", "verify.py")},
        "reproduction_command": "python3 verify.py --output " + shlex.quote(str(args.output)),
        "agent_execution": {"executed": False, "note": "SQL verification was scripted; no model or agent ran"},
        "cases": [], "failures": [],
    }
    expected_cases = sum(len(cases_for(group)) for group, _, _ in PLAN)
    commands = ["#!/bin/sh", "# Recorded psql commands. verify.py creates and deletes the cluster; the socket",
                "# directory and port below refer to the recorded run and no longer exist."]
    try:
        with fixture.Cluster() as cluster:
            evidence["cluster"] = {"port": cluster.port, "socket_dir_prefix": "/tmp/exl-rls-",
                                   "listen_addresses": "(none, unix socket only)"}
            commands.append("# Cluster: initdb -U postgres -A trust; postgres -k " + cluster.root +
                            " -p " + str(cluster.port) + " -c listen_addresses=")
            _, _, out = cluster.run("postgres", "postgres",
                                    "CREATE ROLE app_owner LOGIN;\nCREATE ROLE app_user LOGIN;\n"
                                    "SELECT version();\n")
            (args.output / "roles.txt").write_text(out)
            evidence["versions"]["server_version_line"] = [l.strip() for l in out.splitlines()
                                                           if l.strip().startswith("PostgreSQL")][0]
            for group, mode, config in PLAN:
                database = group + "_" + mode
                _, rc, out = cluster.run("postgres", "postgres",
                                         "CREATE DATABASE " + database + " OWNER app_owner;\n")
                if rc != 0:
                    raise RuntimeError("create database failed: " + out)
                command, rc, out = cluster.run("app_owner", database,
                                               "\\set ON_ERROR_STOP on\n" + fixture.SETUP + config)
                (args.output / (database + "-setup.txt")).write_text(out)
                if rc != 0:
                    raise RuntimeError("setup failed for " + database + ": " + out)
                commands.append("# " + database + ": setup and policies in " + database + "-setup.txt")
                for name, role, sql, exp_vuln, exp_fixed, secure in cases_for(group):
                    expected = exp_fixed if mode == "fixed" else exp_vuln
                    started = now()
                    tick = time.monotonic()
                    command, rc, out = cluster.run(role, database, sql)
                    raw_name = database + "-" + name + ".txt"
                    (args.output / raw_name).write_text(out)
                    commands.append("echo " + shlex.quote(sql) + " | " + shlex.join(command))
                    passed = expected in out
                    evidence["cases"].append({
                        "id": database + "/" + name, "started_at": started,
                        "elapsed_ms": round((time.monotonic() - tick) * 1000, 3),
                        "database": database, "role": role, "sql": sql,
                        "psql_exit_code": rc, "demonstration_expected_text": expected,
                        "matches_demonstration": passed,
                        "isolation_expected_text": secure,
                        "isolation_boundary_holds": (secure in out) if secure else None,
                        "response_file": raw_name, "response_sha256": digest(args.output / raw_name),
                    })
                    if not passed:
                        evidence["failures"].append(database + "/" + name)
            evidence["cluster_root"] = cluster.root
        evidence["cluster_deleted"] = not os.path.exists(evidence.pop("cluster_root"))
    except Exception as exc:
        evidence["failures"].append(type(exc).__name__ + ": " + str(exc))
    if not evidence.get("cluster_deleted"):
        evidence["failures"].append("cluster directory still exists")
    evidence["finished_at"] = now()
    evidence["all_demonstration_checks_passed"] = not evidence["failures"] and len(evidence["cases"]) == expected_cases
    (args.output / "results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "commands.sh").write_text("\n".join(commands) + "\n")
    print(json.dumps({"checks": len(evidence["cases"]), "passed": evidence["all_demonstration_checks_passed"],
                      "failures": evidence["failures"], "evidence": str(args.output / "results.json")}))
    return 0 if evidence["all_demonstration_checks_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
