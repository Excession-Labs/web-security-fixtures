#!/usr/bin/env python3
"""Throwaway PostgreSQL cluster plus the SQL for three row level security mistakes.

Everything is synthetic. The cluster lives in a temp directory, listens only on a
unix socket inside that directory, and is deleted when the context exits.
Nothing outside the temp directory is read or written.
"""
import os
import shutil
import socket
import subprocess
import tempfile
import time

VERSION = "1.0.0"
BIN_DIRS = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/lib/postgresql/16/bin"]

# One table, two tenants. The application sets app.tenant_id after it connects.
SETUP = """
CREATE TABLE invoices (
  id        integer PRIMARY KEY,
  tenant_id text    NOT NULL,
  amount    integer NOT NULL
);
INSERT INTO invoices VALUES (1, 'acme', 100), (2, 'acme', 250),
                            (3, 'globex', 400), (4, 'globex', 75);
GRANT SELECT, INSERT, UPDATE ON invoices TO app_user;
"""

TENANT = "tenant_id = current_setting('app.tenant_id', true)"

# Mistake 1: the table has no row level security at all.
M1_VULNERABLE = ""
M1_FIXED = """
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON invoices FOR SELECT
  USING (tenant_id = current_setting('app.tenant_id', true));
"""

# Mistake 2: RLS is enabled, but the table owner is exempt unless it is forced.
M2_VULNERABLE = M1_FIXED
M2_FIXED = M1_FIXED + "ALTER TABLE invoices FORCE ROW LEVEL SECURITY;\n"

# Mistake 3: the read policy is correct, but the write policies only check
# that the amount is not negative. An explicit WITH CHECK replaces the default.
M3_VULNERABLE = """
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON invoices FOR SELECT
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_insert ON invoices FOR INSERT
  WITH CHECK (amount >= 0);
CREATE POLICY tenant_update ON invoices FOR UPDATE
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (amount >= 0);
"""
M3_FIXED = """
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_read ON invoices FOR SELECT
  USING (tenant_id = current_setting('app.tenant_id', true));
CREATE POLICY tenant_insert ON invoices FOR INSERT
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true) AND amount >= 0);
CREATE POLICY tenant_update ON invoices FOR UPDATE
  USING (tenant_id = current_setting('app.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true) AND amount >= 0);
"""

# Control: one FOR ALL policy with only USING. PostgreSQL reuses USING as the check.
M3_USING_ONLY = """
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_all ON invoices FOR ALL
  USING (tenant_id = current_setting('app.tenant_id', true));
"""


def find_bin(name):
    found = shutil.which(name)
    if found:
        return found
    for directory in BIN_DIRS:
        candidate = os.path.join(directory, name)
        if os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(name + " not found; install PostgreSQL 14 or later")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Cluster:
    """initdb into a temp dir, start on a unix socket, delete everything on exit."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="exl-rls-", dir="/tmp")
        self.data = os.path.join(self.root, "data")
        self.port = free_port()
        self.process = None
        self.psql_bin = find_bin("psql")

    def __enter__(self):
        try:
            subprocess.run([find_bin("initdb"), "-D", self.data, "-U", "postgres",
                            "-A", "trust", "--no-sync", "-E", "UTF8", "--locale=C"],
                           check=True, capture_output=True, timeout=60)
            self.process = subprocess.Popen(
                [find_bin("postgres"), "-D", self.data, "-k", self.root, "-p", str(self.port),
                 "-c", "listen_addresses=", "-c", "fsync=off", "-c", "logging_collector=off"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ready = find_bin("pg_isready")
            for _ in range(100):
                if subprocess.run([ready, "-h", self.root, "-p", str(self.port)],
                                  capture_output=True).returncode == 0:
                    return self
                time.sleep(0.1)
            raise RuntimeError("PostgreSQL did not become ready in ten seconds")
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *exc):
        if self.process:
            self.process.terminate()  # SIGTERM: smart shutdown
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        shutil.rmtree(self.root, ignore_errors=True)

    def psql_command(self, role, database, extra=()):
        return [self.psql_bin, "-X", "-a", "-h", self.root, "-p", str(self.port),
                "-U", role, "-d", database, *extra]

    def run(self, role, database, sql):
        """Run SQL in one psql session; return (command, exit code, stdout+stderr)."""
        command = self.psql_command(role, database)
        done = subprocess.run(command, input=sql, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=20)
        return command, done.returncode, done.stdout


if __name__ == "__main__":
    print("fixture.py is a library; run verify.py")
