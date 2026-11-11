Row level security: local PostgreSQL fixture evidence
Fixture / runner version: 1.0.0

All tenants, roles and invoice rows are synthetic. No production credentials,
customer records or external targets were used. The cluster is created by
initdb in a temp directory under /tmp, listens only on a unix socket in that
directory (listen_addresses is empty) and is deleted when verify.py ends.
Nothing else on the machine is read or changed.

Requirements: Python 3.9+ (standard library) and PostgreSQL with initdb,
postgres, pg_isready and psql in PATH or in /opt/homebrew/bin, /usr/local/bin.
Recorded with PostgreSQL 16.15 only. Versions and source SHA-256 hashes are in
recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It creates one database per
configuration (m1, m2, m3 vulnerable and fixed, plus m3c, a control with one
FOR ALL policy that has only USING), runs each test in its own psql session,
saves the full psql output and deletes the cluster.
Exit 0 means all 30 cases matched their expected outcome, including the
intentionally vulnerable ones. It does NOT mean the vulnerable configurations
are secure. isolation_boundary_holds in results.json marks each case where
the tenant boundary held. superuser and rls-flags cases have no boundary.

The original command was:
  python3 verify.py --output recorded-run

recorded-run/commands.sh holds the psql commands. Its socket directory and
port belong to the finished run and no longer exist.

Limits: one table, PostgreSQL 16.15, trust authentication, no DELETE, no
restrictive policies, no views, no BYPASSRLS role, no Supabase.
No AI agent or model task ran during verification.
