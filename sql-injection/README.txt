SQL injection: local fixture evidence
Fixture / runner version: 1.0.0

All users, passwords, products and orders are synthetic public demo data.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1 and keeps its sqlite3 database in memory.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Modes of fixture.py:
  vulnerable  every query is built by string concatenation
  bound       values use ? placeholders; the ORDER BY column is still concatenated
  fixed       values use placeholders; the ORDER BY column comes from an allowlist

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts each mode on an
OS-assigned loopback port, sends 14 curl requests per mode (42 in total),
records commands and full raw responses, and stops the servers.
Exit 0 means the 42 demonstration checks matched their expected responses;
it does NOT mean the vulnerable mode is secure. secure_boundary_holds and
secure_boundary_failures in results.json identify the reproduced failures.

The original command was:
  python3 verify.py --output recorded-run

recorded-run/commands.sh contains the exact executed curl commands. Its ports
were ephemeral and are no longer listening.

Manual inspection, separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Stop with Ctrl-C.

Limits: sqlite3 only, no blind or time-based techniques, no ORM, no stored
procedures, no database privilege model, no web application firewall.
The fixture stores unsalted SHA-256 hashes for brevity; do not copy that.
No AI agent or model ran.
