OWASP API Top 10 starter checklist: local fixture evidence
Fixture / runner version: 1.0.0

All identities, bearer tokens, notes and rows are synthetic public demo data.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1. Implemented methods: GET and PATCH.

The fixture has four flaws in vulnerable mode and fixes in fixed mode:
  API1 GET /notes/<id>      object ownership check
  API3 PATCH /profile       allowlist of writable fields
  API4 GET /search?limit=N  page size cap (50)
  API5 GET /admin/users     admin role check

Requirements: Python 3.9+ (standard library), curl in PATH.
Versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts the vulnerable and
fixed servers one after the other on OS-assigned loopback ports, sends 12 curl
requests to each, saves every raw response, writes results.json, table.md and
commands.sh, and stops both servers.

Each case states the SECURE expectation. The vulnerable server is expected to
fail 5 cases; the fixed server is expected to pass all 12. Exit 0 means both
modes behaved as designed. It does NOT mean the vulnerable mode is secure.

To adapt: edit the CASES list in verify.py (token, method, path, JSON body,
secure status, body check) and keep the positive controls.

Manual inspection:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Stop with Ctrl-C. Recorded commands.sh ports belong to the finished run.

No AI agent or model ran. SHA256SUMS is an integrity check, not attestation.
