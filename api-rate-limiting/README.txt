API rate limiting: local fixture evidence
Fixture / runner version: 1.0.0

All accounts, passwords and header values are synthetic public demo data.
X-Forwarded-For values are TEST-NET documentation addresses.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1. POST /login is the only implemented route.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Policy under test: 5 attempts per key in a 60-second window, then 429.
Vulnerable mode keys the limit on the client-supplied X-Forwarded-For header.
Fixed mode keys on (account, TCP peer address), trusts the header only from a
configured proxy (none in this fixture), and sends Retry-After with each 429.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts five fresh servers
on OS-assigned loopback ports, sends 56 curl requests, saves every full HTTP
response, writes results.json and commands.sh, and stops the servers.
Exit 0 means every response matched what the experiment expected, including
the intentional bypass in vulnerable mode. It does NOT mean the vulnerable
fixture is secure.

The original command was:
  python3 verify.py --output recorded-run

commands.sh holds the exact curl arguments. Its ports were ephemeral and are
no longer listening. Use verify.py for a fresh run.

Manual inspection:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Stop each with Ctrl-C.

Not covered: shared counters across servers, window expiry, boundary bursts,
IPv6, other forwarding headers, a real reverse proxy (the trusted-proxy branch
is present but never executed), or many real addresses against one account.

No AI agent or model task ran and no inference charges were incurred.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
