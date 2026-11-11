Open redirect: local fixture evidence
Fixture / runner version: 1.0.0

All redirect targets are synthetic. evil.test and site.example are reserved names
(RFC 2606). curl never follows a redirect, so nothing contacts those names.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1. GET /login is the only implemented route.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts four fixture modes
(vulnerable, naive-slash, naive-host, fixed) one after another on OS-assigned
loopback ports, sends 24 curl requests in total, records each command and the full
HTTP response, and stops the servers.
Exit 0 means the 24 demonstration checks matched their expected Location values
and expected site-exit outcomes. It does NOT mean the vulnerable or naive modes are
secure. leaves_site and redirect_boundary_holds in results.json identify each case
where the redirect left the site.

browser_host_modeled is the runner's own model of WHATWG URL resolution (strip
control characters and spaces at the ends, remove tab and newline, treat a backslash
as a slash, resolve against http://site.example/login). No browser ran.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run commands.sh contains the exact executed curl argument values.
Its ports were ephemeral and are no longer listening. Use verify.py for a fresh
run; do not expect commands.sh to recreate its own servers.

Manual inspection, one terminal per server:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
  curl -i --get --data-urlencode 'next=//evil.test/phish' http://127.0.0.1:8765/login

Raw response files keep line endings as Python read them from curl, so the CR of
each CRLF pair is not present.

No AI agent or model task ran and no inference charges were incurred by this
fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
