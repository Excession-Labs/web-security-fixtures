security.txt checker: local fixture evidence
Fixture / runner / checker version: 1.0.0

check.py validates a security.txt file against the rules of RFC 9116
(https://www.rfc-editor.org/rfc/rfc9116.html). security.txt.example is a copy-paste
file with placeholder example.com values.

All files, addresses and dates are synthetic. No credentials, customer data or
external targets were used by verify.py. The fixture servers bind 127.0.0.1 only.

Requirements: Python 3.9+ (standard library). check.py fetches with urllib, so curl
is not needed to run verify.py. curl was used once, by hand, for the live request
described below.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts a "broken" and a "fixed"
server on OS-assigned loopback ports, runs check.py against nine cases, records the
text and JSON output of each, and stops the servers. Exit 0 means every case gave its
expected result (five expected failures, four expected passes). Recorded command:
  python3 verify.py --output recorded-run

The example file is checked with a pinned clock (--now 2026-11-10T00:00:00Z) so a
rerun still passes after its Expires date has passed.

Live request (outside verify.py, recorded-run/commands-live.sh): on 2026-11-10 at
22:47:36 UTC https://excessionlabs.ai/.well-known/security.txt and
https://excessionlabs.ai/security.txt both returned HTTP 404 with an HTML body. This is
recorded as found. It is not a result of the fixture.

check.py does not verify OpenPGP signatures, validate TLS certificates or test that a
contact answers. Passing it means a file matches the implemented rules; it is not an
audit.

No AI agent or model task ran in this workflow.

SHA256SUMS covers the published source, text and recorded files. It is an integrity
comparison, not independent attestation.
