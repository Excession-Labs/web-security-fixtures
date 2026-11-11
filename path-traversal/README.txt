Path traversal: local fixture evidence
Fixture / runner version: 1.0.0

All files, contents and the "secret" are synthetic demo data. No production
credentials, customer records or external targets were used. The server always
binds 127.0.0.1. GET /files/<name> is the only implemented route.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts three fixture modes
one after another on OS-assigned loopback ports (vulnerable, naive = strips
"../" once, fixed = realpath plus commonpath check), sends eight curl requests
to each with --path-as-is, saves every raw response, and stops the servers. The
fixture creates a temporary directory with public/ (served) and secret.txt
(outside public/) and deletes it on exit.
Exit 0 means all 24 requests matched their expected status and expected
presence or absence of the secret marker. It does NOT mean the vulnerable and
naive modes are secure; the results show where they disclose the secret.

The original command was:
  python3 verify.py --output recorded-run

recorded-run/commands.sh holds the exact curl arguments. Its ports and
temporary directories no longer exist; use verify.py for a fresh run.

Manual inspection:
  python3 fixture.py --mode vulnerable --port 8765
  curl --path-as-is http://127.0.0.1:8765/files/../secret.txt
Stop with Ctrl-C. The fixture prints JSON with the secret and base paths.

Not covered: Windows paths, symbolic links, null bytes, double decoding by a
proxy, upload or archive extraction, and write endpoints.

No AI agent or model ran this workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation.
