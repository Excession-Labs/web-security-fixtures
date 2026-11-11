Host header injection / password-reset poisoning: local fixture evidence
Fixture / runner version: 1.0.0

All emails, tokens and hostnames are synthetic public demo data.
No production credentials, customer records or external API targets were used.
The server always binds 127.0.0.1. POST /reset-password is the only route.
Instead of sending mail, the fixture appends each rendered message to a
local outbox file (<mode>-outbox.jsonl in the evidence directory).

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts vulnerable and
fixed servers sequentially on OS-assigned loopback ports, runs four requests
per mode (one legitimate reset, one forged Host header, one forged
X-Forwarded-Host header with a valid Host header, and one unknown-email
negative control), records commands and full synthetic HTTP responses, and
stops both servers.

Exit 0 means the eight demonstration checks matched their expected
responses; it does NOT mean the vulnerable fixture is secure. Each case in
results.json records demonstration_expected_status, observed_status,
expected_link_host and observed_link_host separately, so the reproduced
Host-trusting failure is visible in the data, not only in the exit code.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run commands.sh contains the exact executed curl argument values.
Its ports were ephemeral and are no longer listening. Use verify.py for a
fresh run; do not expect commands.sh to recreate its own servers.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765 --outbox /tmp/vuln-outbox.jsonl
  python3 fixture.py --mode fixed --port 8766 --outbox /tmp/fixed-outbox.jsonl
Then replay a recorded curl command against the corresponding chosen port,
or send your own POST with a forged Host or X-Forwarded-Host header, and
read the outbox file afterward. Stop these manual servers with Ctrl-C.
Fixed mode enables the canonical-origin and Host-allowlist check already
present in the source; it is a controlled configuration change, not an
agent-generated patch or a production remediation.

No AI agent or model task ran and no inference charges were incurred by
this fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
