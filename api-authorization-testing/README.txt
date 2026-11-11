API authorization testing: local fixture evidence
Fixture / runner version: 1.0.0

All identities, bearer values and note contents are synthetic public demo data.
No production credentials, customer records or external API targets were used.
The server always binds 127.0.0.1. GET is the only implemented application method.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts vulnerable and fixed
servers sequentially on OS-assigned loopback ports, runs four requests per mode,
records commands and full synthetic HTTP responses, and stops both servers.
Exit 0 means the eight demonstration checks matched their expected responses;
it does NOT mean the vulnerable fixture is secure. secure_expected_status and
authorization_boundary_holds separately identify the reproduced failure.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run commands.sh contains the exact executed curl argument values.
Its ports were ephemeral and are no longer listening. Use verify.py for a fresh
run; do not expect commands.sh to recreate its own servers.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Then replay a recorded curl command against the corresponding chosen port.
Stop these manual servers with Ctrl-C. Fixed mode enables the ownership check
already present in the source; it is a controlled configuration change, not an
agent-generated patch or a production remediation.

No AI agent or model task ran and no inference charges were incurred by this
fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
