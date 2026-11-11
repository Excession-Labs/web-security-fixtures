Broken access control (vertical privilege escalation): local fixture evidence
Fixture / runner version: 1.0.0

All identities, bearer values and accounts are synthetic public demo data.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1. GET and DELETE are the only implemented methods.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts the vulnerable and the
fixed server one after the other on OS-assigned loopback ports, sends 23 curl requests
to each (a role x route x method matrix plus a state check and two unlisted-route
checks), records the commands and the full synthetic HTTP responses, and stops both servers.
Exit 0 means the 46 demonstration checks matched their expected responses; it does NOT
mean the vulnerable fixture is secure. secure_expected_status and
authorization_boundary_holds separately identify the requests that broke the policy.

The original command was:
  python3 verify.py --output recorded-run

recorded-run/commands.sh holds the exact curl arguments. Its ports were ephemeral and
are no longer listening. Use verify.py for a fresh run.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Stop these servers with Ctrl-C. Fixed mode switches on the policy gate already present
in the source; it is a controlled configuration change, not a production remediation.

Limits: one process, two static sessions, a flat two-role model. No POST, PUT or PATCH,
no method override headers, no path normalization tricks, no JWT or cookies.

No AI agent or model task ran. The workflow is scripted Python and curl.

SHA256SUMS covers the published source, text and recorded evidence files. It provides
integrity comparison, not independent attestation or authorship proof.
