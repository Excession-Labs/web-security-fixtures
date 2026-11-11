Mass assignment vulnerability: local fixture evidence
Fixture / runner version: 1.0.0

All identities, bearer values, names and password_hash strings are synthetic public demo data.
No production credentials, real user records or external API targets were used.
The server always binds 127.0.0.1. GET and PATCH are the only implemented methods.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts the vulnerable and fixed
servers sequentially on OS-assigned loopback ports, runs ten requests per mode in a
fixed order (later requests read state changed by earlier ones), records commands and
full synthetic HTTP responses, and stops both servers.
Exit 0 means the twenty demonstration checks matched their expected responses; it does
NOT mean the vulnerable fixture is secure. results.json fields secure_policy_holds,
policy_violations_in_vulnerable_mode and policy_violations_in_fixed_mode identify the
reproduced failure and the retest result.

Fixed mode combines a per-role writable-field allowlist with a response serializer.
Non-writable or unknown fields are REJECTED with HTTP 400 and nothing in the request is
applied; they are not silently ignored.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run commands.sh contains the exact executed curl argument values. Its ports
were ephemeral and are no longer listening. Use verify.py for a fresh run.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Stop these manual servers with Ctrl-C.

Not covered: nested objects, PUT/POST create flows, GraphQL, framework binders, value
validation, concurrency, tenant rules.

No AI agent or model task ran by this fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It provides
integrity comparison, not independent attestation or authorship proof.
