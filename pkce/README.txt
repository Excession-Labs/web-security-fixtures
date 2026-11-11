PKCE experiment: local fixture evidence
Fixture / runner version: 1.0.0

fixture.py is a toy OAuth authorization server (GET /authorize, POST /token) with
one synthetic public client. Vulnerable mode ignores code_challenge and
code_verifier. Fixed mode requires an S256 code_challenge and checks the
code_verifier at the token endpoint (RFC 7636).

All codes, verifiers and tokens are one-time synthetic demo values.
No production credentials, real users or external targets were used.
The server always binds 127.0.0.1. The redirect URI demoapp://callback is never
fetched; the runner reads the Location header, as an interceptor would.

Requirements: Python 3 (standard library), curl in PATH.
The recorded run used Python 3.15.2. Versions and source SHA-256 hashes are in
recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts vulnerable and fixed
servers sequentially on OS-assigned loopback ports, runs six flows per mode (12
in total) with real curl requests, records commands and full responses, and
stops both servers. It also recomputes the RFC 7636 Appendix B example.
Exit 0 means the 12 flows matched their expected outcomes; it does NOT mean the
vulnerable mode is secure. secure_expected_outcome and boundary_holds in
results.json separately identify the reproduced failures.

The original command was:
  python3 verify.py --output recorded-run

recorded-run/commands.sh holds the exact executed curl commands. Its ports were
ephemeral and are no longer listening. Each flow used its own authorization
code, which the server consumes on first use.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766

Not covered: real OS URI-scheme hijacking, TLS, code expiry, confidential
clients, refresh tokens, challenge and verifier length checks, a race between
an attacker and the real client, and the downgrade attack in RFC 7636 section 7.2.

No AI agent or model task ran and no inference charges were incurred by this
fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
