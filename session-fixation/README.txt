Session fixation: local fixture evidence
Fixture / runner version: 1.0.0

All identities, passwords and session IDs are synthetic demo data.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts the vulnerable and
the fixed server sequentially on OS-assigned loopback ports, sends six curl
requests to each (attacker gets a session, attacker is denied before login,
victim wrong password, victim login with the attacker's ID, victim reads the
account, attacker replays the original ID), records the commands and full HTTP
responses, and stops both servers.
Exit 0 means the twelve demonstration checks matched their expected responses;
it does NOT mean the vulnerable mode is secure. secure_expected_status and
boundary_holds in results.json separately identify the reproduced failure.

The original command was:
  python3 verify.py --output recorded-run

commands.sh holds the exact curl arguments. Its ports and session IDs belong to
the recorded run and are no longer valid. Use verify.py for a fresh run.

Manual inspection, two terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766

The victim's login step sends the attacker's ID as a cookie. How an ID is
planted in a real browser is not tested. The cookie has no Secure attribute
because the fixture uses plain HTTP on loopback.

No AI agent or model task ran and no inference charges were incurred.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
