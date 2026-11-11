Credential stuffing: local fixture evidence
Fixture / runner version: 1.0.0

All accounts, passwords, "leaked" pairs, corpus digests and second-factor secrets
are synthetic. They are generated from a fixed seed (20261111) inside fixture.py.
No production credentials, customer records or external targets were used.
Every server binds 127.0.0.1 on an OS-assigned port.

Requirements: Python 3.9+ (standard library), curl in PATH.
verify.py imports fixture.py, so keep both files in the same directory.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts a fresh server for each
configuration, sends the 100 synthetic leaked pairs once each with curl, saves every
raw HTTP response, and stops the servers. Configurations:
  vulnerable                      per-account lockout only
  fixed                           budget + leaked-password check + second factor
  fixed-budget-only               budget only
  fixed-budget-only-valid-first   budget only, the 12 working pairs listed first
  fixed-leaked-only               leaked-password check only
  fixed-mfa-only                  second factor only (TOTP, RFC 6238)
Exit 0 means every observed outcome matched the expected outcome in verify.py,
including the intentionally vulnerable one. It does NOT mean the vulnerable fixture
is secure. Expected values come from a small model of the data in verify.py, not
from the server.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run files:
  results.json      checks, expected and observed values, server counters, hashes
  stuffing-*.http   raw responses for all 100 attempts of each configuration
  *.http            single control requests (legitimate sign-in, wrong password,
                    lockout guesses)
  commands.sh       exact curl commands; the ports belong to the finished run

Manual inspection, separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
  python3 fixture.py --mode fixed --controls leaked,mfa --port 8767
GET /_stats returns the fixture's counters. It exists only for the runner.

Known limits of the toy: one client address, a 1,000-iteration password hash, a
corpus held as SHA-1 digests in memory, no CAPTCHA, no fingerprinting, no
notifications. The fixture is for learning and for testing your own systems with
written permission.

No AI agent or model task ran and no inference charges were incurred by this
fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
