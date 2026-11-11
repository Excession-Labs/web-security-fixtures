Timing attack on an API token check: local fixture evidence
Fixture / runner version: 1.0.0

The token, the account and every response are synthetic demo data. The runner
generates a new random 16-character hex token each run (the recorded one is in
recorded-run/results.json). No production credentials or external targets.
The server always binds 127.0.0.1.

IMPORTANT: the vulnerable server adds an ARTIFICIAL sleep (--delay-ms, 2.0 in
the recorded run) after every matching byte. Without it the early-return
difference of a 16-character compare is far below what HTTP timing can see on
loopback. The experiment states this and also records a run with no delay.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory (takes about 15 seconds):
  python3 verify.py --output rerun

The runner refuses an existing output directory. It does four things:
  1. Times ==, hmac.compare_digest and a Python early-return loop in-process
     (21 rounds, interleaved) at 32 bytes and 65,536 bytes.
  2. Starts the vulnerable and fixed servers and sends four curl requests to each
     (valid token, wrong token, correct prefix with wrong rest, no token).
  3. Runs a timing attack with Python http.client (25 requests per candidate,
     4 token characters) against the vulnerable server with delay, then against
     the fixed server (with the same --delay-ms value, which it ignores).
  4. Restarts the vulnerable server with no delay and repeats the attack.
Exit 0 means the 12 asserted checks passed. The no-delay runs are observations
and are not asserted. Raw per-request latencies are in recorded-run/attack-*.json.
Timing numbers differ from run to run and between machines.

Manual inspection:
  python3 fixture.py --mode vulnerable --port 8765 --delay-ms 2
  python3 fixture.py --mode fixed --port 8766
Stop with Ctrl-C.

No AI agent or model ran in this workflow and no inference charges were incurred.
SHA256SUMS covers the published files; it is an integrity comparison, not an
independent attestation.
