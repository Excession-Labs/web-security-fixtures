ReDoS: local fixture evidence
Fixture / runner version: 1.0.0

All inputs are synthetic: runs of the letter a and fixed demo names.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1. GET /validate?name=... is the only endpoint.
The server is single-threaded on purpose, so one slow match delays queued requests.

Requirements: Python 3.9+ (standard library), curl in PATH.
The recorded run used Python 3.15.2; other versions were not tested.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts the vulnerable and
fixed servers one after the other on OS-assigned loopback ports, sends real curl
requests, records the commands and full responses, and stops both servers.
Every curl call has a hard 8 second limit. The attack ladder stops climbing if a
request takes longer than 4 seconds. The worst vulnerable request in the
recorded run took about 3.1 seconds.

Timings are observed wall-clock values. They vary by machine and by run. Compare
the growth between steps on your own machine, not the absolute numbers.

Exit 0 means every case returned its expected status and the five timing claims
held. It does NOT mean the vulnerable mode is safe.

The original command was:
  python3 verify.py --output recorded-run

recorded-run/commands.sh holds the exact curl commands. Its ports were ephemeral
and are no longer listening. Use verify.py for a fresh run.

Manual inspection, two terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Only send short inputs to the vulnerable server by hand. 26 letters plus "!" took
about 3 seconds in the recorded run and each extra letter doubles the time.
Stop each server with Ctrl-C.

No AI agent or model ran the test and no inference charges were incurred.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
