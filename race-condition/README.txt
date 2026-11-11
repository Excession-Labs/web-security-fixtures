Race condition / TOCTOU coupon-redemption fixture: evidence
Fixture / runner version: 1.0.0

All coupon codes are synthetic public demo strings (SAVE10, CONTROL1).
No production credentials, customer records or external API targets were used.
The server always binds 127.0.0.1. The data store is a temporary on-disk
SQLite file created fresh per process and removed on shutdown.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. For each of three
conditions it starts a fresh fixture.py process (fresh database) five times:

  vulnerable-baseline  mode=vulnerable, no added delay between the check
                        and the write (the ordinary check-then-act window
                        from socket and interpreter scheduling only)
  vulnerable-widened   mode=vulnerable, --delay 0.05 (an artificial, stated
                        50 ms sleep inserted between the check and the
                        write, to widen the window so local threads land
                        in it reliably)
  fixed                mode=fixed, no check-then-act window exists: one
                        conditional SQL UPDATE does the check and the
                        write together

Each round runs, in order: a GET for an unknown coupon (negative control),
one sequential redemption of CONTROL1 (positive control), a second
sequential redemption of CONTROL1 which must be refused (negative control),
a burst of 16 concurrent redemption attempts against the single-use coupon
SAVE10 using Python threads (concurrent.futures.ThreadPoolExecutor with
urllib.request, not curl --parallel), and a final GET of SAVE10's remaining
uses. Sequential requests use real curl subprocesses; the concurrent burst
does not, and that choice is stated in verify.py's own docstring and in the
published post.

Exit 0 means every round's controls matched and the fixed condition's burst
produced exactly one success in all five rounds; it does NOT mean the
vulnerable fixture is secure. successful_200_count and final_uses_remaining
in each round record separately identify how many of the 16 concurrent
requests the vulnerable server actually allowed to redeem the coupon.

The original command was:
  python3 verify.py --output recorded-run

recorded-run/commands.sh contains the exact executed curl argument values
and the fixture.py startup command for every round. Its ports were
ephemeral and are no longer listening. Use verify.py for a fresh run; do
not expect commands.sh to recreate its own servers.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765 --delay 0.05
  python3 fixture.py --mode fixed --port 8766
Then send several concurrent POST /redeem requests with header
"X-Coupon-Code: SAVE10" against the corresponding chosen port, for example
with `ab`, a short shell loop backgrounding curl, or a small Python script.
Stop these manual servers with Ctrl-C. Fixed mode uses the single
conditional UPDATE already present in the source; it is a controlled
configuration change, not an agent-generated patch or a production
remediation.

No AI agent or model task ran and no inference charges were incurred by
this fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files.
It provides integrity comparison, not independent attestation or
authorship proof.
