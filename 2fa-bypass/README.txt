Two-step login (password + code) bypass: local fixture evidence
Fixture / runner version: 1.0.0

All usernames, passwords and codes are synthetic public demo data.
No production credentials, customer records or external API targets were used.
The server always binds 127.0.0.1. The code is 4 synthetic digits (0000-9999),
not the 6-digit length common in production, chosen so a full sequential
search finishes in well under a second during this test. This is disclosed
in the published post.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts vulnerable and
fixed servers sequentially on OS-assigned loopback ports, runs the same
scripted sequence of login, code-verification and account requests against
each, then runs a sequential 0000-9999 code-guessing loop against a third
account's pending session, saves commands and full HTTP responses, and
stops both servers. Exit 0 means every check matched its expected outcome
for that mode, including the intentionally vulnerable responses.

Discrete scenario requests (login, verify-code, account, test-inbox) run as
real curl subprocesses; see recorded-run/commands.sh for the exact argument
values. The code-guessing loop uses Python's standard-library http.client
directly over one kept-alive connection, because spawning a separate curl
process for up to 10,000 guesses made the loop too slow to finish in a
reasonable test run. No external package was installed or used.

The three reproduced flaws, by case id in results.json:
  1. Step skipping: "account-before-mfa". A session created by /login alone
     (password step only, before /verify-code) already reads /account.
  2. No attempt limit: "brute_force". A sequential guess loop against one
     pending session's own code, with no login or code value fed to the
     attacker.
  3. Code not bound to the session: "cross-session-code". Bob's pending
     session is submitted together with Alice's valid, unused code.
  Plus one related hardening check, "replay-code": resubmitting an
  already-used correct code and session.

Positive controls ("own-code-login", "account-after-mfa") show the legitimate
flow, a user reading their own code and completing their own login, keeps
working in both modes.

The GET /test-inbox endpoint is test-harness scaffolding: it lets the
legitimate owner of a session read the code "sent" to them, standing in for
a tester checking their own phone or email. It is not part of either the
vulnerable or the fixed attack-surface logic, and the brute-force loop never
calls it.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run commands.sh contains the exact executed curl argument values
for the discrete cases. Its ports were ephemeral and are no longer
listening. Use verify.py for a fresh run; do not expect commands.sh to
recreate its own servers. The brute-force summaries
(vulnerable-brute-force-summary.json, fixed-brute-force-summary.json)
record the attempt count, elapsed time and final HTTP response for that
loop; they are not curl commands.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Then replay a recorded curl command against the corresponding chosen port.
Stop these manual servers with Ctrl-C. Fixed mode enables checks already
present in the source (pending-state check on /account, an attempt cap with
lockout, session-bound code comparison, and single-use marking); it is a
controlled configuration change, not an agent-generated patch or a
production remediation.

No AI agent or model task ran and no inference charges were incurred by this
fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
