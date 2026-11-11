HttpOnly cookie: local fixture evidence
Fixture / runner version: 1.0.0

The only credential is the public demo password for the synthetic user alice.
Session IDs are random values held in memory by a short-lived local server.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1. curl --resolve maps app.example.test to it,
so no DNS lookup leaves the machine. The fixture serves plain HTTP only.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts vulnerable and fixed
servers sequentially on OS-assigned loopback ports, sends five curl requests to
each, saves the full responses, audits the Set-Cookie header, runs two Python
cookie-rule models and stops both servers. Exit 0 means the 20 checks matched
their expected outcomes. It does NOT mean the vulnerable fixture is secure.

What is real and what is a model:
  curl requests and recorded headers: real responses from fixture.py.
  audit: our parser; it reads attribute text and enforces nothing.
  cookiejar-model: Python http.cookiejar applying Domain and Secure send
    rules (Netscape-style per the Python docs, not RFC 6265). It is not a browser. It does not enforce the __Host- prefix
    (the cookiejar-ignores-prefix check records this).
  script-visible-model: our model of RFC 6265 section 4.1.2.6. Python has no
    script API. Only a browser hides an HttpOnly cookie from document.cookie,
    applies Secure over real HTTPS, enforces SameSite and rejects bad prefixes.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run commands.sh contains the exact executed curl argument values.
Its ports were ephemeral and are no longer listening.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Stop these manual servers with Ctrl-C.

No AI agent or model task ran and no inference charges were incurred by this
fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
