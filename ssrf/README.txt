SSRF (server-side request forgery) local fixture evidence
Fixture / runner version: 1.0.0

All hosts, tokens and the one secret value are synthetic public demo data.
No production credentials, customer records or external network targets were used.
Every server binds 127.0.0.1. GET is the only implemented method.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts a "target" server
(stands in for the public site a URL-preview feature is meant to fetch) and a
"metadata" server (stands in for an internal metadata service holding one
synthetic secret), then starts a "preview" server three times in a row, once
per defense mode: vulnerable, naive, strict. For each mode it sends four GET
requests to the preview server's /preview?url=... endpoint and records the
real HTTP response. It stops every server before exiting.

Hostname resolution for the symbolic name "target.test" is a fixed local
table inside fixture.py, not real DNS, so the whole fixture runs fully
offline and deterministically. Every other hostname used in the four cases
(127.0.0.1, and the decimal form 2130706433) resolves through the normal
socket layer, which is why those forms still land on loopback.

The four cases, same across all three modes:
  legit     - http://target.test:<port>/article            (ordinary preview use)
  literal   - http://127.0.0.1:<port>/latest/meta-data/secret
  encoded   - http://2130706433:<port>/latest/meta-data/secret  (decimal IP form of 127.0.0.1)
  redirect  - http://target.test:<port>/redirect            (302 to the metadata URL above)

Exit 0 means all twelve demonstration checks matched their expected preview
status and expected secret_leaked value. It does NOT mean the vulnerable or
naive fixture is secure; those two modes are expected to leak the secret in
several cases by design.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run commands.sh contains the exact executed curl argument values.
Its ports were ephemeral and are no longer listening. Use verify.py for a
fresh run; do not expect commands.sh to recreate its own servers.

Manual inspection, three separate terminals:
  python3 fixture.py --role metadata --port 8766
  python3 fixture.py --role target --port 8765 --redirect-to http://127.0.0.1:8766/latest/meta-data/secret
  python3 fixture.py --role preview --port 8767 --mode strict --allow 127.0.0.1:8765
Then curl "http://127.0.0.1:8767/preview?url=<url-encoded target URL>".
Stop these manual servers with Ctrl-C. Each mode is a controlled configuration
change already present in the source; none of them is an agent-generated
patch or a production remediation.

No AI agent or model task ran and no inference charges were incurred by this
fixture workflow.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
