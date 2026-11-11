CSRF and SameSite cookies: local fixture evidence
Fixture / runner version: 1.0.0

All identities, cookies, tokens and email addresses are synthetic demo data.
No production credentials, customer records or external targets were used.
Every server binds 127.0.0.1 only. The attacker page is a second local server,
opened in the browser as http://localhost:<port> so that it is a different
site from the target at http://127.0.0.1:<port>.

Requirements for the curl part: Python 3.9+ (standard library), curl in PATH.
The browser part is optional: it needs Node.js and the Playwright package with
a Chromium build. Playwright is not installed by this bundle.

Reproduce from this directory (curl only):
  python3 verify.py --output rerun

With the browser test, if a node_modules directory with Playwright exists:
  python3 verify.py --output rerun --node-modules /path/to/node_modules --wait-seconds 125

The runner refuses an existing output directory. It starts the target in
vulnerable mode and then in fixed mode on OS-assigned loopback ports, sends 8
curl requests per mode, optionally runs Chromium against both modes, saves every
raw response, and stops all servers. --wait-seconds adds one case that waits
that long before the forged POST, to test the two-minute window of
Lax-by-default cookies (it makes the run about two minutes longer).

Exit 0 means every observed result matched its expected value for that mode,
including the intentionally vulnerable results. It does NOT mean the
vulnerable fixture is safe. boundary_holds in results.json shows, per case,
whether the secure outcome was observed.

The recorded command was:
  python3 verify.py --output recorded-run --node-modules <path> --wait-seconds 125

Ports and cookie values in recorded-run are from that run and are gone.
Browser results depend on the browser build. The recorded one is in
results.json (versions.browser). Other browsers were not tested.

Manual inspection, two terminals:
  python3 fixture.py --role target --mode vulnerable --port 8765
  python3 fixture.py --role attacker --target-port 8765 --port 8766
Open http://localhost:8766/attack-post.html in a browser that has first visited
http://127.0.0.1:8765/login?samesite=lax . Use --mode fixed for the fixed
configuration. Stop with Ctrl-C.

No AI agent or model task ran and no inference charges were incurred.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
