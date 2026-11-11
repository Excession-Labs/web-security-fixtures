Clickjacking: local fixture evidence
Fixture / runner version: 1.0.0

All data is synthetic. No production credentials, customer records or external targets
were used. Both servers always bind 127.0.0.1 on OS-assigned ports.

Requirements: Python 3.9+ (standard library), curl in PATH.
Optional browser step: Node plus the playwright package and a Chromium build.
  PLAYWRIGHT_NODE_MODULES=/path/to/node_modules python3 verify.py --output rerun
Without it only the two header cases run and results.json has browser_run=false.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Files:
  fixture.py        target server (account page, delete counter) and attacker server (framing page)
  browser_check.cjs headless Chromium script used by verify.py (.cjs because the parent
                    project may declare ES modules)
  verify.py         starts fresh servers per scenario, runs curl and Chromium, writes evidence

The runner refuses an existing output directory. Exit 0 means the six demonstration
checks matched their expected values, including the intentionally vulnerable result.
It does NOT mean the vulnerable fixture is secure.

The original command was:
  PLAYWRIGHT_NODE_MODULES=<node_modules with playwright> python3 verify.py --output recorded-run

recorded-run/commands.sh lists the executed commands. Its ports were ephemeral and
are no longer listening.

Manual inspection, separate terminals:
  python3 fixture.py --role target --mode vulnerable --port 8765
  python3 fixture.py --role attacker --port 8766 --target-url http://127.0.0.1:8765
Then open http://127.0.0.1:8766/attack in a browser. Use --mode fixed on the target to
enable frame-ancestors 'none' and X-Frame-Options: DENY. Stop servers with Ctrl-C.

Limits: no login or cookies, one browser (Chromium), a scripted click, two origins that
share the host 127.0.0.1 (cross-origin, not cross-site). No AI agent or model ran.

SHA256SUMS covers the published files. It is an integrity comparison, not attestation.
