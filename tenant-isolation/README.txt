Tenant isolation testing: local fixture evidence
Fixture / runner version: 1.0.0

All tenants, identities, bearer values, invoices and reports are synthetic public demo data.
No production credentials, customer records or external API targets were used.
The server always binds 127.0.0.1. GET and POST are the only implemented methods.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Fixture: two tenants (acme: alice, amy; globex: bob, bea). Three endpoints:
  GET  /invoices?q=...&tenant_id=...   list/search
  GET  /reports/usage?period=...       response cache
  POST /exports, GET /exports/<id>     export jobs
Vulnerable mode has three gaps: the list trusts the tenant_id parameter, the cache key
omits the tenant, and the export lookup has no tenant check. Fixed mode derives the
tenant from the session, puts it in the cache key and checks it on the job lookup.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts the vulnerable and fixed
servers sequentially on OS-assigned loopback ports, runs 19 requests per mode,
records commands and full synthetic HTTP responses, and stops both servers.
Exit 0 means the 38 demonstration checks matched their expected responses;
it does NOT mean the vulnerable fixture is secure. cross_tenant_data_returned and
authorization_boundary_holds in results.json identify each reproduced leak.

The original command was:
  python3 verify.py --output recorded-run

Recorded-run commands.sh contains the exact executed curl argument values.
Its ports were ephemeral and are no longer listening. Use verify.py for a fresh
run; do not expect commands.sh to recreate its own servers.

Manual inspection, two separate terminals:
  python3 fixture.py --mode vulnerable --port 8765
  python3 fixture.py --mode fixed --port 8766
Stop these manual servers with Ctrl-C. Fixed mode enables checks already present
in the source; it is a controlled configuration change, not a generated patch or
a production remediation.

Limits: one in-process cache, no shared HTTP cache or CDN, no multi-tenant users,
no token or header tenant claims, no database-level isolation, no queues or file storage.

No AI agent or model task ran and no inference charges were incurred.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
