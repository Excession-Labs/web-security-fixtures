GraphQL introspection: local fixture evidence
Fixture / runner version: 1.0.0

All identities, bearer values and records are synthetic public demo data
(example.invalid addresses). No production credentials, customer records or
external API targets were used. The server always binds 127.0.0.1. POST /graphql
is the only implemented route.

Requirements: Python 3.9+, curl in PATH, and network access to PyPI once.
verify.py creates a temporary virtual environment, installs the pinned release
graphql-core==3.2.14 into it, and deletes the environment when it finishes.
Nothing is installed globally. To reuse an environment you made yourself:
  python3 -m venv gqenv && gqenv/bin/pip install graphql-core==3.2.14
  python3 verify.py --output rerun --venv gqenv
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. It starts four fixture
configurations one after another on OS-assigned loopback ports, sends six real
curl requests to each (24 in total), records commands and full HTTP responses,
and stops the servers.
  A  introspection on,  resolver check off  (vulnerable)
  B  introspection off, resolver check off
  C  introspection on,  resolver check on
  D  introspection off, resolver check on
Exit 0 means the 24 demonstration checks matched their expected outcomes,
including the intentionally vulnerable ones. It does NOT mean the vulnerable
configurations are secure. secure_expected_outcome and
authorization_boundary_holds in results.json mark the reproduced failure.

The original command was:
  python3 verify.py --output recorded-run

recorded-run/commands.sh contains the exact executed curl argument values. Its
ports were ephemeral and are no longer listening. Use verify.py for a fresh run.

Manual inspection (needs graphql-core in the python you use):
  python3 fixture.py --introspection on --authz off --port 8765
The resolver check is a switch already present in the source. It is a
controlled configuration change, not an agent-generated patch or a production
remediation.

No AI agent or model ran any part of this experiment.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
