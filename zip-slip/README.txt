Zip slip: local fixture evidence
Fixture / runner version: 1.0.0

All archives, member names and file contents are synthetic.
No production credentials, customer records or external targets were used.
The server always binds 127.0.0.1. POST /upload/zip and POST /upload/tar are the only routes.

Requirements: Python 3.9+ (standard library), curl in PATH.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

verify.py creates a temporary folder (zipslip-run-*), builds eight archives in memory,
starts the vulnerable and the fixed server in turn, uploads each archive with curl,
checks the file system after every upload, then extracts the same archives with
Python's own zipfile and tarfile in separate sandboxes. It removes the temporary
folder at the end. The runner refuses an existing output directory.

Exit 0 means the sixteen upload checks matched their expected outcomes and the
temporary folder was removed. It does NOT mean the vulnerable mode is secure:
secure_expected_status and boundary_holds in results.json show the reproduced failure.

The original commands were:
  python3 verify.py --output recorded-run                  (Python 3.15.2)
  /usr/bin/python3 verify.py --output recorded-run-py39    (Python 3.9.6, no tarfile filters)

Python 3.9.6 has no tarfile extraction filters, so that run has 8 standard-library
runs instead of 16. The upload checks are identical.

Manual inspection, one terminal:
  mkdir /tmp/zipslip-demo
  python3 fixture.py --mode vulnerable --root /tmp/zipslip-demo --port 8765
The server writes only inside --root and refuses a folder whose name does not start
with zipslip-. It creates uploads/ (the destination) and outside/ (the sibling that
a hostile member should never reach). Stop it with Ctrl-C and delete the folder.

recorded-run/commands.sh holds the exact curl argument values. Its ports and
temporary folders belong to the finished run and no longer exist. Absolute member
names in the recorded files contain that run's random temporary folder name.

No AI agent or model task ran and no inference charges were incurred.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
