HSTS header: local fixture evidence
Fixture / runner version: 1.0.0

All content is synthetic. No external network targets, production credentials or
customer data were used. Both listeners bind 127.0.0.1 on OS-assigned ports. The
name hsts.test is pinned to 127.0.0.1 with curl --resolve and exists nowhere else.

Requirements: Python 3.9+ (standard library), curl and openssl in PATH.
curl needs HSTS support: "curl --help all | grep hsts" should list --hsts.
Tested versions and source SHA-256 hashes are in recorded-run/results.json.

Reproduce from this directory:
  python3 verify.py --output rerun

The runner refuses an existing output directory. For each of four fixture modes it
sends three real curl requests, parses the headers with a small RFC 6797 parser,
compares the findings with the expected ones and runs eleven parser self-checks.
Exit 0 means every demonstration check matched its expected value. It does NOT mean
the vulnerable, short or misplaced modes are secure.

Modes:
  vulnerable  HTTPS has no Strict-Transport-Security header; HTTP serves the page.
  short       HTTPS sends max-age=300 only; HTTP redirects.
  misplaced   Only the plain-HTTP redirect carries the header; HTTPS has none.
  fixed       HTTPS sends max-age=31536000; includeSubDomains; HTTP only redirects.

The TLS certificate is self-signed and made by the openssl command each time the
fixture starts, in a temporary directory outside this folder. The private key is
deleted as soon as the server has loaded it. No key or certificate is published.
curl -k (--insecure) skips certificate checks, so the run does not test certificate
validity.

curl does not enforce HSTS like a browser. curl's own --hsts cache only stores a
host and upgrades later http:// requests inside that curl run. The fixture tests
the header. It does not test browser behaviour, the browser preload list or any
real domain. The fixture uses non-default ports, and curl keeps the port when it
upgrades, so the upgraded request meets a TLS handshake on the plain listener and
fails. That failure is the evidence that curl did not send plain HTTP.

The fixed mode deliberately omits the preload directive. See the post for the
hstspreload.org requirements.

Manual inspection:
  python3 fixture.py --mode fixed
  (the first output line gives both ports)
  curl -ik --resolve hsts.test:HTTPSPORT:127.0.0.1 https://hsts.test:HTTPSPORT/
  Stop the server with Ctrl-C.

No AI agent or model task ran and no inference charges were incurred.

SHA256SUMS covers the published source, text and recorded evidence files. It
provides integrity comparison, not independent attestation or authorship proof.
