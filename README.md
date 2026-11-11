# web-security-fixtures

Small local fixtures that reproduce common web and API flaws, each with a vulnerable mode, a fixed mode, a verifier and a recorded run.

## Fixtures

| Flaw | Folder | What the run shows | Write-up |
|---|---|---|---|
| OWASP API Top 10 | [`owasp-api-top-10`](owasp-api-top-10/) | 12-request checklist against a vulnerable and a fixed toy API | [Write-up](https://excessionlabs.ai/blog/owasp-api-top-10/) |
| IDOR | [`idor-vulnerability`](idor-vulnerability/) | a second user lists, edits and deletes another user's invoices; UUIDs alone do not help | [Write-up](https://excessionlabs.ai/blog/idor-vulnerability/) |
| SQL injection | [`sql-injection`](sql-injection/) | login bypass, UNION read and second-order injection, closed by parameterized queries and a sort allowlist | [Write-up](https://excessionlabs.ai/blog/sql-injection/) |
| SSRF | [`ssrf`](ssrf/) | a URL preview leaks an internal secret; a hostname block is bypassed by decimal IP and a redirect | [Write-up](https://excessionlabs.ai/blog/ssrf/) |
| Timing attack | [`timing-attack`](timing-attack/) | a token check that stops at the first wrong byte leaks characters; hmac.compare_digest fixes it | [Write-up](https://excessionlabs.ai/blog/timing-attack/) |
| Clickjacking | [`clickjacking`](clickjacking/) | a hidden delete button clicked through a decoy; frame headers make Chromium block the frame | [Write-up](https://excessionlabs.ai/blog/clickjacking/) |
| Row level security | [`row-level-security`](row-level-security/) | three PostgreSQL RLS mistakes on a throwaway local cluster, each retested after the fix | [Write-up](https://excessionlabs.ai/blog/row-level-security/) |
| security.txt | [`security-txt`](security-txt/) | a Python checker flags five defective files by rule and passes the corrected one | [Write-up](https://excessionlabs.ai/blog/security-txt/) |
| Path traversal | [`path-traversal`](path-traversal/) | ../, encoded and absolute paths read files; stripping dots fails, a real-path check holds | [Write-up](https://excessionlabs.ai/blog/path-traversal/) |
| Session fixation | [`session-fixation`](session-fixation/) | a planted session ID survives login; issuing a new ID at login fixes it | [Write-up](https://excessionlabs.ai/blog/session-fixation/) |
| API rate limiting | [`api-rate-limiting`](api-rate-limiting/) | a 5-attempt login limit is bypassed by changing X-Forwarded-For; a fixed limiter key returns 429 | [Write-up](https://excessionlabs.ai/blog/api-rate-limiting/) |
| Broken access control | [`broken-access-control`](broken-access-control/) | a normal user reaches admin functions through a hidden route, a role header and a DELETE method | [Write-up](https://excessionlabs.ai/blog/broken-access-control/) |
| GraphQL introspection | [`graphql-introspection`](graphql-introspection/) | introspection off still leaves an admin field callable; a resolver check stops the read | [Write-up](https://excessionlabs.ai/blog/graphql-introspection/) |
| 2FA bypass | [`2fa-bypass`](2fa-bypass/) | a password-only session, unlimited code guesses and one user's code finishing another's login | [Write-up](https://excessionlabs.ai/blog/2fa-bypass/) |
| CSRF and SameSite | [`csrf-samesite`](csrf-samesite/) | a forged cross-site POST changes an email; a token and Origin check block it | [Write-up](https://excessionlabs.ai/blog/csrf-samesite/) |
| Open redirect | [`open-redirect`](open-redirect/) | a ?next= redirect to an attacker host; two naive fixes are bypassed, a parsed path check holds | [Write-up](https://excessionlabs.ai/blog/open-redirect/) |
| Mass assignment | [`mass-assignment`](mass-assignment/) | a user sets role and credit through a profile endpoint; a per-role allowlist closes it | [Write-up](https://excessionlabs.ai/blog/mass-assignment/) |
| Tenant isolation | [`tenant-isolation`](tenant-isolation/) | a client-supplied tenant_id, a shared cache key and an unchecked export job leak across tenants | [Write-up](https://excessionlabs.ai/blog/tenant-isolation/) |
| Race condition | [`race-condition`](race-condition/) | 16 concurrent requests redeem one coupon up to 16 times; one atomic SQL update fixes it | [Write-up](https://excessionlabs.ai/blog/race-condition/) |
| Host header injection | [`host-header-injection`](host-header-injection/) | a forged Host or X-Forwarded-Host puts the victim's reset token on an attacker domain | [Write-up](https://excessionlabs.ai/blog/host-header-injection/) |
| API authorization testing | [`api-authorization-testing`](api-authorization-testing/) | a cross-account read with eight real requests, then the server-side check | [Write-up](https://excessionlabs.ai/blog/api-authorization-testing/) |
| ReDoS | [`redos`](redos/) | a nested-quantifier regex takes about 3 seconds on 27 characters; a linear pattern and a length cap fix it | [Write-up](https://excessionlabs.ai/blog/redos/) |
| HSTS | [`hsts`](hsts/) | four header setups checked with curl: none, short max-age, HTTP-only and correct | [Write-up](https://excessionlabs.ai/blog/hsts/) |
| PKCE | [`pkce`](pkce/) | an intercepted authorization code redeems for tokens; requiring S256 denies it | [Write-up](https://excessionlabs.ai/blog/pkce/) |
| Credential stuffing | [`credential-stuffing`](credential-stuffing/) | 100 invented leaked pairs open 12 of 60 synthetic accounts past a per-account lockout | [Write-up](https://excessionlabs.ai/blog/credential-stuffing/) |
| HttpOnly cookie | [`httponly-cookie`](httponly-cookie/) | a session cookie without HttpOnly, Secure or SameSite fails a local audit five ways | [Write-up](https://excessionlabs.ai/blog/httponly-cookie/) |
| Zip slip | [`zip-slip`](zip-slip/) | ../ names, absolute names and a tar symlink escape an extract folder; a resolved-path check holds | [Write-up](https://excessionlabs.ai/blog/zip-slip/) |

The `security-txt` folder has no server. Its checker runs against defective and corrected files instead.

## Run one

Each folder is self-contained. Pick one and run its verifier:

```
cd idor-vulnerability
python3 verify.py --output rerun
```

The verifier starts the fixture on loopback, sends the requests, writes the responses and a `results.json`, then stops the server. It refuses an output folder that already exists. Exit code 0 means every case matched its expected result. That includes the vulnerable cases, so it does not mean the vulnerable mode is safe. The `recorded-run/` folder in each fixture holds the run we published, and `SHA256SUMS` lists hashes of the files. Each `README.txt` has the details for that fixture.

## Requirements

Most fixtures need Python 3.9 or newer (standard library only) and `curl` in your PATH. Four folders need more:

- `row-level-security` needs a local PostgreSQL install with `initdb`, `postgres`, `pg_isready` and `psql`. It was recorded with PostgreSQL 16.15. The verifier creates a throwaway cluster in a temp folder on a unix socket and deletes it at the end.
- `graphql-introspection` builds a temporary virtual environment and installs `graphql-core==3.2.14` from PyPI, so it needs network access once. Nothing is installed globally.
- `clickjacking` and `csrf-samesite` have an optional browser check. It needs Node.js, the Playwright package and a Chromium build, which these folders do not install. Without it, only the curl cases run. See each `README.txt` for the flags.

## Safety

These fixtures are intentionally vulnerable. They bind to 127.0.0.1, and every identity, token and record in them is synthetic. Run them only on your own machine and never expose their ports to a network. Do not point the techniques at systems you do not own or have no written permission to test. See the acceptable use policy: https://excessionlabs.ai/aup/

## License

MIT. See [LICENSE](LICENSE).

By Excession Labs, a security lab: https://excessionlabs.ai
