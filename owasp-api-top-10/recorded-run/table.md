| Case | Risk | Secure status | Vulnerable | Fixed |
|---|---|---|---|---|
| alice-reads-own-note | API1 control | 200 | 200 PASS | 200 PASS |
| bob-reads-alice-note | API1 | 403 | 200 FAIL | 403 PASS |
| anonymous-reads-note | API1 control | 401 | 401 PASS | 401 PASS |
| bob-edits-display-name | API3 control | 200 | 200 PASS | 200 PASS |
| bob-sets-own-role | API3 | 400 | 200 FAIL | 400 PASS |
| bob-reads-own-profile | API3 | 200 | 200 FAIL | 200 PASS |
| carol-lists-admin-users | API5 | 403 | 200 FAIL | 403 PASS |
| admin-lists-admin-users | API5 control | 200 | 200 PASS | 200 PASS |
| anonymous-lists-admin-users | API5 control | 401 | 401 PASS | 401 PASS |
| alice-search-limit-50 | API4 control | 200 | 200 PASS | 200 PASS |
| alice-search-limit-100000 | API4 | 400 | 200 FAIL | 400 PASS |
| alice-search-bad-limit | API4 control | 400 | 400 PASS | 400 PASS |
