#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 53441
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53441/api/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53441/api/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53441/api/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53441/api/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53441/api/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53441/api/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53441/api/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53441/api/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53441/api/admin/audit-log
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53441/api/admin/audit-log
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53441/api/admin/audit-log
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53441/api/admin/audit-log
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53441/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53441/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53441/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53441/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request DELETE http://127.0.0.1:53441/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request DELETE --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53441/api/admin/accounts/acct-8
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request DELETE --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53441/api/admin/accounts/acct-9
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request DELETE --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53441/api/admin/accounts/acct-10
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53441/api/admin/accounts/acct-8
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53441/api/admin/debug
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53441/api/admin/debug
# Server: python3 fixture.py --mode fixed --port 53466
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53466/api/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53466/api/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53466/api/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53466/api/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53466/api/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53466/api/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53466/api/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53466/api/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53466/api/admin/audit-log
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53466/api/admin/audit-log
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53466/api/admin/audit-log
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53466/api/admin/audit-log
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53466/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53466/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53466/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53466/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request DELETE http://127.0.0.1:53466/api/admin/accounts/acct-7
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request DELETE --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53466/api/admin/accounts/acct-8
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request DELETE --header 'Authorization: Bearer demo-user-token' --header 'X-Role: admin' http://127.0.0.1:53466/api/admin/accounts/acct-9
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request DELETE --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53466/api/admin/accounts/acct-10
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53466/api/admin/accounts/acct-8
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53466/api/admin/debug
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-user-token' http://127.0.0.1:53466/api/admin/debug
