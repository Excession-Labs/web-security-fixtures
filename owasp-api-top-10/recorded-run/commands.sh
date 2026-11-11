#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 53529
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' http://127.0.0.1:53529/notes/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-bob-token' http://127.0.0.1:53529/notes/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53529/notes/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request PATCH --header 'Authorization: Bearer demo-bob-token' --header 'Content-Type: application/json' --data '{"display_name": "Bobby"}' http://127.0.0.1:53529/profile
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request PATCH --header 'Authorization: Bearer demo-bob-token' --header 'Content-Type: application/json' --data '{"role": "admin"}' http://127.0.0.1:53529/profile
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-bob-token' http://127.0.0.1:53529/profile
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-carol-token' http://127.0.0.1:53529/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53529/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53529/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' 'http://127.0.0.1:53529/search?limit=50'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' 'http://127.0.0.1:53529/search?limit=100000'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' 'http://127.0.0.1:53529/search?limit=abc'
# Server: python3 fixture.py --mode fixed --port 53542
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' http://127.0.0.1:53542/notes/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-bob-token' http://127.0.0.1:53542/notes/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53542/notes/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request PATCH --header 'Authorization: Bearer demo-bob-token' --header 'Content-Type: application/json' --data '{"display_name": "Bobby"}' http://127.0.0.1:53542/profile
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request PATCH --header 'Authorization: Bearer demo-bob-token' --header 'Content-Type: application/json' --data '{"role": "admin"}' http://127.0.0.1:53542/profile
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-bob-token' http://127.0.0.1:53542/profile
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-carol-token' http://127.0.0.1:53542/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-admin-token' http://127.0.0.1:53542/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53542/admin/users
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' 'http://127.0.0.1:53542/search?limit=50'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' 'http://127.0.0.1:53542/search?limit=100000'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' 'http://127.0.0.1:53542/search?limit=abc'
