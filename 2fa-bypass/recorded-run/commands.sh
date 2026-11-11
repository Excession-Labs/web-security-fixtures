#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# The brute-force guess loop used Python http.client directly; see results.json.
# Server: python3 fixture.py --mode vulnerable --port 56059
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "alice-demo-pw"}' http://127.0.0.1:56059/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer sess-1-alice' http://127.0.0.1:56059/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "alice-demo-pw"}' http://127.0.0.1:56059/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56059/test-inbox?session=sess-2-alice'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"session": "sess-2-alice", "code": "0116"}' http://127.0.0.1:56059/verify-code
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer sess-2-alice' http://127.0.0.1:56059/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"session": "sess-2-alice", "code": "0116"}' http://127.0.0.1:56059/verify-code
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "bob", "password": "bob-demo-pw"}' http://127.0.0.1:56059/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "alice-demo-pw"}' http://127.0.0.1:56059/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56059/test-inbox?session=sess-4-alice'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"session": "sess-3-bob", "code": "6225"}' http://127.0.0.1:56059/verify-code
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "charlie", "password": "charlie-demo-pw"}' http://127.0.0.1:56059/login
# Server: python3 fixture.py --mode fixed --port 56075
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "alice-demo-pw"}' http://127.0.0.1:56075/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer sess-1-alice' http://127.0.0.1:56075/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "alice-demo-pw"}' http://127.0.0.1:56075/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56075/test-inbox?session=sess-2-alice'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"session": "sess-2-alice", "code": "4081"}' http://127.0.0.1:56075/verify-code
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer sess-2-alice' http://127.0.0.1:56075/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"session": "sess-2-alice", "code": "4081"}' http://127.0.0.1:56075/verify-code
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "bob", "password": "bob-demo-pw"}' http://127.0.0.1:56075/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "alice-demo-pw"}' http://127.0.0.1:56075/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56075/test-inbox?session=sess-4-alice'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"session": "sess-3-bob", "code": "4385"}' http://127.0.0.1:56075/verify-code
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "charlie", "password": "charlie-demo-pw"}' http://127.0.0.1:56075/login
