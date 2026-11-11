#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh servers.
# Ports and the token refer to the recorded run; the servers are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 53587 --token 4b0266e94967baa9 --delay-ms 2.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer 4b0266e94967baa9' http://127.0.0.1:53587/api/v1/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer ffffffffffffffff' http://127.0.0.1:53587/api/v1/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer 4b0266e9zzzzzzzz' http://127.0.0.1:53587/api/v1/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53587/api/v1/me
# Server: python3 fixture.py --mode fixed --port 53593 --token 4b0266e94967baa9 --delay-ms 2.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer 4b0266e94967baa9' http://127.0.0.1:53593/api/v1/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer ffffffffffffffff' http://127.0.0.1:53593/api/v1/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer 4b0266e9zzzzzzzz' http://127.0.0.1:53593/api/v1/me
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53593/api/v1/me
