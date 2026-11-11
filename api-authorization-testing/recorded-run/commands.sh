#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 32818
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' http://127.0.0.1:32818/objects/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-bob-token' http://127.0.0.1:32818/objects/bob-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-bob-token' http://127.0.0.1:32818/objects/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:32818/objects/alice-note
# Server: python3 fixture.py --mode fixed --port 32824
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-alice-token' http://127.0.0.1:32824/objects/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-bob-token' http://127.0.0.1:32824/objects/bob-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-bob-token' http://127.0.0.1:32824/objects/alice-note
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:32824/objects/alice-note
