#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 50025
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Ada Lovelace' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Grace Brewster Murray Hopper of the Navy' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode name=aaaaaaaaaaaaaaaaaaaaaaaaaa http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=bad!' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Ada  Lovelace' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Ada	Lovelace' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaa!' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50025/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Ada Lovelace' http://127.0.0.1:50025/validate
# Server: python3 fixture.py --mode fixed --port 50085
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Ada Lovelace' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Grace Brewster Murray Hopper of the Navy' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode name=aaaaaaaaaaaaaaaaaaaaaaaaaa http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=bad!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Ada  Lovelace' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Ada	Lovelace' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=aaaaaaaaaaaaaaaaaaaaaaaa!' http://127.0.0.1:50085/validate
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 8 --get --data-urlencode 'name=Ada Lovelace' http://127.0.0.1:50085/validate
