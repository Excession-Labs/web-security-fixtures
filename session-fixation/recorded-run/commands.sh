#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# Ports and session IDs refer to the recorded run; the servers are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 52659
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52659/session
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=a73e453b9181db0077034a4aa0dae665 --request GET http://127.0.0.1:52659/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=a73e453b9181db0077034a4aa0dae665 --request POST --header 'Content-Type: application/json' --data '{"user": "victor", "password": "wrong-guess"}' http://127.0.0.1:52659/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=a73e453b9181db0077034a4aa0dae665 --request POST --header 'Content-Type: application/json' --data '{"user": "victor", "password": "demo-password-not-real"}' http://127.0.0.1:52659/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=a73e453b9181db0077034a4aa0dae665 --request GET http://127.0.0.1:52659/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=a73e453b9181db0077034a4aa0dae665 --request GET http://127.0.0.1:52659/account
# Server: python3 fixture.py --mode fixed --port 52666
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52666/session
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=9c49b4cac21557c0ebde63be301f8776 --request GET http://127.0.0.1:52666/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=9c49b4cac21557c0ebde63be301f8776 --request POST --header 'Content-Type: application/json' --data '{"user": "victor", "password": "wrong-guess"}' http://127.0.0.1:52666/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=9c49b4cac21557c0ebde63be301f8776 --request POST --header 'Content-Type: application/json' --data '{"user": "victor", "password": "demo-password-not-real"}' http://127.0.0.1:52666/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=499daed97ba66c5e8e864a6811554d9c --request GET http://127.0.0.1:52666/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --cookie sid=9c49b4cac21557c0ebde63be301f8776 --request GET http://127.0.0.1:52666/account
