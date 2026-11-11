#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 55868
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55868:127.0.0.1 --request POST --data 'username=alice&password=demo-password' http://app.example.test:55868/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55868:127.0.0.1 --request POST --data 'username=alice&password=wrong' http://app.example.test:55868/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55868:127.0.0.1 --request GET --header 'Cookie: sid=2f265d07d6b69a252a14a1ada46cb791' http://app.example.test:55868/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55868:127.0.0.1 --request GET http://app.example.test:55868/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55868:127.0.0.1 --request GET --header 'Cookie: sid=00000000000000000000000000000000' http://app.example.test:55868/account
# Server: python3 fixture.py --mode fixed --port 55875
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55875:127.0.0.1 --request POST --data 'username=alice&password=demo-password' http://app.example.test:55875/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55875:127.0.0.1 --request POST --data 'username=alice&password=wrong' http://app.example.test:55875/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55875:127.0.0.1 --request GET --header 'Cookie: __Host-sid=8884ed1ca9344caf19d0e0e691659c1b' http://app.example.test:55875/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55875:127.0.0.1 --request GET http://app.example.test:55875/account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --resolve app.example.test:55875:127.0.0.1 --request GET --header 'Cookie: __Host-sid=00000000000000000000000000000000' http://app.example.test:55875/account
