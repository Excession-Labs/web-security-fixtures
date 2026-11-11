#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 54539 --outbox vulnerable-outbox.jsonl
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --header 'Host: app.example.test' --data-binary '{"email": "victim@example.test"}' http://127.0.0.1:54539/reset-password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --header 'Host: attacker.evil' --data-binary '{"email": "victim@example.test"}' http://127.0.0.1:54539/reset-password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --header 'Host: app.example.test' --header 'X-Forwarded-Host: attacker.evil' --data-binary '{"email": "victim@example.test"}' http://127.0.0.1:54539/reset-password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --header 'Host: app.example.test' --data-binary '{"email": "nobody@example.test"}' http://127.0.0.1:54539/reset-password
# Server: python3 fixture.py --mode fixed --port 54544 --outbox fixed-outbox.jsonl
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --header 'Host: app.example.test' --data-binary '{"email": "victim@example.test"}' http://127.0.0.1:54544/reset-password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --header 'Host: attacker.evil' --data-binary '{"email": "victim@example.test"}' http://127.0.0.1:54544/reset-password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --header 'Host: app.example.test' --header 'X-Forwarded-Host: attacker.evil' --data-binary '{"email": "victim@example.test"}' http://127.0.0.1:54544/reset-password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --header 'Host: app.example.test' --data-binary '{"email": "nobody@example.test"}' http://127.0.0.1:54544/reset-password
