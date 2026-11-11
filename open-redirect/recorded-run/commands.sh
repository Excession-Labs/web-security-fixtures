#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 53848
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=/account http://127.0.0.1:53848/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://evil.test/phish http://127.0.0.1:53848/login
# Server: python3 fixture.py --mode naive-slash --port 53851
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=/account http://127.0.0.1:53851/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://evil.test/phish http://127.0.0.1:53851/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=//evil.test/phish http://127.0.0.1:53851/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode 'next=/\evil.test/phish' http://127.0.0.1:53851/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode 'next=/	/evil.test/phish' http://127.0.0.1:53851/login
# Server: python3 fixture.py --mode naive-host --port 53858
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://site.example/account http://127.0.0.1:53858/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://evil.test/phish http://127.0.0.1:53858/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://site.example.evil.test/phish http://127.0.0.1:53858/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode 'next=https://evil.test/?site.example' http://127.0.0.1:53858/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://site.example@evil.test/phish http://127.0.0.1:53858/login
# Server: python3 fixture.py --mode fixed --port 53864
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=/account http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode 'next=/account/billing?tab=invoices' http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://evil.test/phish http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://site.example/account http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=//evil.test/phish http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode 'next=/\evil.test/phish' http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode 'next=/	/evil.test/phish' http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://site.example.evil.test/phish http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode 'next=https://evil.test/?site.example' http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode next=https://site.example@evil.test/phish http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode dest=billing http://127.0.0.1:53864/login
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --get --data-urlencode dest=https://evil.test/phish http://127.0.0.1:53864/login
