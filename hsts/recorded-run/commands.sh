#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# The ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable (http 50573, https 50572)
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50572:127.0.0.1 --hsts recorded-run/vulnerable-curl-cache-after-https.txt https://hsts.test:50572/
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50573:127.0.0.1 --hsts recorded-run/vulnerable-curl-cache-after-http.txt http://hsts.test:50573/
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50573:127.0.0.1 --verbose --hsts recorded-run/vulnerable-curl-cache-after-https.txt http://hsts.test:50573/
# Server: python3 fixture.py --mode short (http 50578, https 50577)
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50577:127.0.0.1 --hsts recorded-run/short-curl-cache-after-https.txt https://hsts.test:50577/
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50578:127.0.0.1 --hsts recorded-run/short-curl-cache-after-http.txt http://hsts.test:50578/
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50578:127.0.0.1 --verbose --hsts recorded-run/short-curl-cache-after-https.txt http://hsts.test:50578/
# Server: python3 fixture.py --mode misplaced (http 50583, https 50582)
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50582:127.0.0.1 --hsts recorded-run/misplaced-curl-cache-after-https.txt https://hsts.test:50582/
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50583:127.0.0.1 --hsts recorded-run/misplaced-curl-cache-after-http.txt http://hsts.test:50583/
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50583:127.0.0.1 --verbose --hsts recorded-run/misplaced-curl-cache-after-https.txt http://hsts.test:50583/
# Server: python3 fixture.py --mode fixed (http 50588, https 50587)
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50587:127.0.0.1 --hsts recorded-run/fixed-curl-cache-after-https.txt https://hsts.test:50587/
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50588:127.0.0.1 --hsts recorded-run/fixed-curl-cache-after-http.txt http://hsts.test:50588/
curl --noproxy '*' --silent --show-error --include --http1.1 --insecure --connect-timeout 1 --max-time 3 --request GET --resolve hsts.test:50588:127.0.0.1 --verbose --hsts recorded-run/fixed-curl-cache-after-https.txt http://hsts.test:50588/
