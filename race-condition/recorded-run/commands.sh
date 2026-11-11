#!/bin/sh
# Recorded commands; rerun verify.py to start fresh fixture servers.
# Server ports below refer to the finished run and are no longer listening.
# vulnerable-baseline round 0: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56701/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56701/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56701/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56701/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-baseline round 1: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56722/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56722/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56722/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56722/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-baseline round 2: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56743/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56743/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56743/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56743/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-baseline round 3: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56766/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56766/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56766/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56766/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-baseline round 4: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56787/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56787/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56787/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56787/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-widened round 0: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.05
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56808/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56808/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56808/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56808/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-widened round 1: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.05
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56829/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56829/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56829/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56829/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-widened round 2: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.05
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56850/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56850/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56850/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56850/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-widened round 3: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.05
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56872/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56872/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56872/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56872/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# vulnerable-widened round 4: python3 -u fixture.py --mode vulnerable --port 0 --delay 0.05
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56905/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56905/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56905/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56905/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# fixed round 0: python3 -u fixture.py --mode fixed --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56941/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56941/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56941/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56941/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# fixed round 1: python3 -u fixture.py --mode fixed --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56964/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56964/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56964/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56964/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# fixed round 2: python3 -u fixture.py --mode fixed --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56985/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56985/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:56985/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:56985/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# fixed round 3: python3 -u fixture.py --mode fixed --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:57006/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:57006/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:57006/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:57006/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
# fixed round 4: python3 -u fixture.py --mode fixed --port 0 --delay 0.0
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:57027/status?code=NOPE'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:57027/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'X-Coupon-Code: CONTROL1' http://127.0.0.1:57027/redeem
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:57027/status?code=SAVE10'
# burst: 16 concurrent Python-thread POST /redeem requests, coupon SAVE10
