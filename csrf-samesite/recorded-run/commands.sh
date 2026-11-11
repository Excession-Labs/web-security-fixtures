#!/bin/sh
# Recorded curl commands. Ports belong to the finished run; use verify.py for fresh servers.
# Server: python3 fixture.py --role target --mode vulnerable --port 54259
# vulnerable / view-account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Cookie: sid=aa8706bccc8a724740ba6c823232835a' http://127.0.0.1:54259/account
# vulnerable / legit-post
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=8bea462c6f5c3da9b553be03505108e7' --header 'Origin: http://127.0.0.1:54259' --header 'Content-Type: application/x-www-form-urlencoded' --data 'email=alice-new@example.test&csrf_token=no-token-field-in-vulnerable-page' http://127.0.0.1:54259/account/email
# vulnerable / forged-post-no-token
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=b4e9c26abe06b9370c82f40d14347a41' --header 'Origin: http://localhost:9' --header 'Content-Type: application/x-www-form-urlencoded' --data email=attacker@evil.test http://127.0.0.1:54259/account/email
# vulnerable / forged-post-stolen-token
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=9e247cb13056782879970a58c8cc8b50' --header 'Origin: http://localhost:9' --header 'Content-Type: application/x-www-form-urlencoded' --data 'email=attacker@evil.test&csrf_token=no-token-field-in-vulnerable-page' http://127.0.0.1:54259/account/email
# vulnerable / same-origin-no-token
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=5cb6bc4f5141145f689b7fd60d909d51' --header 'Origin: http://127.0.0.1:54259' --header 'Content-Type: application/x-www-form-urlencoded' --data email=attacker@evil.test http://127.0.0.1:54259/account/email
# vulnerable / same-origin-wrong-token
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=d0642d360148311d3967280672944eba' --header 'Origin: http://127.0.0.1:54259' --header 'Content-Type: application/x-www-form-urlencoded' --data 'email=attacker@evil.test&csrf_token=00000000000000000000000000000000' http://127.0.0.1:54259/account/email
# vulnerable / forged-post-no-cookie
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Origin: http://localhost:9' --header 'Content-Type: application/x-www-form-urlencoded' --data email=attacker@evil.test http://127.0.0.1:54259/account/email
# vulnerable / forged-get
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Cookie: sid=98791531cd25139e3661d3437d3579e5' 'http://127.0.0.1:54259/account/email/change?email=attacker@evil.test'
# Server: python3 fixture.py --role target --mode fixed --port 55269
# fixed / view-account
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Cookie: sid=cb59efedfe6830ee21dc3934919885f3' http://127.0.0.1:55269/account
# fixed / legit-post
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=badd4d93554d15b9e9692d232b1b9f21' --header 'Origin: http://127.0.0.1:55269' --header 'Content-Type: application/x-www-form-urlencoded' --data 'email=alice-new@example.test&csrf_token=0895388efcf2b1284c99d12dc896cb93' http://127.0.0.1:55269/account/email
# fixed / forged-post-no-token
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=13906f3f03015a3d0b0831118e5b5c0b' --header 'Origin: http://localhost:9' --header 'Content-Type: application/x-www-form-urlencoded' --data email=attacker@evil.test http://127.0.0.1:55269/account/email
# fixed / forged-post-stolen-token
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=f56af2c8b5bdf1999cfea4acfc8a8b47' --header 'Origin: http://localhost:9' --header 'Content-Type: application/x-www-form-urlencoded' --data 'email=attacker@evil.test&csrf_token=bf62134407ef3276b55f5f85aa45c7e2' http://127.0.0.1:55269/account/email
# fixed / same-origin-no-token
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=39ce0a363e3f58f9fdf8f124c1fe8671' --header 'Origin: http://127.0.0.1:55269' --header 'Content-Type: application/x-www-form-urlencoded' --data email=attacker@evil.test http://127.0.0.1:55269/account/email
# fixed / same-origin-wrong-token
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Cookie: sid=ec0ccb52fdc86462f35f791b90a8fcaf' --header 'Origin: http://127.0.0.1:55269' --header 'Content-Type: application/x-www-form-urlencoded' --data 'email=attacker@evil.test&csrf_token=00000000000000000000000000000000' http://127.0.0.1:55269/account/email
# fixed / forged-post-no-cookie
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Origin: http://localhost:9' --header 'Content-Type: application/x-www-form-urlencoded' --data email=attacker@evil.test http://127.0.0.1:55269/account/email
# fixed / forged-get
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Cookie: sid=557da4107add94f33531e045b79f4f8d' 'http://127.0.0.1:55269/account/email/change?email=attacker@evil.test'
