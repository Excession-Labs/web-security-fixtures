#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --role metadata --port 55472
# Server: python3 fixture.py --role target --port 55473 --redirect-to http://127.0.0.1:55472/latest/meta-data/secret
# Server: python3 fixture.py --role preview --port 55474 --mode vulnerable
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55474/preview?url=http%3A%2F%2Ftarget.test%3A55473%2Farticle'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55474/preview?url=http%3A%2F%2F127.0.0.1%3A55472%2Flatest%2Fmeta-data%2Fsecret'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55474/preview?url=http%3A%2F%2F2130706433%3A55472%2Flatest%2Fmeta-data%2Fsecret'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55474/preview?url=http%3A%2F%2Ftarget.test%3A55473%2Fredirect'
# Server: python3 fixture.py --role preview --port 55485 --mode naive
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55485/preview?url=http%3A%2F%2Ftarget.test%3A55473%2Farticle'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55485/preview?url=http%3A%2F%2F127.0.0.1%3A55472%2Flatest%2Fmeta-data%2Fsecret'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55485/preview?url=http%3A%2F%2F2130706433%3A55472%2Flatest%2Fmeta-data%2Fsecret'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55485/preview?url=http%3A%2F%2Ftarget.test%3A55473%2Fredirect'
# Server: python3 fixture.py --role preview --port 55494 --mode strict --allow 127.0.0.1:55473
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55494/preview?url=http%3A%2F%2Ftarget.test%3A55473%2Farticle'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55494/preview?url=http%3A%2F%2F127.0.0.1%3A55472%2Flatest%2Fmeta-data%2Fsecret'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55494/preview?url=http%3A%2F%2F2130706433%3A55472%2Flatest%2Fmeta-data%2Fsecret'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:55494/preview?url=http%3A%2F%2Ftarget.test%3A55473%2Fredirect'
