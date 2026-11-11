#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 53155
# vulnerable/login-valid: alice logs in with the right password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "demo-alice-pw"}' http://127.0.0.1:53155/login
# vulnerable/login-wrong-password: alice with a wrong password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "wrong"}' http://127.0.0.1:53155/login
# vulnerable/login-apostrophe-name: o'brien logs in with the right password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "o'"'"'brien", "password": "demo-obrien-pw"}' http://127.0.0.1:53155/login
# vulnerable/login-bypass: username alice'-- with a wrong password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice'"'"'--", "password": "wrong"}' http://127.0.0.1:53155/login
# vulnerable/search-valid: search for Widget
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q=Widget http://127.0.0.1:53155/search
# vulnerable/search-union: UNION SELECT from the users table through q
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode 'q=zzz'"'"' UNION SELECT id, username, pw_hash FROM users --' http://127.0.0.1:53155/search
# vulnerable/sort-valid: sort by price
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode sort=price http://127.0.0.1:53155/search
# vulnerable/sort-unknown-column: sort by a column that does not exist
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode sort=nosuchcolumn http://127.0.0.1:53155/search
# vulnerable/sort-oracle-true: sort expression true when the first hash character of alice matches
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode 'sort=CASE WHEN (SELECT substr(pw_hash,1,1) FROM users WHERE username='"'"'alice'"'"')='"'"'4'"'"' THEN price ELSE -price END' http://127.0.0.1:53155/search
# vulnerable/sort-oracle-false: same expression with a wrong character
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode 'sort=CASE WHEN (SELECT substr(pw_hash,1,1) FROM users WHERE username='"'"'alice'"'"')='"'"'0'"'"' THEN price ELSE -price END' http://127.0.0.1:53155/search
# vulnerable/second-order-legit-step1: register carol, then read her history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "carol"}' http://127.0.0.1:53155/register
# vulnerable/second-order-legit-step2: register carol, then read her history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode id=4 http://127.0.0.1:53155/history
# vulnerable/second-order-payload-step1: register a username holding SQL, then read its history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "x'"'"' OR '"'"'1'"'"'='"'"'1"}' http://127.0.0.1:53155/register
# vulnerable/second-order-payload-step2: register a username holding SQL, then read its history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode id=5 http://127.0.0.1:53155/history
# Server: python3 fixture.py --mode bound --port 53170
# bound/login-valid: alice logs in with the right password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "demo-alice-pw"}' http://127.0.0.1:53170/login
# bound/login-wrong-password: alice with a wrong password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "wrong"}' http://127.0.0.1:53170/login
# bound/login-apostrophe-name: o'brien logs in with the right password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "o'"'"'brien", "password": "demo-obrien-pw"}' http://127.0.0.1:53170/login
# bound/login-bypass: username alice'-- with a wrong password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice'"'"'--", "password": "wrong"}' http://127.0.0.1:53170/login
# bound/search-valid: search for Widget
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q=Widget http://127.0.0.1:53170/search
# bound/search-union: UNION SELECT from the users table through q
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode 'q=zzz'"'"' UNION SELECT id, username, pw_hash FROM users --' http://127.0.0.1:53170/search
# bound/sort-valid: sort by price
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode sort=price http://127.0.0.1:53170/search
# bound/sort-unknown-column: sort by a column that does not exist
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode sort=nosuchcolumn http://127.0.0.1:53170/search
# bound/sort-oracle-true: sort expression true when the first hash character of alice matches
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode 'sort=CASE WHEN (SELECT substr(pw_hash,1,1) FROM users WHERE username='"'"'alice'"'"')='"'"'4'"'"' THEN price ELSE -price END' http://127.0.0.1:53170/search
# bound/sort-oracle-false: same expression with a wrong character
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode 'sort=CASE WHEN (SELECT substr(pw_hash,1,1) FROM users WHERE username='"'"'alice'"'"')='"'"'0'"'"' THEN price ELSE -price END' http://127.0.0.1:53170/search
# bound/second-order-legit-step1: register carol, then read her history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "carol"}' http://127.0.0.1:53170/register
# bound/second-order-legit-step2: register carol, then read her history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode id=4 http://127.0.0.1:53170/history
# bound/second-order-payload-step1: register a username holding SQL, then read its history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "x'"'"' OR '"'"'1'"'"'='"'"'1"}' http://127.0.0.1:53170/register
# bound/second-order-payload-step2: register a username holding SQL, then read its history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode id=5 http://127.0.0.1:53170/history
# Server: python3 fixture.py --mode fixed --port 53186
# fixed/login-valid: alice logs in with the right password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "demo-alice-pw"}' http://127.0.0.1:53186/login
# fixed/login-wrong-password: alice with a wrong password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice", "password": "wrong"}' http://127.0.0.1:53186/login
# fixed/login-apostrophe-name: o'brien logs in with the right password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "o'"'"'brien", "password": "demo-obrien-pw"}' http://127.0.0.1:53186/login
# fixed/login-bypass: username alice'-- with a wrong password
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "alice'"'"'--", "password": "wrong"}' http://127.0.0.1:53186/login
# fixed/search-valid: search for Widget
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q=Widget http://127.0.0.1:53186/search
# fixed/search-union: UNION SELECT from the users table through q
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode 'q=zzz'"'"' UNION SELECT id, username, pw_hash FROM users --' http://127.0.0.1:53186/search
# fixed/sort-valid: sort by price
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode sort=price http://127.0.0.1:53186/search
# fixed/sort-unknown-column: sort by a column that does not exist
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode sort=nosuchcolumn http://127.0.0.1:53186/search
# fixed/sort-oracle-true: sort expression true when the first hash character of alice matches
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode 'sort=CASE WHEN (SELECT substr(pw_hash,1,1) FROM users WHERE username='"'"'alice'"'"')='"'"'4'"'"' THEN price ELSE -price END' http://127.0.0.1:53186/search
# fixed/sort-oracle-false: same expression with a wrong character
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode q= --data-urlencode 'sort=CASE WHEN (SELECT substr(pw_hash,1,1) FROM users WHERE username='"'"'alice'"'"')='"'"'0'"'"' THEN price ELSE -price END' http://127.0.0.1:53186/search
# fixed/second-order-legit-step1: register carol, then read her history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "carol"}' http://127.0.0.1:53186/register
# fixed/second-order-legit-step2: register carol, then read her history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode id=4 http://127.0.0.1:53186/history
# fixed/second-order-payload-step1: register a username holding SQL, then read its history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Content-Type: application/json' --data '{"username": "x'"'"' OR '"'"'1'"'"'='"'"'1"}' http://127.0.0.1:53186/register
# fixed/second-order-payload-step2: register a username holding SQL, then read its history
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --get --data-urlencode id=5 http://127.0.0.1:53186/history
