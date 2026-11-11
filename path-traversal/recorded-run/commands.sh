#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 52737
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52737/files/report.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52737/files/docs/guide.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52737/files/nope.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52737/files/../secret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52737/files/..%2fsecret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52737/files/%2Fvar%2Ffolders%2Fbv%2F1kt12mw94_sbpfvm9xw5lw380000gn%2FT%2Fpt-fixture-jorskkjr%2Fsecret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52737/files/....//secret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52737/files/%252e%252e%252fsecret.txt
# Server: python3 fixture.py --mode naive --port 52746
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52746/files/report.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52746/files/docs/guide.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52746/files/nope.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52746/files/../secret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52746/files/..%2fsecret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52746/files/%2Fvar%2Ffolders%2Fbv%2F1kt12mw94_sbpfvm9xw5lw380000gn%2FT%2Fpt-fixture-dxa48__4%2Fsecret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52746/files/....//secret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52746/files/%252e%252e%252fsecret.txt
# Server: python3 fixture.py --mode fixed --port 52755
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52755/files/report.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52755/files/docs/guide.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52755/files/nope.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52755/files/../secret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52755/files/..%2fsecret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52755/files/%2Fvar%2Ffolders%2Fbv%2F1kt12mw94_sbpfvm9xw5lw380000gn%2FT%2Fpt-fixture-i9_z9vsm%2Fsecret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52755/files/....//secret.txt
curl --noproxy '*' --silent --show-error --include --path-as-is --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:52755/files/%252e%252e%252fsecret.txt
