#!/bin/sh
# Recorded check.py commands; rerun verify.py to start fresh fixture servers.
# The ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode broken --port 53877
python3 check.py --site http://127.0.0.1:53877 --allow-insecure-local
python3 check.py --site http://127.0.0.1:53877/noexpires --allow-insecure-local
python3 check.py --site http://127.0.0.1:53877/expired --allow-insecure-local
python3 check.py --site http://127.0.0.1:53877/httpcontact --allow-insecure-local
python3 check.py --site http://127.0.0.1:53877/html --allow-insecure-local
# Server: python3 fixture.py --mode fixed --port 53894
python3 check.py --site http://127.0.0.1:53894 --allow-insecure-local
python3 check.py --site http://127.0.0.1:53894/minimal --allow-insecure-local
python3 check.py --site http://127.0.0.1:53894/signed --allow-insecure-local
python3 check.py security.txt.example --now 2026-11-10T00:00:00Z
