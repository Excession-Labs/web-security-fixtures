#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Server: python3 fixture.py --mode vulnerable --port 53743
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53743/invoices?q=inv&tenant_id=acme'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' 'http://127.0.0.1:53743/invoices?q=inv&tenant_id=globex'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53743/invoices?q=inv&tenant_id=globex'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' 'http://127.0.0.1:53743/invoices?q=inv&tenant_id=acme'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:53743/invoices?q=inv&tenant_id=acme'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53743/reports/usage?period=2026-09'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' 'http://127.0.0.1:53743/reports/usage?period=2026-09'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' 'http://127.0.0.1:53743/reports/usage?period=2026-10'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53743/reports/usage?period=2026-10'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53743/reports/usage?period=2026-09'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:53743/reports/usage?period=2026-09'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Authorization: Bearer demo-acme-alice' --header 'Content-Type: application/json' --data '{}' http://127.0.0.1:53743/exports
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Authorization: Bearer demo-globex-bob' --header 'Content-Type: application/json' --data '{}' http://127.0.0.1:53743/exports
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' http://127.0.0.1:53743/exports/exp-0001
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' http://127.0.0.1:53743/exports/exp-0002
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' http://127.0.0.1:53743/exports/exp-0001
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-amy' http://127.0.0.1:53743/exports/exp-0001
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' http://127.0.0.1:53743/exports/exp-9999
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53743/exports/exp-0001
# Server: python3 fixture.py --mode fixed --port 53763
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53763/invoices?q=inv&tenant_id=acme'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' 'http://127.0.0.1:53763/invoices?q=inv&tenant_id=globex'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53763/invoices?q=inv&tenant_id=globex'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' 'http://127.0.0.1:53763/invoices?q=inv&tenant_id=acme'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:53763/invoices?q=inv&tenant_id=acme'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53763/reports/usage?period=2026-09'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' 'http://127.0.0.1:53763/reports/usage?period=2026-09'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' 'http://127.0.0.1:53763/reports/usage?period=2026-10'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53763/reports/usage?period=2026-10'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' 'http://127.0.0.1:53763/reports/usage?period=2026-09'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:53763/reports/usage?period=2026-09'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Authorization: Bearer demo-acme-alice' --header 'Content-Type: application/json' --data '{}' http://127.0.0.1:53763/exports
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --header 'Authorization: Bearer demo-globex-bob' --header 'Content-Type: application/json' --data '{}' http://127.0.0.1:53763/exports
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-globex-bob' http://127.0.0.1:53763/exports/exp-0001
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' http://127.0.0.1:53763/exports/exp-0002
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' http://127.0.0.1:53763/exports/exp-0001
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-amy' http://127.0.0.1:53763/exports/exp-0001
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET --header 'Authorization: Bearer demo-acme-alice' http://127.0.0.1:53763/exports/exp-9999
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53763/exports/exp-0001
