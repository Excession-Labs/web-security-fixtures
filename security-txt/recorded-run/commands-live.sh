# Live check of excessionlabs.ai, run separately from verify.py on 2026-11-10 (not part of the local fixture)
date -u +%Y-%m-%dT%H:%M:%SZ  # saved as live-timestamp.txt
curl -sS -m 20 -i https://excessionlabs.ai/.well-known/security.txt > live-wellknown.http  # response headers and start of body
curl -sS -m 20 -i https://excessionlabs.ai/security.txt > live-root.http
python3 check.py --site https://excessionlabs.ai > live-check.txt
