#!/bin/sh
# Recorded curl commands; rerun verify.py to start fresh fixture servers.
# These ephemeral ports refer to the recorded run and are no longer listening.
# Each flow uses its own authorization code, which the server consumes on first use.
# Server: python3 fixture.py --mode vulnerable --port 50601
# Flow: legit-s256
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50601/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-legit-s256&code_challenge=VuywtG9PQeHVkauqVoaOB8cbZ1dWLYHuVoi5QIszsx8&code_challenge_method=S256'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=utkXwjruYLU8DHPhRyUuSw&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&code_verifier=bgm4SpCCXnOSJQ4DN5EvrL7-JF0ptcU9acDQmcuB7JM' http://127.0.0.1:50601/token
# Flow: intercept-no-verifier
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50601/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-intercept-no-verifier&code_challenge=aaaY-o50fAhBq1RyxrCUF6QWjJCCxnesKprIvr4AdFI&code_challenge_method=S256'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=Awb_hZZmRxtiNaCBTgiQqw&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback' http://127.0.0.1:50601/token
# Flow: intercept-guessed-verifier
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50601/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-intercept-guessed-verifier&code_challenge=HGNzXDMTcgk8Ubf7P6pETYEoC503LO6H7nh6WreBAdA&code_challenge_method=S256'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=j4PUFcCMp7MSlVrlzej6FQ&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&code_verifier=edRSwKKrOfnMpUMRPOd7H_ssflD1gGjgpfjfoPBV44g' http://127.0.0.1:50601/token
# Flow: intercept-challenge-as-verifier
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50601/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-intercept-challenge-as-verifier&code_challenge=3dE7bxpvu-uIcvWO8dNUiOtSRxWf9ogbkp2c2W2AIIY&code_challenge_method=S256'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=QGTZgmMFcbFbBeHwoxWHlw&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&code_verifier=3dE7bxpvu-uIcvWO8dNUiOtSRxWf9ogbkp2c2W2AIIY' http://127.0.0.1:50601/token
# Flow: legacy-client-no-pkce
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50601/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-legacy-client-no-pkce'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=AvdzT2CjL_7bh7rFw1jSpg&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback' http://127.0.0.1:50601/token
# Flow: plain-method
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50601/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-plain-method&code_challenge=lzcHucZtsHd5fXNVF_cGpMS43QWmOslP8W8wiLQj1Dw&code_challenge_method=plain'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=utMsuyra8pimdl1KGkwREQ&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&code_verifier=lzcHucZtsHd5fXNVF_cGpMS43QWmOslP8W8wiLQj1Dw' http://127.0.0.1:50601/token
# Server: python3 fixture.py --mode fixed --port 50617
# Flow: legit-s256
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50617/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-legit-s256&code_challenge=QmoWZ6HslyiNqCzrg0f7PUhL8ttBSLLJPnoG58f2Tto&code_challenge_method=S256'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=eXJwT886SWQGTC9gOYCd7g&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&code_verifier=8kVfFbTnLTAUeKsC9RHfUw7wf_xJnb0Ql_gUKcBAjZ0' http://127.0.0.1:50617/token
# Flow: intercept-no-verifier
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50617/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-intercept-no-verifier&code_challenge=gdYvqu3J6J4cqBmMsnyePFpB8s1sY10UlqxuG4jw3CI&code_challenge_method=S256'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=92bsjlPjiQvHds3sVOunhg&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback' http://127.0.0.1:50617/token
# Flow: intercept-guessed-verifier
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50617/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-intercept-guessed-verifier&code_challenge=6pv5RoMwxk4WyYGlIj2hQ36rFjVmkbGxCArp7pP-6yE&code_challenge_method=S256'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=2aDBolnDw3hjXdhL5gn9pw&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&code_verifier=m4T8aC2QWcX-4NSV1wZxld2LO262m3QsjixJ2hEK5M8' http://127.0.0.1:50617/token
# Flow: intercept-challenge-as-verifier
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50617/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-intercept-challenge-as-verifier&code_challenge=9kb3qdDMYjl9Qf_HUk9HwrdxaZW9c4DiFmu7czGagsA&code_challenge_method=S256'
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request POST --data 'grant_type=authorization_code&code=bFQfkHgbCPgrhCeAhCRoXA&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&code_verifier=9kb3qdDMYjl9Qf_HUk9HwrdxaZW9c4DiFmu7czGagsA' http://127.0.0.1:50617/token
# Flow: legacy-client-no-pkce
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50617/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-legacy-client-no-pkce'
# Flow: plain-method
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET 'http://127.0.0.1:50617/authorize?response_type=code&client_id=demo-public-app&redirect_uri=demoapp%3A%2F%2Fcallback&state=demo-state-plain-method&code_challenge=8mekNvGjY4aDA7J2AT9VhPbC1D9qhbG8wzledSBRoC0&code_challenge_method=plain'
