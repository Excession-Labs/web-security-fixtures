#!/bin/sh
# Recorded commands; ports belong to the finished run and are no longer listening.
# target vulnerable on http://127.0.0.1:53494
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53494/account
NODE_PATH=<dir with playwright> node browser_check.cjs framed http://127.0.0.1:53498 http://127.0.0.1:53497
NODE_PATH=<dir with playwright> node browser_check.cjs direct '' http://127.0.0.1:53510
# target fixed on http://127.0.0.1:53516
curl --noproxy '*' --silent --show-error --include --http1.1 --connect-timeout 1 --max-time 3 --request GET http://127.0.0.1:53516/account
NODE_PATH=<dir with playwright> node browser_check.cjs framed http://127.0.0.1:53520 http://127.0.0.1:53518
NODE_PATH=<dir with playwright> node browser_check.cjs direct '' http://127.0.0.1:53562
