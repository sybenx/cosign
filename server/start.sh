#!/bin/sh
# Container entry: on first start, make a throwaway key split 2-of-3 into /data/a and
# /data/b (the phone's share waits in a until your phone scans a's code). Then run as A.
set -e
[ -f /data/a/state.json ] || node setup.ts --dir /data --relays "${COSIGN_RELAYS:-wss://syb.lol,wss://nos.lol,wss://relay.primal.net}"
exec node server.ts "${COSIGN_MEMBER:-/data/a}"
