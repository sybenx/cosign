#!/bin/sh
# Container entry: a shared server rooted at /data (host.json, groups/).
#
# On first start, unless COSIGN_PERSONAL=0, make a throwaway key split 2-of-3 into
# /data/a and /data/b (the phone's share waits in a until your phone scans a's code), as
# a server always has. Whichever of those this container is (COSIGN_MEMBER, /data/a by
# default) it serves, beside every group enrolled in /data/groups. An existing /data/a
# is served as it is: no new key.
set -e
MEMBER="${COSIGN_MEMBER:-/data/a}"
if [ "${COSIGN_PERSONAL:-1}" != 0 ] && [ ! -f /data/a/state.json ] && [ ! -f /data/host.json ]; then
  node setup.ts --dir /data --relays "${COSIGN_RELAYS:-wss://syb.lol,wss://nos.lol,wss://relay.primal.net}"
fi
if [ -f "$MEMBER/state.json" ]; then exec node server.ts --root /data "$MEMBER"; fi
exec node server.ts --root /data
