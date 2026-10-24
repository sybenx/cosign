#!/bin/sh
# Container entry: a shared server rooted at /data (host.json, groups/).
#
# On first start, unless COSIGN_PERSONAL=0, it makes a key of its own for you in /data/a:
# no key yet, the page shows a code, and your phone and this one server make it together
# (setup.ts --weighted --single), so neither can sign alone and nothing else on this box
# holds a share. (Its paper backup needs a second server: add one from the app.) Whichever member this
# container is (COSIGN_MEMBER, /data/a by default) it serves, beside every group enrolled
# in /data/groups. An existing /data/a is served as it is: no new key.
set -e
MEMBER="${COSIGN_MEMBER:-/data/a}"
if [ "${COSIGN_PERSONAL:-weighted}" != 0 ] && [ ! -f /data/a/state.json ] && [ ! -f /data/host.json ]; then
  node setup.ts --dir /data --weighted --single --relays "${COSIGN_RELAYS:-wss://syb.lol,wss://nos.lol,wss://relay.primal.net}"
fi
if [ -f "$MEMBER/state.json" ]; then exec node server.ts --root /data "$MEMBER"; fi
exec node server.ts --root /data
