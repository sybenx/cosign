#!/bin/sh
# Container entry: a shared server rooted at /data (host.json, groups/).
#
# On first start, unless COSIGN_PERSONAL=0, it makes a key of its own for you in /data/a:
# no key yet, the page shows a code, and your phone and this one server make it together
# (setup.ts --weighted --single), so neither can sign alone and nothing else on this box
# holds a share. COSIGN_PERSONAL=dealt makes the old throwaway 2-of-3 instead, with server
# B's share in /data/b on this same box, which can then sign alone. Whichever member this
# container is (COSIGN_MEMBER, /data/a by default) it serves, beside every group enrolled
# in /data/groups. An existing /data/a is served as it is: no new key.
set -e
MEMBER="${COSIGN_MEMBER:-/data/a}"
if [ "${COSIGN_PERSONAL:-weighted}" != 0 ] && [ ! -f /data/a/state.json ] && [ ! -f /data/host.json ]; then
  if [ "$COSIGN_PERSONAL" = dealt ]; then
    echo "COSIGN_PERSONAL=dealt: a throwaway 2-of-3 key with servers A and B both in /data. This one box holds 2 of 3 shares and can sign alone; move /data/b to another machine." >&2
    set --
  else
    set -- --weighted --single
  fi
  node setup.ts --dir /data "$@" --relays "${COSIGN_RELAYS:-wss://syb.lol,wss://nos.lol,wss://relay.primal.net}"
fi
if [ -f "$MEMBER/state.json" ]; then exec node server.ts --root /data "$MEMBER"; fi
exec node server.ts --root /data
