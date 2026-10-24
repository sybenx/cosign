#!/bin/sh
# Publish the newest GitHub release to Zapstore, from zapstore.yaml. Signed by the
# publisher's own key in their browser extension (NIP-07): zsp opens a page to approve
# it. Run after ./release.sh. Needs zsp (github.com/zapstore/zsp) on PATH.
#
#   ./zapstore.sh                 sign in the browser
#   SIGN_WITH=bunker://… ./zapstore.sh    or with a NIP-46 signer
set -e
cd "$(dirname "$0")"
command -v zsp >/dev/null || { echo "zsp isn't installed: see github.com/zapstore/zsp"; exit 1; }
SIGN_WITH=${SIGN_WITH:-browser} zsp publish zapstore.yaml
