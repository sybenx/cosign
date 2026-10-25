#!/bin/sh
# Release Cosign: tag the protocol and publish a GitHub release, which builds and pushes
# the server image (ghcr.io/sybenx/cosign-server, .github/workflows/server-image.yml) for
# amd64 and arm64, tagged with the version, its minor line and latest. The sidecar setups
# in deploy/ and the Umbrel app pin those.
#
#   ./release.sh 0.12.5
#
# Cosign builds no app: Marble is its own repository (sybenx/marble) with its own
# releases, and consumes android/cosign as a submodule. Notes come from
# release-notes/<version>.md if there is one.
set -e
cd "$(dirname "$0")"

VERSION=${1:-}
[ -n "$VERSION" ] || { echo "usage: ./release.sh <version>   (e.g. 0.12.5)"; exit 1; }
case "$VERSION" in
  v*) echo "give the version without the v: ./release.sh ${VERSION#v}"; exit 1 ;;
  *[!0-9.]*|*..*|.*|*.) echo "that doesn't look like a version: $VERSION"; exit 1 ;;
esac
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || { echo "release from main"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "commit or put aside your changes first"; exit 1; }
git fetch -q origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "main here isn't what origin has: pull or push first"; exit 1; }
git rev-parse -q --verify "refs/tags/v$VERSION" >/dev/null && { echo "v$VERSION is already tagged"; exit 1; }
gh release view "v$VERSION" >/dev/null 2>&1 && { echo "v$VERSION is already released"; exit 1; }

# The server reports this on its status page, and the image is tagged with it.
sed -i '' -E "s/\"version\": \"[^\"]+\"/\"version\": \"$VERSION\"/" server/package.json
grep -q "\"version\": \"$VERSION\"" server/package.json || { echo "couldn't set the version in server/package.json"; exit 1; }

if [ -n "$(git status --porcelain)" ]; then
  git add -A
  git commit -q -m "Release Cosign $VERSION

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
fi
git push -q origin main

NOTES="Cosign $VERSION: the protocol, the server and the signing libraries.

The server image is ghcr.io/sybenx/cosign-server:$VERSION (also :${VERSION%.*} and :latest), for amd64 and arm64. Running one: docs/servers.md. Marble, the Android app, is released from https://github.com/sybenx/marble."
[ -f "release-notes/$VERSION.md" ] && NOTES="$(cat "release-notes/$VERSION.md")

$NOTES"
gh release create "v$VERSION" --title "Cosign $VERSION" --notes "$NOTES"
echo "Cosign $VERSION is tagged; the server image is building: https://github.com/sybenx/cosign/actions/workflows/server-image.yml"
