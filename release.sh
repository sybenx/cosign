#!/bin/sh
# Build Cosign for Android and publish it as a GitHub release (which Obtainium follows:
# github.com/sybenx/cosign) and on cosign.aaro.cc.
#
#   ./release.sh        (bump versionCode and versionName in android/app/build.gradle.kts first)
#
# The page links the newest build as Cosign-<version>.apk; /cosign.apk is always the
# newest too, for people. Every build is signed with the same key, so each one installs
# over the last.
set -e
cd "$(dirname "$0")"
VERSION=$(sed -n 's/.*versionName = "\(.*\)"/\1/p' android/app/build.gradle.kts)
[ -n "$VERSION" ] || { echo "no versionName"; exit 1; }
[ -e "Cosign-$VERSION.apk" ] && { echo "Cosign-$VERSION.apk already exists: bump the version first"; exit 1; }

# The server reports the same version on its status page.
sed -i '' -E "s/\"version\": \"[^\"]+\"/\"version\": \"$VERSION\"/" server/package.json
(cd android && JAVA_HOME=${JAVA_HOME:-/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home} ./gradlew -q :app:assembleRelease)
rm -f Cosign-*.apk link/public/Cosign-*.apk
cp android/app/build/outputs/apk/release/app-release.apk "Cosign-$VERSION.apk"
cp "Cosign-$VERSION.apk" "link/public/Cosign-$VERSION.apk"
cp "Cosign-$VERSION.apk" link/public/cosign.apk
sed -i '' -E "s#/Cosign-[0-9.]+\.apk\">Cosign-[0-9.]+\.apk#/Cosign-$VERSION.apk\">Cosign-$VERSION.apk#" link/public/index.html
grep -q "Cosign-$VERSION.apk" link/public/index.html || { echo "couldn't update the page's link"; exit 1; }

(cd link && wrangler deploy)
git add -A && git commit -q -m "Release Cosign $VERSION

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" && git push -q origin main
gh release create "v$VERSION" "Cosign-$VERSION.apk" --title "Cosign $VERSION" --notes "Android build of Cosign $VERSION. Install over the previous version; your phone stays in your key."
echo "Cosign $VERSION is at https://cosign.aaro.cc/Cosign-$VERSION.apk"
