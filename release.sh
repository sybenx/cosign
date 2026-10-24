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
# Signed with Cosign's release key (kept off the repo, in $COSIGN_KEYS), with the
# lineage that proves it took over from the debug key the first builds were signed
# with, so every build still installs over the last (APK key rotation, Android 9+).
KEYS=${COSIGN_KEYS:-$HOME/cosign-release}
if [ -f "$KEYS/cosign-release.jks" ]; then
  BT=$(ls -d ${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}/build-tools/* | sort -V | tail -1)
  JAVA_HOME=${JAVA_HOME:-/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home} "$BT/apksigner" sign \
    --ks "$KEYS/old-debug.keystore" --ks-pass pass:android --ks-key-alias androiddebugkey --key-pass pass:android \
    --next-signer --ks "$KEYS/cosign-release.jks" --ks-pass "file:$KEYS/password.txt" --ks-key-alias cosign \
    --lineage "$KEYS/lineage.bin" --rotation-min-sdk-version 28 \
    --out "Cosign-$VERSION.apk" android/app/build/outputs/apk/release/app-release.apk
  rm -f "Cosign-$VERSION.apk.idsig"
else
  echo "no release key in $KEYS: signing with the debug key"; cp android/app/build/outputs/apk/release/app-release.apk "Cosign-$VERSION.apk"
fi
cp "Cosign-$VERSION.apk" "link/public/Cosign-$VERSION.apk"
cp "Cosign-$VERSION.apk" link/public/cosign.apk
sed -i '' -E "s#/Cosign-[0-9.]+\.apk\">Cosign-[0-9.]+\.apk#/Cosign-$VERSION.apk\">Cosign-$VERSION.apk#" link/public/index.html
grep -q "Cosign-$VERSION.apk" link/public/index.html || { echo "couldn't update the page's link"; exit 1; }

# The live list of public servers (cosign.aaro.cc/servers), from site/src/servers.ts.
(cd site && npx esbuild src/servers-page.ts --bundle --format=iife --minify --target=es2022 --outfile=../link/public/servers.js --log-level=warning)
(cd link && wrangler deploy)
git add -A && git commit -q -m "Release Cosign $VERSION

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" && git push -q origin main
gh release create "v$VERSION" "Cosign-$VERSION.apk" --title "Cosign $VERSION" --notes "Android build of Cosign $VERSION. Install over the previous version; your phone stays in your key."
echo "Cosign $VERSION is at https://cosign.aaro.cc/Cosign-$VERSION.apk"
