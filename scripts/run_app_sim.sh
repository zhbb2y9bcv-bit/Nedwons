#!/usr/bin/env bash
# Build + run the NEDWONS demo app on an iOS simulator (closes the software half of R-101 for the
# Secret Message feature — a runnable @main app). Regenerates the Xcode project from project.yml
# (xcodegen), builds for a simulator, installs, and launches. Pass `-autoRevealDemo` handling is in
# the app; this script just boots + launches so you can interact.
#
# Requires: Xcode 26.x, xcodegen (brew install xcodegen), and MlsFfi.xcframework built by
# scripts/build_mls_ffi.sh. Derived data goes to a temp dir OUTSIDE the TCC-protected project tree
# (Desktop/Documents), or xctest/launch fails with a misleading "bundle does not exist".
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APPDIR="$ROOT/apps/ios/Nedwons"
SIM="${NEDWONS_SIM:-iPhone 17 Pro}"
BUNDLE_ID="app.nedwons.demo"
export PATH="/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

if [ ! -d "$ROOT/apps/ios/NedwonsMLS/MlsFfi.xcframework" ]; then
  echo "MlsFfi.xcframework missing — run scripts/build_mls_ffi.sh first." >&2
  exit 1
fi

echo "== generate project =="
(cd "$APPDIR" && xcodegen generate >/dev/null)

DD="$(mktemp -d /tmp/nedwons-app-dd.XXXXXX)"
echo "== build (derivedData=$DD) =="
xcodebuild -project "$APPDIR/Nedwons.xcodeproj" -scheme Nedwons \
  -destination "platform=iOS Simulator,name=$SIM" -derivedDataPath "$DD" \
  build >/dev/null

APP="$(find "$DD/Build/Products" -name 'Nedwons.app' -maxdepth 3 | head -1)"
echo "== boot + install + launch on '$SIM' =="
xcrun simctl boot "$SIM" 2>/dev/null || true
xcrun simctl bootstatus "$SIM" -b >/dev/null 2>&1 || true
xcrun simctl install "$SIM" "$APP"
xcrun simctl launch "$SIM" "$BUNDLE_ID" "$@"
echo "launched $BUNDLE_ID on '$SIM'."
