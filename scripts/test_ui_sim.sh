#!/usr/bin/env bash
# Run the XCUITest suite (apps/ios/Nedwons/UITests) against the REAL app on an iOS simulator.
#
# The app is launched by the tests with the Debug-only harness flag (NedwonsUI/UITestHarness.swift),
# which replaces the network with an in-process fixture; nothing else is faked. No server is needed.
#
# Requires: Xcode 26.x, xcodegen (brew install xcodegen), MlsFfi.xcframework
# (scripts/build_mls_ffi.sh — the app target links it), and an installed iPhone simulator.
#
# GOTCHA (same as test_mls_sim.sh): derived data must live OUTSIDE TCC-protected folders
# (Desktop/Documents/Downloads) and avoid spaces, or the simulator's test runner fails with the
# misleading "bundle does not exist".
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APPDIR="$ROOT/apps/ios/Nedwons"
DD="${NEDWONS_UI_DD:-${TMPDIR:-/tmp}/nedwons-ui-simdd}"
export PATH="/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

if [ ! -d "$ROOT/apps/ios/NedwonsMLS/MlsFfi.xcframework" ]; then
  echo "MlsFfi.xcframework missing — run scripts/build_mls_ffi.sh first." >&2
  exit 1
fi

# Destination: $NEDWONS_SIM_NAME if set, else the first available iPhone simulator.
NAME="${NEDWONS_SIM_NAME:-}"
if [ -z "$NAME" ]; then
  NAME="$(xcrun simctl list devices available \
    | sed -n 's/^ *\(iPhone [^(]*\)(.*/\1/p' | head -1 | sed 's/ *$//')"
fi
if [ -z "$NAME" ]; then
  echo "ERROR: no available iPhone simulator. Install one (Xcode > Settings > Platforms)." >&2
  exit 1
fi

echo "== generate project =="
(cd "$APPDIR" && xcodegen generate >/dev/null)

echo "== UI tests on iOS simulator: ${NAME} (derived data: ${DD}) =="
xcodebuild test \
  -project "$APPDIR/Nedwons.xcodeproj" \
  -scheme Nedwons \
  -only-testing:NedwonsUITests \
  -destination "platform=iOS Simulator,name=${NAME}" \
  -derivedDataPath "$DD" \
  CODE_SIGNING_ALLOWED=NO "$@" 2>&1 \
  | grep -E "Test Suite|Test Case .*(passed|failed)|Executed .* tests|TEST (SUCCEEDED|FAILED)|error:|BUILD (SUCCEEDED|FAILED)" \
  | tail -40
# grep consumes the output; the pipeline's success is xcodebuild's via pipefail.
echo "== UI tests: PASS =="
