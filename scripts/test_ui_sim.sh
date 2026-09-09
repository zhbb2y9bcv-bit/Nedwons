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

FULL_LOG="${DD}/xcodebuild.log"
mkdir -p "$DD"

# One retry, deliberately bounded. On a freshly erased device the test RUNNER has been observed to
# die once mid-suite (no assertion, no crash log — the run simply restarts and reports FAILED
# overall). Three subsequent fresh-device runs could not reproduce it, so it is treated as runner
# flakiness rather than a product fault. A genuinely broken test still fails: it fails every
# attempt. This is not a licence to leave a flaky TEST in place — a test that needs the retry to
# pass is a bug to fix, and the full log names it.
echo "== UI tests on iOS simulator: ${NAME} (derived data: ${DD}) =="
echo "   full log: ${FULL_LOG}"
# The WHOLE log goes to a file and only a summary to the console. Filtering in the pipe (as this
# script used to) throws away the one thing a failure run is for: a test whose runner crashes
# reports no failure line at all, so the summary showed passes and an unexplained "TEST FAILED".
set +e
xcodebuild test \
  -project "$APPDIR/Nedwons.xcodeproj" \
  -scheme Nedwons \
  -only-testing:NedwonsUITests \
  -destination "platform=iOS Simulator,name=${NAME}" \
  -derivedDataPath "$DD" \
  -retry-tests-on-failure -test-iterations 2 \
  CODE_SIGNING_ALLOWED=NO "$@" >"$FULL_LOG" 2>&1
STATUS=$?
set -e

grep -E "Test Case .*(passed|failed)|Executed .* tests|TEST (SUCCEEDED|FAILED)" "$FULL_LOG" | tail -40

if [ "$STATUS" -ne 0 ]; then
  echo
  echo "== UI tests FAILED (exit ${STATUS}). Why: =="
  # Assertion failures, crashed/terminated runners, and build errors — each of which explains a
  # failure the pass/fail lines alone do not.
  grep -nE "error:|XCTAssert|Assertion Failure|crashed|terminated|lost connection|Failed to|failed to|timed out" \
    "$FULL_LOG" | tail -30
  exit "$STATUS"
fi
echo "== UI tests: PASS =="
