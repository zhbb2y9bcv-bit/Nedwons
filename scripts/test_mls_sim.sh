#!/usr/bin/env bash
# Run the Swift↔Rust MLS bridge tests ON the iOS simulator (ADR-0007), against the
# ios-arm64-simulator xcframework slice — converting it from "compiles/links" to "runs".
# xcodebuild hosts the XCTest bundle straight from the Swift package; no Xcode project needed.
#
# GOTCHA (the reason for the custom derived-data path): build products must NOT live under a
# TCC-protected folder (Desktop/Documents/Downloads) and should avoid spaces — the simulator's
# xctest runner cannot read the bundle there and fails with the misleading error
# "Failed to create a bundle instance … Check that the bundle exists on disk."
#
# Prereq: MlsFfi.xcframework built (scripts/build_mls_ffi.sh). Requires an installed iPhone
# simulator runtime (any iOS >= 17).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="$ROOT/apps/ios/NedwonsMLS"
DD="${NEDWONS_SIM_DD:-${TMPDIR:-/tmp}/nedwons-mls-simdd}"

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

echo "== MLS bridge tests on iOS simulator: ${NAME} (derived data: ${DD}) =="
cd "$PKG"
xcodebuild test -scheme NedwonsMLS \
  -destination "platform=iOS Simulator,name=${NAME}" \
  -derivedDataPath "$DD" 2>&1 \
  | grep -E "Test Suite|Test Case .*(passed|failed)|Executed .* tests|TEST (SUCCEEDED|FAILED)|error:" \
  | tail -30
# grep consumes the output; the pipeline's success is xcodebuild's via pipefail.
echo "== simulator bridge tests: PASS =="
