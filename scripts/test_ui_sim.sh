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
  # `|| true` is REQUIRED, not defensive noise: this script runs under `set -euo pipefail`, and
  # grep exits 1 when it matches nothing. Without it, a failure whose log contains none of these
  # patterns kills the script right here — losing both the annotations below and the real exit
  # code, which is the exact blindness this block exists to prevent.
  REASONS="$(grep -nE "error:|XCTAssert|Assertion Failure|crashed|terminated|lost connection|Failed to|failed to|timed out" \
    "$FULL_LOG" | tail -30 || true)"
  printf '%s\n' "$REASONS"

  # Under GitHub Actions, repeat the reason as workflow annotations. Reading a failed job's raw log
  # requires repo-ADMIN rights and the result bundle is likewise gated, but the run SUMMARY is not —
  # so without this a CI-only failure is invisible to anyone who does not own the repository.
  #
  # WHICH lines get annotated matters as much as annotating at all. This used to tail the list,
  # which is exactly backwards for a COMPILE failure: the tail of 142 isolation errors was four
  # diagnostics about the file's last line, and reading them cost a day chasing a one-line bug that
  # did not exist. A compiler reports the root cause FIRST, so compile errors are annotated from the
  # top; only when there are none does the tail (a genuine assertion failure or a dead runner) win.
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    # `error:` with a file:line prefix — a compile diagnostic. Deduplicated with awk rather than
    # `sort -u`, because sorting is lexical and would reorder the diagnostics: ":103:" sorts before
    # ":39:", so the compiler's FIRST error (the one most likely to be the root cause) gets pushed
    # out of the top ten by later ones. awk keeps first-seen order while still dropping the copies
    # xcodebuild prints once per compilation unit.
    # `|| true` for the same reason as above — a run that failed on an assertion rather than a
    # compile error matches nothing here, and that is the COMMON case, not an edge one.
    COMPILE_ERRORS="$(grep -hoE "[^ ]+\.(swift|m|h):[0-9]+:[0-9]+: error: .*" "$FULL_LOG" \
      | awk '!seen[$0]++' || true)"
    LABEL="UI test build error"
    if [ -n "$COMPILE_ERRORS" ]; then
      ANNOTATIONS="$(printf '%s\n' "$COMPILE_ERRORS" | head -10)"
    else
      ANNOTATIONS="$(printf '%s\n' "$REASONS" | tail -10)"
      LABEL="UI test failure"
    fi
    # How much was left unsaid, so a truncated list never reads as a complete one.
    TOTAL="$(printf '%s' "$COMPILE_ERRORS" | grep -c . || true)"
    printf '%s\n' "$ANNOTATIONS" | while IFS= read -r line; do
      [ -n "$line" ] || continue
      printf '::error title=%s::%s\n' "$LABEL" "$(printf '%s' "$line" | tr -d '\r' | cut -c1-400)"
    done
    if [ "${TOTAL:-0}" -gt 10 ]; then
      printf '::error title=%s::… and %s more compile errors; see the full log at %s\n' \
        "$LABEL" "$((TOTAL - 10))" "$FULL_LOG"
    fi
  fi
  exit "$STATUS"
fi
echo "== UI tests: PASS =="
