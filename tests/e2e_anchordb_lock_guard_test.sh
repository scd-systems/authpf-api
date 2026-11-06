#!/bin/bash
# e2e_anchordb_lock_guard_test.sh - keep the anchorsDB locking discipline intact
#
# The anchorsDB (internal/authpf/anchordb.go) is a struct that owns its map and a
# mutex of its own, which is what makes it safe for extensions. Around it sits a
# second mutex (internal/server/types.go), taken by the API handler and the
# scheduler around a whole section, so a check and the write that follows cannot
# interleave. Neither arrangement is visible to the compiler, so a refactor can
# quietly remove one Lock() and the result is not a failed request but a Go runtime
# fatal error that takes the daemon down.
#
# This guard checks that arrangement from two sides:
#
#   1. static   who reaches the map, and who takes the mutex. Every accessor must
#               match an entry in the ledger (static_guard/ledger.go), which names
#               the pattern and the reason for each one. A new accessor with no
#               entry fails, and so does an existing one that stops locking.
#   2. runtime  the pattern is proven, not assumed. An extension-shaped reader
#               survives, Range's callback may reach back into the DB, and the
#               handler's section stays atomic.
#
# The extension-facing interface is guarded by the mutex inside the DB now. The
# independent probe for that claim is ./tests/e2e_anchordb_lock_test.sh --expect-clean
#
# Usage: ./tests/e2e_anchordb_lock_guard_test.sh [options]
#   --verbose     list every function that reaches the map, not only findings
#   --selftest    also run the fixtures that prove the guard can fail
#   --skip-runtime  static half only
#
# Exit: 0 = locking discipline intact, 1 = something drifted or broke.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GUARD_PKG="./tests/anchordb_lock_guard/static_guard"
RUNTIME_PKG="./tests/anchordb_lock_guard/runtime"

VERBOSE=0
SELFTEST=0
SKIP_RUNTIME=0

for arg in "$@"; do
    case "$arg" in
        --verbose)      VERBOSE=1 ;;
        --selftest)     SELFTEST=1 ;;
        --skip-runtime) SKIP_RUNTIME=1 ;;
        -h|--help)      sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
    esac
done

cd "$PROJECT_DIR" || exit 2

FAILURES=0

section() {
    echo
    echo "=== $1 ==="
}

# The guard is a program, so a broken build is a failure rather than a skip.
section "build guard"
if ! go build -o /dev/null "$GUARD_PKG"; then
    echo "FAIL  guard does not build"
    exit 1
fi
echo "ok"

section "static: locking pattern in source"
GO_ARGS=(-dir .)
[ "$VERBOSE" -eq 1 ] && GO_ARGS+=(-v)
if go run "$GUARD_PKG" "${GO_ARGS[@]}"; then
    echo "ok"
else
    echo "FAIL  locking pattern drifted from the ledger"
    FAILURES=$((FAILURES + 1))
fi

if [ "$SELFTEST" -eq 1 ]; then
    section "static: guard selftest (proves it can fail)"
    if go run "$GUARD_PKG" -selftest; then
        echo "ok"
    else
        echo "FAIL  guard cannot detect its own fixtures, do not trust its verdict"
        FAILURES=$((FAILURES + 1))
    fi
fi

if [ "$SKIP_RUNTIME" -eq 0 ]; then
    section "runtime: pattern proven against the real map type"
    if go test -count=1 -timeout 120s "$RUNTIME_PKG"; then
        echo "ok"
    else
        echo "FAIL  runtime half failed"
        FAILURES=$((FAILURES + 1))
    fi
fi

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "anchordb lock guard: FAILED ($FAILURES stage(s))"
    echo
    echo "A regression means some code now reads or writes the anchorsDB map"
    echo "without a known holder of the shared mutex. Concurrent access to that"
    echo "map is a fatal runtime error, so the fix is to take the lock at the"
    echo "entry point and hold it across the section, then re-run this script."
    echo "If the change was intentional, update tests/anchordb_lock_guard/"
    echo "static_guard/ledger.go and say why in the commit message."
    exit 1
fi

echo "anchordb lock guard: PASSED"
exit 0
