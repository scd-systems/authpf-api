#!/bin/bash
# e2e_scheduler_test.sh - End-to-end test for authpf-api scheduler
# Verifies that rules are automatically removed after their TTL expires
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
E2E_TMP=$(mktemp -d)
E2E_PORT=19998
BASE_URL="http://127.0.0.1:$E2E_PORT"
API_PID=""

# Shared password hash
PW_HASH=""

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
    rm -rf "$E2E_TMP"
    echo "Done."
}
trap cleanup EXIT

# --- HTTP helpers ---

# req METHOD PATH [TOKEN] [BODY] [EXPECTED] [NAME]
req() {
    local method="$1" path="$2" token="${3:-}" body="${4:-}" expected="$5" name="$6"
    local args=(-s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path")
    [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
    [ -n "$body" ] && args+=(-H "Content-Type: application/json" -d "$body")
    local status
    status=$(curl "${args[@]}")
    check "$name" "$expected" "$status"
}

# login USERNAME -> sets global TOKEN variable
login() {
    local user="$1"
    local sha256_hex=$(echo -n "testpassword123" | sha256sum | awk '{print $1}')
    local resp=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$user\",\"password\":\"$sha256_hex\"}")
    local status=$(echo "$resp" | tail -1)
    check "Login $user" 200 "$status"
    TOKEN=$(echo "$resp" | head -1 | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
}

# activate TOKEN USERNAME TTL EXPECTED NAME
activate() {
    local token="$1" user="$2" ttl="$3" expected="$4" name="$5"
    req POST "/api/v1/authpf/activate?timeout=$ttl" "$token" \
        "{\"username\":\"$user\"}" "$expected" "$name"
}

# get_status TOKEN USERNAME -> returns anchor info or empty
get_status() {
    local token="$1" user="$2"
    curl -s "$BASE_URL/api/v1/authpf/activate" \
        -H "Authorization: Bearer $token" 2>/dev/null | \
        grep -o "\"$user\":{[^}]*}" || echo ""
}

# --- Test runner ---
PASS=0
FAIL=0
check() {
    local name="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  ✅ $name (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $name (expected $expected, got $actual)"
        FAIL=$((FAIL + 1))
    fi
}

# --- Setup ---
echo "=== E2E Scheduler Test Setup ==="

# Password hash
PW_HASH=$(echo "testpassword123" | go run "$PROJECT_DIR/cmd/main.go" -gen-user-password 2>/dev/null)
[ -z "$PW_HASH" ] && { echo "Failed to generate password hash"; exit 1; }

# Mock sudo
printf '#!/bin/bash\nexec "$@"\n' > "$E2E_TMP/sudo"
chmod +x "$E2E_TMP/sudo"

# Rules for all users
for user in user_short user_medium user_long; do
    mkdir -p "$E2E_TMP/rules/$user"
    printf '# rules for %s\npass all\n' "$user" > "$E2E_TMP/rules/$user/rules"
done

# Config with short scheduler interval (2s)
cat > "$E2E_TMP/authpf-api.conf" << CONF
server:
  bind: 127.0.0.1
  port: $E2E_PORT
  logfile: "$E2E_TMP/server.log"
  elevatorMode: "sudo"
  jwtTokenTimeout: "1h"
  jwtSecret: "e2e-test-secret-key-12345"

defaults:
  pfctlBinary: "echo"

authpf:
  timeout: "1h"
  userRulesRootFolder: "$E2E_TMP/rules"
  userRulesFile: "rules"
  anchorName: "authpf"
  flushFilter:
    - "rules"
    - "nat"
  schedulerInterval: "2s"

rbac:
  roles:
    admin:
      permissions:
        - "activate_own_rules"
        - "activate_other_rules"
        - "deactivate_own_rules"
        - "deactivate_other_rules"
        - "view_own_rules"
        - "view_other_rules"
  users:
    user_short:
      password: "$PW_HASH"
      role: "admin"
      userId: 1001
    user_medium:
      password: "$PW_HASH"
      role: "admin"
      userId: 1002
    user_long:
      password: "$PW_HASH"
      role: "admin"
      userId: 1003
CONF
chmod 0640 "$E2E_TMP/authpf-api.conf"

# Start API
echo "=== Starting authpf-api (scheduler interval: 2s) ==="
export PATH="$E2E_TMP:$PATH"
cd "$PROJECT_DIR" && go build -o "$E2E_TMP/authpf-api" cmd/main.go
"$E2E_TMP/authpf-api" -c "$E2E_TMP/authpf-api.conf" -foreground -v trace &
API_PID=$!

echo "Waiting for server..."
for i in $(seq 1 40); do
    curl -s "$BASE_URL/" >/dev/null 2>&1 && { echo "Server ready after ${i}00ms"; break; }
    sleep 0.5
done

# --- Tests ---
echo ""
echo "=== Scheduler E2E Tests ==="

# Login as all users
login "user_short"
SHORT_TOKEN="$TOKEN"
login "user_medium"
MEDIUM_TOKEN="$TOKEN"
login "user_long"
LONG_TOKEN="$TOKEN"

# Activate all users with different TTLs
echo ""
echo "--- Phase 1: Activate with different TTLs ---"
activate "$SHORT_TOKEN" "user_short" "5s" 201 "Activate user_short (5s TTL)"
activate "$MEDIUM_TOKEN" "user_medium" "10s" 201 "Activate user_medium (10s TTL)"
activate "$LONG_TOKEN" "user_long" "15s" 201 "Activate user_long (15s TTL)"

# Verify all are active
echo ""
echo "--- Phase 2: Verify all active ---"
req GET "/api/v1/authpf/activate" "$SHORT_TOKEN" "" 200 "Get Status (all active)"

# Wait for user_short to expire (5s TTL + 2s scheduler interval)
echo ""
echo "--- Phase 3: Wait for user_short (5s TTL) to expire ---"
echo "  Waiting 8s for scheduler to expire user_short..."
sleep 8

# Check that user_short is expired but others are still active
STATUS_SHORT=$(get_status "$SHORT_TOKEN" "user_short")
STATUS_MEDIUM=$(get_status "$MEDIUM_TOKEN" "user_medium")
STATUS_LONG=$(get_status "$LONG_TOKEN" "user_long")

if [ -z "$STATUS_SHORT" ]; then
    echo "  ✅ user_short expired (as expected)"
    PASS=$((PASS + 1))
else
    echo "  ❌ user_short still active (should be expired)"
    FAIL=$((FAIL + 1))
fi

if [ -n "$STATUS_MEDIUM" ]; then
    echo "  ✅ user_medium still active (as expected)"
    PASS=$((PASS + 1))
else
    echo "  ❌ user_medium already expired (should still be active)"
    FAIL=$((FAIL + 1))
fi

if [ -n "$STATUS_LONG" ]; then
    echo "  ✅ user_long still active (as expected)"
    PASS=$((PASS + 1))
else
    echo "  ❌ user_long already expired (should still be active)"
    FAIL=$((FAIL + 1))
fi

# Wait for user_medium to expire (10s TTL + 2s scheduler interval)
echo ""
echo "--- Phase 4: Wait for user_medium (10s TTL) to expire ---"
echo "  Waiting 5s for scheduler to expire user_medium..."
sleep 5

STATUS_MEDIUM=$(get_status "$MEDIUM_TOKEN" "user_medium")
STATUS_LONG=$(get_status "$LONG_TOKEN" "user_long")

if [ -z "$STATUS_MEDIUM" ]; then
    echo "  ✅ user_medium expired (as expected)"
    PASS=$((PASS + 1))
else
    echo "  ❌ user_medium still active (should be expired)"
    FAIL=$((FAIL + 1))
fi

if [ -n "$STATUS_LONG" ]; then
    echo "  ✅ user_long still active (as expected)"
    PASS=$((PASS + 1))
else
    echo "  ❌ user_long already expired (should still be active)"
    FAIL=$((FAIL + 1))
fi

# Wait for user_long to expire (15s TTL + 2s scheduler interval)
echo ""
echo "--- Phase 5: Wait for user_long (15s TTL) to expire ---"
echo "  Waiting 5s for scheduler to expire user_long..."
sleep 5

STATUS_LONG=$(get_status "$LONG_TOKEN" "user_long")

if [ -z "$STATUS_LONG" ]; then
    echo "  ✅ user_long expired (as expected)"
    PASS=$((PASS + 1))
else
    echo "  ❌ user_long still active (should be expired)"
    FAIL=$((FAIL + 1))
fi

# Final status check - all should be expired
echo ""
echo "--- Phase 6: Final status check ---"
req GET "/api/v1/authpf/activate" "$SHORT_TOKEN" "" 200 "Get Status (all expired)"

# --- Results ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
