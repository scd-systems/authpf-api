#!/bin/bash
# e2e_rate_limit_test.sh - Rate limiting E2E test for authpf-api
# Tests that the API returns HTTP 429 when rate limit is exceeded
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
E2E_TMP=$(mktemp -d)
E2E_PORT=19997
BASE_URL="http://127.0.0.1:$E2E_PORT"
API_PID=""
PASS=0
FAILURES=0

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
    rm -rf "$E2E_TMP"
    echo "Done."
}
trap cleanup EXIT

assert_eq() {
    local actual="$1"
    local expected="$2"
    local name="$3"
    if [ "$actual" = "$expected" ]; then
        echo "  ✅ $name"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $name (expected=$expected, actual=$actual)"
        FAILURES=$((FAILURES + 1))
    fi
}

# --- Setup ---

# Build binary
echo "=== Build ==="
cd "$PROJECT_DIR"
go build -o "$E2E_TMP/authpf-api" ./cmd/main.go

# Create mock sudo
mkdir -p "$E2E_TMP/bin"
cat > "$E2E_TMP/bin/sudo" <<'EOF'
#!/bin/bash
exec "$@"
EOF
chmod +x "$E2E_TMP/bin/sudo"
export PATH="$E2E_TMP/bin:$PATH"

# Create rules directory
mkdir -p "$E2E_TMP/rules"

# Create config with low rate limit
cat > "$E2E_TMP/authpf-api.conf" << CONF
defaults:
  pfctlBinary: "echo"

server:
  bind: 127.0.0.1
  port: $E2E_PORT
  logfile: "$E2E_TMP/server.log"
  elevatorMode: "sudo"
  rateLimit: 5
  rateLimitBurst: 10

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
  users: {}
CONF
chmod 0640 "$E2E_TMP/authpf-api.conf"

# Start server
echo "=== Start Server ==="
"$E2E_TMP/authpf-api" -c "$E2E_TMP/authpf-api.conf" -foreground &
API_PID=$!
sleep 2

# Verify server is running
if ! kill -0 "$API_PID" 2>/dev/null; then
    echo "ERROR: Server failed to start"
    exit 1
fi
echo "  Server running on $BASE_URL (PID $API_PID)"

# --- Tests ---

# Test 1: Normal requests should succeed (within burst limit)
echo ""
echo "=== Test: Normal requests succeed ==="
for i in $(seq 1 5); do
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE_URL/" || true)
    assert_eq "$status" "200" "Healthcheck $i"
done

# Test 2: Rapid requests should eventually hit rate limit
echo ""
echo "=== Test: Rate limit triggers 429 ==="
hit_429=false
for i in $(seq 1 80); do
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE_URL/" || true)
    if [ "$status" = "429" ]; then
        hit_429=true
        echo "  ✅ Rate limit hit after $i requests (HTTP 429)"
        PASS=$((PASS + 1))
        break
    fi
done
if [ "$hit_429" = false ]; then
    echo "  ❌ Rate limit not triggered after 80 requests"
    FAILURES=$((FAILURES + 1))
fi

# Test 3: Rate limit response body contains expected fields
echo ""
echo "=== Test: Rate limit response body ==="
# Exhaust rate limit first
for i in $(seq 1 80); do
    curl -s -o /dev/null --max-time 5 "$BASE_URL/" || true
done
response=$(curl -s --max-time 5 "$BASE_URL/" || true)
if echo "$response" | grep -q '"status"'; then
    echo "  ✅ Response body contains status field"
    PASS=$((PASS + 1))
else
    echo "  ❌ Response body missing expected fields: $response"
    FAILURES=$((FAILURES + 1))
fi

# Test 4: Rate limit resets after waiting
echo ""
echo "=== Test: Rate limit resets after delay ==="
sleep 3
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE_URL/" || true)
assert_eq "$status" "200" "Healthcheck after rate limit reset"

# Test 5: Rate limit 429 status code is correct
echo ""
echo "=== Test: Rate limit returns HTTP 429 ==="
# Exhaust rate limit
for i in $(seq 1 80); do
    curl -s -o /dev/null --max-time 5 "$BASE_URL/" || true
done
status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE_URL/" || true)
assert_eq "$status" "429" "HTTP 429 Too Many Requests"

# --- Results ---
echo ""
echo "=== Results: $PASS passed, $FAILURES failed ==="
if [ "$FAILURES" -gt 0 ]; then
    exit 1
fi
