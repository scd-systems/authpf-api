#!/bin/bash
# e2e_test.sh - End-to-end test for authpf-api
# Starts the API as a separate process and runs client tests via curl
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
E2E_TMP=$(mktemp -d)
E2E_PORT=19999
BASE_URL="http://127.0.0.1:$E2E_PORT"
API_PID=""

# Shared password hash (both users share the same password)
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
# Sends an HTTP request and checks the status code
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
    local body=$(echo "$resp" | head -1)
    check "Login $user" 200 "$status"
    TOKEN=$(echo "$body" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
}

# activate TOKEN USERNAME [-t TARGET] EXPECTED NAME
activate() {
    local token="$1" user="$2" target="" expected="$3" name="$4"
    shift 4
    while [ $# -gt 0 ]; do
        case "$1" in -t) target="$2"; shift 2;; *) shift;; esac
    done
    local path="/api/v1/authpf/activate"
    [ -n "$target" ] && path="$path?authpf_username=$target"
    req POST "$path" "$token" "{\"username\":\"$user\"}" "$expected" "$name"
}

# deactivate TOKEN USERNAME [-t TARGET] [-a] EXPECTED NAME
# -t TARGET sets ?authpf_username= query param
# -a uses DELETE /api/v1/authpf/all instead
deactivate() {
    local token="$1" user="$2" target="" all="" expected="$3" name="$4"
    shift 4
    while [ $# -gt 0 ]; do
        case "$1" in -t) target="$2"; shift 2;; -a) all=1; shift;; *) shift;; esac
    done
    if [ -n "$all" ]; then
        req DELETE "/api/v1/authpf/all" "$token" "" "$expected" "$name"
    else
        local path="/api/v1/authpf/activate"
        [ -n "$target" ] && path="$path?authpf_username=$target"
        req DELETE "$path" "$token" "{\"username\":\"$user\"}" "$expected" "$name"
    fi
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
echo "=== E2E Test Setup ==="

# Password hash
PW_HASH=$(echo "testpassword123" | go run "$PROJECT_DIR/cmd/main.go" -gen-user-password 2>/dev/null)
[ -z "$PW_HASH" ] && { echo "Failed to generate password hash"; exit 1; }

# Mock sudo
printf '#!/bin/bash\nexec "$@"\n' > "$E2E_TMP/sudo"
chmod +x "$E2E_TMP/sudo"

# Rules for both users
for user in testuser limiteduser; do
    mkdir -p "$E2E_TMP/rules/$user"
    printf '# rules for %s\npass all\n' "$user" > "$E2E_TMP/rules/$user/rules"
done

# Config
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
    user:
      permissions:
        - "activate_own_rules"
        - "deactivate_own_rules"
        - "view_own_rules"
  users:
    testuser:
      password: "$PW_HASH"
      role: "admin"
      userId: 1000
    limiteduser:
      password: "$PW_HASH"
      role: "user"
      userId: 2000
CONF
chmod 0640 "$E2E_TMP/authpf-api.conf"

# Start API
echo "=== Starting authpf-api ==="
export PATH="$E2E_TMP:$PATH"
cd "$PROJECT_DIR" && go build -o "$E2E_TMP/authpf-api" cmd/main.go
"$E2E_TMP/authpf-api" -c "$E2E_TMP/authpf-api.conf" -foreground &
API_PID=$!

echo "Waiting for server..."
for i in $(seq 1 40); do
    curl -s "$BASE_URL/" >/dev/null 2>&1 && { echo "Server ready after ${i}00ms"; break; }
    sleep 0.5
done

# --- Tests ---
echo ""
echo "=== E2E Client Tests ==="

# Admin workflow
req GET "/" "" "" 200 "Healthcheck"
login "testuser"
ADMIN_TOKEN="$TOKEN"
activate "$ADMIN_TOKEN" "testuser" 201 "Activate"
req GET "/api/v1/authpf/activate" "$ADMIN_TOKEN" "" 200 "Get Status"
activate "$ADMIN_TOKEN" "testuser" 208 "Duplicate Activate"
req GET "/info" "" "" 200 "Info"
deactivate "$ADMIN_TOKEN" "testuser" 202 "Deactivate"
req GET "/api/v1/authpf/activate" "$ADMIN_TOKEN" "" 200 "Status after Deactivate"

echo ""
echo "=== Limited User Tests ==="

# Limited user workflow
login "limiteduser"
LIMITED_TOKEN="$TOKEN"
activate "$LIMITED_TOKEN" "limiteduser" 201 "Limited User Activate Own"
activate "$LIMITED_TOKEN" "limiteduser" 403 "Limited User Activate Other (denied)" -t testuser
activate "$ADMIN_TOKEN" "testuser" 201 "Admin Activate testuser"
deactivate "$LIMITED_TOKEN" "" 403 "Limited User Deactivate-All (denied)" -a
deactivate "$LIMITED_TOKEN" "limiteduser" 403 "Limited User Deactivate Other (denied)" -t testuser
deactivate "$LIMITED_TOKEN" "limiteduser" 202 "Limited User Deactivate Own"
deactivate "$ADMIN_TOKEN" "" 200 "Admin Deactivate-All" -a
req GET "/api/v1/authpf/all" "$LIMITED_TOKEN" "" 403 "Limited User View All (denied)"

# --- Results ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
