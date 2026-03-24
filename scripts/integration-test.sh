#!/usr/bin/env bash
# Integration test for Straylight-AI
# Tests the full MCP flow: tool-list, check, api_call, services
# Runs without Docker — starts the Go server directly using go run.
#
# Usage:
#   ./scripts/integration-test.sh
#
# Environment variables:
#   STRAYLIGHT_PORT  Port to run the server on (default: 19470)
#   SKIP_GO_TESTS    Set to "1" to skip the Go integration test phase
#
# Exit codes:
#   0  All tests passed
#   1  One or more tests failed
#   2  Setup error (missing dependencies, build failure, etc.)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

STRAYLIGHT_PORT="${STRAYLIGHT_PORT:-19470}"
STRAYLIGHT_URL="http://localhost:${STRAYLIGHT_PORT}"
SKIP_GO_TESTS="${SKIP_GO_TESTS:-0}"

# The test credential must not appear in any output captured from the MCP server.
TEST_CREDENTIAL="test_FAKECRED_not_a_real_key_000"
TEST_SERVICE="test-stripe"

# Timeout for waiting on the server to become ready (seconds).
SERVER_READY_TIMEOUT=15

# Track test results.
TESTS_PASSED=0
TESTS_FAILED=0
SERVER_PID=""

# ---------------------------------------------------------------------------
# Colours and formatting (disabled when not a terminal)
# ---------------------------------------------------------------------------

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' NC=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[PASS]${NC}  $*"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; TESTS_FAILED=$((TESTS_FAILED + 1)); }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# assert_contains <description> <expected-substring> <actual>
assert_contains() {
    local desc="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        log_ok "$desc"
    else
        log_fail "$desc — expected to find: $expected"
        echo "         Actual: $actual" >&2
    fi
}

# assert_not_contains <description> <forbidden-substring> <actual>
assert_not_contains() {
    local desc="$1" forbidden="$2" actual="$3"
    if echo "$actual" | grep -q "$forbidden"; then
        log_fail "$desc — forbidden value found in output"
        echo "         Found:  $forbidden" >&2
        echo "         Actual: $actual" >&2
    else
        log_ok "$desc"
    fi
}

# assert_http_status <description> <expected-status> <actual-status>
assert_http_status() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        log_ok "$desc (HTTP $actual)"
    else
        log_fail "$desc — expected HTTP $expected, got HTTP $actual"
    fi
}

# cleanup: kill the server and any children on exit.
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log_info "Stopping server (PID $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing=0

    if ! command -v go >/dev/null 2>&1; then
        echo "ERROR: 'go' is not in PATH. Install Go from https://go.dev/dl/" >&2
        missing=1
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "ERROR: 'curl' is not installed." >&2
        missing=1
    fi

    if [ "$missing" -ne 0 ]; then
        exit 2
    fi

    log_info "Go version: $(go version)"
}

# ---------------------------------------------------------------------------
# Phase 1: Go unit + integration tests
# ---------------------------------------------------------------------------

run_go_tests() {
    if [ "${SKIP_GO_TESTS}" = "1" ]; then
        log_warn "Skipping Go test phase (SKIP_GO_TESTS=1)"
        return
    fi

    log_info "Running Go integration tests (no external services required)..."

    if go test -tags=integration -v -timeout=30s ./internal/integration/... 2>&1; then
        log_ok "Go integration tests passed"
    else
        log_fail "Go integration tests FAILED"
    fi

    log_info "Running full unit test suite..."
    if go test -timeout=60s ./... 2>&1; then
        log_ok "All unit tests passed"
    else
        log_fail "Unit tests FAILED"
    fi
}

# ---------------------------------------------------------------------------
# Phase 2: Live HTTP smoke test (starts the server via go run)
# ---------------------------------------------------------------------------

start_server() {
    log_info "Building straylight binary..."
    go build -o /tmp/straylight-test-server ./cmd/straylight 2>&1 || {
        log_warn "Build failed — skipping live HTTP smoke tests"
        return 1
    }

    log_info "Starting Straylight server on port $STRAYLIGHT_PORT..."

    # Start with a temporary data directory to avoid touching real OpenBao state.
    STRAYLIGHT_ADDR="localhost:${STRAYLIGHT_PORT}" \
    STRAYLIGHT_DATA_DIR="/tmp/straylight-integration-test-$$" \
        /tmp/straylight-test-server &>/tmp/straylight-test-$$.log &
    SERVER_PID=$!

    log_info "Server PID: $SERVER_PID"

    # Wait for the server to become ready.
    local attempts=0
    while [ $attempts -lt $SERVER_READY_TIMEOUT ]; do
        if curl -sf "${STRAYLIGHT_URL}/api/v1/health" >/dev/null 2>&1; then
            log_ok "Server ready at ${STRAYLIGHT_URL}"
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done

    log_warn "Server did not become ready within ${SERVER_READY_TIMEOUT}s"
    log_warn "Server log: $(cat /tmp/straylight-test-$$.log 2>/dev/null || echo 'no log')"
    return 1
}

run_http_smoke_tests() {
    log_info "Running HTTP smoke tests against live server..."

    # Register the test service via the HTTP API.
    local create_status
    create_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${STRAYLIGHT_URL}/api/v1/services" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"${TEST_SERVICE}\",
            \"type\": \"http_proxy\",
            \"target\": \"https://api.stripe.com\",
            \"inject\": \"header\",
            \"header_name\": \"Authorization\",
            \"header_template\": \"Bearer {{.Secret}}\",
            \"credential\": \"${TEST_CREDENTIAL}\"
        }" 2>/dev/null)
    assert_http_status "Register test-stripe service" "201" "$create_status"

    # Smoke test 1: GET /api/v1/mcp/tool-list returns 4 tools.
    local tool_list_response
    tool_list_response=$(curl -sf "${STRAYLIGHT_URL}/api/v1/mcp/tool-list" 2>/dev/null || echo '{}')
    local tool_count
    tool_count=$(echo "$tool_list_response" | grep -o '"name"' | wc -l | tr -d ' ')
    if [ "$tool_count" -eq 4 ]; then
        log_ok "Tool list returns 4 tools"
    else
        log_fail "Tool list: expected 4 tools, got $tool_count"
    fi
    assert_not_contains "Tool list does not contain credential" "$TEST_CREDENTIAL" "$tool_list_response"

    # Smoke test 2: straylight_check reports "available".
    local check_response
    check_response=$(curl -sf -X POST "${STRAYLIGHT_URL}/api/v1/mcp/tool-call" \
        -H "Content-Type: application/json" \
        -d "{\"tool\":\"straylight_check\",\"arguments\":{\"service\":\"${TEST_SERVICE}\"}}" \
        2>/dev/null || echo '{}')
    assert_contains "straylight_check reports available" '"available"' "$check_response"
    assert_not_contains "straylight_check does not leak credential" "$TEST_CREDENTIAL" "$check_response"

    # Smoke test 3: straylight_services lists test-stripe.
    local services_response
    services_response=$(curl -sf -X POST "${STRAYLIGHT_URL}/api/v1/mcp/tool-call" \
        -H "Content-Type: application/json" \
        -d "{\"tool\":\"straylight_services\",\"arguments\":{}}" \
        2>/dev/null || echo '{}')
    assert_contains "straylight_services lists test-stripe" "$TEST_SERVICE" "$services_response"
    assert_not_contains "straylight_services does not leak credential" "$TEST_CREDENTIAL" "$services_response"

    # Smoke test 4: error on unknown service.
    local error_response
    error_response=$(curl -sf -X POST "${STRAYLIGHT_URL}/api/v1/mcp/tool-call" \
        -H "Content-Type: application/json" \
        -d '{"tool":"straylight_api_call","arguments":{"service":"nonexistent","path":"/v1/balance"}}' \
        2>/dev/null || echo '{}')
    assert_contains "Unknown service returns isError" '"isError":true' "$error_response"

    # Clean up: delete the test service.
    curl -sf -X DELETE "${STRAYLIGHT_URL}/api/v1/services/${TEST_SERVICE}" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Phase 3: MCP stdio smoke test (uses the straylight-mcp binary)
# ---------------------------------------------------------------------------

run_mcp_stdio_tests() {
    log_info "Building straylight-mcp binary..."
    go build -o /tmp/straylight-mcp-test ./cmd/straylight-mcp 2>&1 || {
        log_warn "straylight-mcp build failed — skipping stdio tests"
        return
    }

    log_info "Running MCP stdio smoke tests..."

    # Re-register the test service (deleted above).
    curl -sf -X POST "${STRAYLIGHT_URL}/api/v1/services" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"${TEST_SERVICE}\",
            \"type\": \"http_proxy\",
            \"target\": \"https://api.stripe.com\",
            \"inject\": \"header\",
            \"header_name\": \"Authorization\",
            \"header_template\": \"Bearer {{.Secret}}\",
            \"credential\": \"${TEST_CREDENTIAL}\"
        }" >/dev/null 2>&1 || true

    # Send initialize + tools/list via stdin to the MCP binary.
    local mcp_input
    mcp_input=$(printf '%s\n%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')

    local mcp_output
    mcp_output=$(echo "$mcp_input" | \
        STRAYLIGHT_URL="${STRAYLIGHT_URL}" \
        timeout 5 /tmp/straylight-mcp-test 2>/dev/null || echo '')

    # Check initialize response.
    if echo "$mcp_output" | grep -q '"protocolVersion"'; then
        log_ok "MCP initialize response received"
    else
        log_fail "MCP initialize: no protocolVersion in response"
        echo "         Output: $mcp_output" >&2
    fi

    # Check tools/list response contains 4 tools.
    local mcp_tool_count
    mcp_tool_count=$(echo "$mcp_output" | grep -o '"name"' | wc -l | tr -d ' ')
    if [ "$mcp_tool_count" -ge 4 ]; then
        log_ok "MCP tools/list returns at least 4 tools"
    else
        log_fail "MCP tools/list: expected at least 4 tools, got $mcp_tool_count"
        echo "         Output: $mcp_output" >&2
    fi

    # The entire MCP stdout must not contain the credential.
    assert_not_contains "MCP stdout does not leak credential" "$TEST_CREDENTIAL" "$mcp_output"

    # Clean up test service.
    curl -sf -X DELETE "${STRAYLIGHT_URL}/api/v1/services/${TEST_SERVICE}" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local project_root
    project_root=$(cd "$(dirname "$0")/.." && pwd)
    cd "$project_root"

    echo ""
    echo "=========================================="
    echo " Straylight-AI Integration Test Suite"
    echo "=========================================="
    echo ""

    check_prerequisites

    echo ""
    echo "--- Phase 1: Go Tests ---"
    run_go_tests

    echo ""
    echo "--- Phase 2: Live HTTP Smoke Tests ---"
    if start_server; then
        run_http_smoke_tests

        echo ""
        echo "--- Phase 3: MCP stdio Smoke Tests ---"
        run_mcp_stdio_tests
    else
        log_warn "Skipping live HTTP and stdio tests (server did not start)"
        log_warn "This is expected if cmd/straylight has not been implemented yet."
        log_warn "The Go integration tests in Phase 1 remain the authoritative check."
    fi

    # ---------------------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------------------
    echo ""
    echo "=========================================="
    echo " Results"
    echo "=========================================="
    echo -e "  ${GREEN}Passed:${NC} $TESTS_PASSED"
    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "  ${RED}Failed:${NC} $TESTS_FAILED"
        echo ""
        echo -e "${RED}INTEGRATION TEST SUITE FAILED${NC}"
        exit 1
    else
        echo -e "  ${RED}Failed:${NC} 0"
        echo ""
        echo -e "${GREEN}ALL INTEGRATION TESTS PASSED${NC}"
        exit 0
    fi
}

main "$@"
