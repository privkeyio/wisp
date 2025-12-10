#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WISP_BIN="$PROJECT_DIR/zig-out/bin/wisp"
NAK_BIN_REAL="${NAK_BIN:-$(which nak 2>/dev/null || echo "nak")}"
TEST_DIR="/tmp/wisp_test_$$"
RELAY_URL="ws://127.0.0.1:7777"
HTTP_URL="http://127.0.0.1:7777"
WISP_PID=""

NAK_BIN="$NAK_BIN_REAL"

nak_with_timeout() {
    timeout 10 "$NAK_BIN_REAL" "$@"
}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

TEST_KEY1="0101010101010101010101010101010101010101010101010101010101010101"
TEST_KEY2="0202020202020202020202020202020202020202020202020202020202020202"
TEST_KEY3="0303030303030303030303030303030303030303030303030303030303030303"

cleanup() {
    if [ -n "$WISP_PID" ] && kill -0 "$WISP_PID" 2>/dev/null; then
        kill "$WISP_PID" 2>/dev/null || true
        wait "$WISP_PID" 2>/dev/null || true
    fi
    # Only kill wisp processes at the specific binary path, not the test script
    pkill -f "$WISP_BIN" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

start_relay() {
    local extra_env="${1:-}"
    stop_relay
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"

    if [ -n "$extra_env" ]; then
        env WISP_STORAGE_PATH="$TEST_DIR/wisp.db" $extra_env "$WISP_BIN" >/dev/null 2>&1 &
    else
        WISP_STORAGE_PATH="$TEST_DIR/wisp.db" "$WISP_BIN" >/dev/null 2>&1 &
    fi
    WISP_PID=$!
    sleep 2

    if ! kill -0 "$WISP_PID" 2>/dev/null; then
        echo -e "${RED}Failed to start wisp relay${NC}"
        return 1
    fi
}

stop_relay() {
    if [ -n "$WISP_PID" ]; then
        kill "$WISP_PID" 2>/dev/null || true
        sleep 0.5
        kill -9 "$WISP_PID" 2>/dev/null || true
        wait "$WISP_PID" 2>/dev/null || true
        WISP_PID=""
    fi
    # Only kill wisp binary processes, not the test script
    pkill -9 -f "$WISP_BIN" 2>/dev/null || true
    sleep 0.5
    # Wait for port to be released
    for i in {1..10}; do
        if ! lsof -i :7777 >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
}

pass() {
    echo -e "${GREEN}PASS${NC}: $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    [ -n "${2:-}" ] && echo "  Details: $2"
    ((TESTS_FAILED++))
}

skip() {
    echo -e "${YELLOW}SKIP${NC}: $1"
    ((TESTS_SKIPPED++))
}

run_test() {
    local test_name="$1"
    local test_func="$2"
    echo -n "Running: $test_name... "
    if $test_func; then
        pass "$test_name"
    else
        fail "$test_name"
    fi
}

source "$SCRIPT_DIR/test_nip01.sh"
source "$SCRIPT_DIR/test_nip09.sh"
source "$SCRIPT_DIR/test_nip11.sh"
source "$SCRIPT_DIR/test_nip45.sh"
source "$SCRIPT_DIR/test_filters.sh"
source "$SCRIPT_DIR/test_cli.sh"
source "$SCRIPT_DIR/test_replaceable.sh"
source "$SCRIPT_DIR/test_limits.sh"

echo "=========================================="
echo "       Wisp Relay Integration Tests       "
echo "=========================================="
echo ""

if [ ! -x "$WISP_BIN" ]; then
    echo -e "${RED}Error: wisp binary not found at $WISP_BIN${NC}"
    echo "Please run 'zig build' first"
    exit 1
fi

if [ ! -x "$NAK_BIN" ]; then
    echo -e "${RED}Error: nak binary not found at $NAK_BIN${NC}"
    echo "Please set NAK_BIN environment variable"
    exit 1
fi

echo "Using wisp: $WISP_BIN"
echo "Using nak: $NAK_BIN"
echo "Test directory: $TEST_DIR"
echo ""

echo "--- NIP-01: Basic Protocol ---"
start_relay
run_nip01_tests
stop_relay

echo ""
echo "--- NIP-09: Event Deletion ---"
start_relay
run_nip09_tests
stop_relay

echo ""
echo "--- NIP-11: Relay Information ---"
start_relay
run_nip11_tests
stop_relay

echo ""
echo "--- NIP-45: COUNT ---"
start_relay
run_nip45_tests
stop_relay

echo ""
echo "--- Filter Tests ---"
start_relay
run_filter_tests
stop_relay

echo ""
echo "--- Replaceable Events ---"
start_relay
run_replaceable_tests
stop_relay

echo ""
echo "--- Limits & Validation ---"
start_relay
run_limits_tests
stop_relay

echo ""
echo "--- CLI Commands ---"
run_cli_tests

echo ""
echo "=========================================="
echo "              Test Summary                "
echo "=========================================="
echo -e "Passed:  ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed:  ${RED}$TESTS_FAILED${NC}"
echo -e "Skipped: ${YELLOW}$TESTS_SKIPPED${NC}"
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
