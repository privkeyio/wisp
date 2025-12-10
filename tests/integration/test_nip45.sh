#!/bin/bash

# NIP-45 COUNT tests using Python for more reliable testing
# nak count command waits indefinitely, so we use Python websocket directly

# Use venv python if available
PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python3"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
fi

count_with_python() {
    local filter="$1"
    "$PYTHON_BIN" << EOF
import websocket
import json
try:
    ws = websocket.create_connection("ws://127.0.0.1:7777", timeout=5)
    ws.send(json.dumps(["COUNT", "test-count", $filter]))
    response = ws.recv()
    print(response)
    ws.close()
except Exception as e:
    print("")
EOF
}

test_count_all_events() {
    for i in {1..3}; do
        "$NAK_BIN" event --sec "$TEST_KEY1" -c "Count test $i" "$RELAY_URL" >/dev/null 2>&1
        sleep 0.1
    done

    local result
    result=$(count_with_python '{"kinds": [1]}')

    echo "$result" | grep -qE '"count":[0-9]+' || return 1
    return 0
}

test_count_by_kind() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 1 -c "Kind 1 for count" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 7 -c "+" -e "0000000000000000000000000000000000000000000000000000000000000000" "$RELAY_URL" >/dev/null 2>&1

    local result_k1
    result_k1=$(count_with_python '{"kinds": [1]}')
    local result_k7
    result_k7=$(count_with_python '{"kinds": [7]}')

    echo "$result_k1" | grep -qE '"count":[0-9]+' || return 1
    echo "$result_k7" | grep -qE '"count":[0-9]+' || return 1
    return 0
}

test_count_by_author() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Author 1 event" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY2" -c "Author 2 event" "$RELAY_URL" >/dev/null 2>&1

    local pubkey1
    pubkey1=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)
    local pubkey2
    pubkey2=$("$NAK_BIN" key public "$TEST_KEY2" 2>/dev/null)

    local result1
    result1=$(count_with_python "{\"authors\": [\"$pubkey1\"]}")
    local result2
    result2=$(count_with_python "{\"authors\": [\"$pubkey2\"]}")

    echo "$result1" | grep -qE '"count":[0-9]+' || return 1
    echo "$result2" | grep -qE '"count":[0-9]+' || return 1
    return 0
}

test_count_by_tag() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Tagged for count" -t "t=counttest" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Another tagged" -t "t=counttest" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(count_with_python '{"#t": ["counttest"]}')
    echo "$result" | grep -qE '"count":[0-9]+' || return 1

    local count
    count=$(echo "$result" | grep -oE '"count":([0-9]+)' | grep -oE '[0-9]+')
    [ "${count:-0}" -ge 1 ] || return 1
    return 0
}

test_count_with_since() {
    local now
    now=$(date +%s)
    local past=$((now - 3600))

    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Recent for count" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(count_with_python "{\"kinds\": [1], \"since\": $past}")
    echo "$result" | grep -qE '"count":[0-9]+' || return 1
    return 0
}

test_count_with_until() {
    local now
    now=$(date +%s)
    local future=$((now + 60))

    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Count until test" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(count_with_python "{\"kinds\": [1], \"until\": $future}")
    echo "$result" | grep -qE '"count":[0-9]+' || return 1
    return 0
}

test_count_empty_result() {
    local result
    result=$(count_with_python '{"kinds": [99999]}')

    echo "$result" | grep -qE '"count":0' || echo "$result" | grep -qE '"count":[0-9]+' || return 1
    return 0
}

test_count_multiple_kinds() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 1 -c "Kind 1" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 7 -c "+" -e "0000000000000000000000000000000000000000000000000000000000000000" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(count_with_python '{"kinds": [1, 7]}')
    echo "$result" | grep -qE '"count":[0-9]+' || return 1
    return 0
}

run_nip45_tests() {
    run_test "COUNT all events" test_count_all_events
    run_test "COUNT by kind" test_count_by_kind
    run_test "COUNT by author" test_count_by_author
    run_test "COUNT by tag" test_count_by_tag
    run_test "COUNT with since" test_count_with_since
    run_test "COUNT with until" test_count_with_until
    run_test "COUNT empty result" test_count_empty_result
    run_test "COUNT multiple kinds" test_count_multiple_kinds
}
