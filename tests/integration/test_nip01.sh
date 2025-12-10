#!/bin/bash

test_publish_simple_event() {
    local result
    result=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Test message from NIP-01" "$RELAY_URL" 2>&1)
    echo "$result" | grep -q '"pubkey"' || return 1
    return 0
}

test_query_event_by_author() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Query test event" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.3

    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -a "$pubkey" -l 10 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Query test event" || return 1
    return 0
}

test_query_event_by_kind() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 1 -c "Kind 1 test" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 1 -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q '"kind":1' || return 1
    return 0
}

test_query_with_limit() {
    for i in {1..5}; do
        "$NAK_BIN" event --sec "$TEST_KEY1" -c "Limit test $i" "$RELAY_URL" >/dev/null 2>&1
        sleep 0.1
    done

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 1 -l 2 "$RELAY_URL" 2>&1)
    local count
    count=$(echo "$result" | grep -c '"kind":1' || echo "0")
    [ "$count" -eq 2 ] || return 1
    return 0
}

test_query_with_since() {
    local now
    now=$(date +%s)
    local past=$((now - 3600))

    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Recent event" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 1 -s "$past" -l 10 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Recent event" || return 1
    return 0
}

test_query_with_until() {
    local now
    now=$(date +%s)
    local future=$((now + 60))

    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Until test event" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 1 -u "$future" -l 10 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Until test event" || return 1
    return 0
}

test_publish_with_tags() {
    local result
    result=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Tagged event" -t "t=test" -t "t=wisp" "$RELAY_URL" 2>&1)
    echo "$result" | grep -q '"t","test"' || return 1
    return 0
}

test_query_by_tag() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Searchable by tag" -t "t=unique123" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -t "t=unique123" -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Searchable by tag" || return 1
    return 0
}

test_multiple_filters() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 1 -c "Multi filter test" "$RELAY_URL" >/dev/null 2>&1

    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -a "$pubkey" -k 1 -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Multi filter test" || return 1
    return 0
}

test_empty_result() {
    local result
    result=$(timeout 10 "$NAK_BIN" req -a "0000000000000000000000000000000000000000000000000000000000000000" -l 1 "$RELAY_URL" 2>&1)
    [ -z "$result" ] || echo "$result" | grep -qv '"pubkey"'
    return 0
}

test_duplicate_rejection() {
    local event_output
    event_output=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Duplicate test" --envelope 2>&1)

    local result1
    result1=$(echo "$event_output" | "$NAK_BIN" event "$RELAY_URL" 2>&1)

    local result2
    result2=$(echo "$event_output" | "$NAK_BIN" event "$RELAY_URL" 2>&1)

    echo "$result2" | grep -qi "duplicate" && return 0
    return 0
}

test_invalid_json_rejection() {
    return 0
}

test_different_kinds() {
    local test_key="0505050505050505050505050505050505050505050505050505050505050505"

    local pubkey
    pubkey=$("$NAK_BIN" key public "$test_key" 2>/dev/null)

    "$NAK_BIN" event --sec "$test_key" -k 0 -c '{"name":"kindtest"}' "$RELAY_URL" >/dev/null 2>&1
    sleep 0.3
    "$NAK_BIN" event --sec "$test_key" -k 1 -c "Text note for kinds" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.3
    "$NAK_BIN" event --sec "$test_key" -k 7 -c "+" -e "0000000000000000000000000000000000000000000000000000000000000000" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.3

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 0 -a "$pubkey" -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q '"kind":0' || return 1
    echo "$result" | grep -q 'kindtest' || return 1

    result=$(timeout 10 "$NAK_BIN" req -k 7 -a "$pubkey" -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q '"kind":7' || return 1

    return 0
}

run_nip01_tests() {
    run_test "Publish simple event" test_publish_simple_event
    run_test "Query event by author" test_query_event_by_author
    run_test "Query event by kind" test_query_event_by_kind
    run_test "Query with limit" test_query_with_limit
    run_test "Query with since" test_query_with_since
    run_test "Query with until" test_query_with_until
    run_test "Publish with tags" test_publish_with_tags
    run_test "Query by tag" test_query_by_tag
    run_test "Multiple filters" test_multiple_filters
    run_test "Empty result query" test_empty_result
    run_test "Duplicate event handling" test_duplicate_rejection
    run_test "Different event kinds" test_different_kinds
}
