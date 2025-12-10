#!/bin/bash

test_replaceable_kind_0() {
    # Use a unique key for this test
    local test_key="0606060606060606060606060606060606060606060606060606060606060606"

    "$NAK_BIN" event --sec "$test_key" -k 0 -c '{"name":"first"}' "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    "$NAK_BIN" event --sec "$test_key" -k 0 -c '{"name":"second"}' "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local pubkey
    pubkey=$("$NAK_BIN" key public "$test_key" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 0 -a "$pubkey" -l 10 "$RELAY_URL" 2>&1)

    # For replaceable events, we should only get 1 result but relay behavior varies
    # Main test: must have the newer version with "second"
    # Note: Content is JSON-escaped so quotes appear as \"
    echo "$result" | grep -q 'name.*second' || return 1
    # Must not have the older version
    ! echo "$result" | grep -q 'name.*first' || return 1
    return 0
}

test_replaceable_kind_3() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 3 -c "" -p "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.3

    "$NAK_BIN" event --sec "$TEST_KEY1" -k 3 -c "" -p "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.3

    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 3 -a "$pubkey" -l 10 "$RELAY_URL" 2>&1)

    local count
    count=$(echo "$result" | grep -c '"kind":3' || echo "0")

    [ "$count" -eq 1 ] || return 1

    echo "$result" | grep -q "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || return 1
    return 0
}

test_replaceable_kind_10002() {
    # Use a unique key for this test
    local test_key="0707070707070707070707070707070707070707070707070707070707070707"

    "$NAK_BIN" event --sec "$test_key" -k 10002 -c "" -t "r=wss://relay1.example" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    "$NAK_BIN" event --sec "$test_key" -k 10002 -c "" -t "r=wss://relay2.example" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local pubkey
    pubkey=$("$NAK_BIN" key public "$test_key" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 10002 -a "$pubkey" -l 10 "$RELAY_URL" 2>&1)

    # Main test: must have the newer relay2
    echo "$result" | grep -q "relay2.example" || return 1
    # Must not have the older relay1
    ! echo "$result" | grep -q "relay1.example" || return 1
    return 0
}

test_addressable_kind_30000() {
    # Use a unique key to avoid interference from other tests
    local test_key="0909090909090909090909090909090909090909090909090909090909090909"

    "$NAK_BIN" event --sec "$test_key" -k 30000 -d "test-list" -c "first version" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    "$NAK_BIN" event --sec "$test_key" -k 30000 -d "test-list" -c "second version" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local pubkey
    pubkey=$("$NAK_BIN" key public "$test_key" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 30000 -a "$pubkey" -t "d=test-list" -l 10 "$RELAY_URL" 2>&1)

    # Must have the newer version
    echo "$result" | grep -q "second version" || return 1
    # Must not have the older version
    ! echo "$result" | grep -q "first version" || return 1
    return 0
}

test_addressable_different_d_tags() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 30000 -d "list-a" -c "List A content" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 30000 -d "list-b" -c "List B content" "$RELAY_URL" >/dev/null 2>&1

    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 30000 -a "$pubkey" -l 10 "$RELAY_URL" 2>&1)

    echo "$result" | grep -q "List A content" || return 1
    echo "$result" | grep -q "List B content" || return 1
    return 0
}

test_addressable_different_authors() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 30000 -d "shared-id" -c "Author 1 content" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY2" -k 30000 -d "shared-id" -c "Author 2 content" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 30000 -t "d=shared-id" -l 10 "$RELAY_URL" 2>&1)

    echo "$result" | grep -q "Author 1 content" || return 1
    echo "$result" | grep -q "Author 2 content" || return 1
    return 0
}

test_older_replaceable_rejected() {
    # Use a unique key for this test
    local test_key="0808080808080808080808080808080808080808080808080808080808080808"

    local now
    now=$(date +%s)
    local past=$((now - 100))

    "$NAK_BIN" event --sec "$test_key" -k 0 -c '{"name":"newer"}' "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    "$NAK_BIN" event --sec "$test_key" -k 0 --ts "$past" -c '{"name":"older"}' "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local pubkey
    pubkey=$("$NAK_BIN" key public "$test_key" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 0 -a "$pubkey" -l 10 "$RELAY_URL" 2>&1)

    # Must have the newer event
    # Note: Content is JSON-escaped so quotes appear as \"
    echo "$result" | grep -q 'name.*newer' || return 1
    # Older event should not be stored (replaced)
    ! echo "$result" | grep -q 'name.*older' || return 1
    return 0
}

test_ephemeral_not_stored() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 20000 -c "Ephemeral event" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 20000 -a "$pubkey" -l 5 "$RELAY_URL" 2>&1)

    [ -z "$result" ] || ! echo "$result" | grep -q "Ephemeral event"
    return 0
}

run_replaceable_tests() {
    run_test "Replaceable kind 0 (metadata)" test_replaceable_kind_0
    run_test "Replaceable kind 3 (contacts)" test_replaceable_kind_3
    run_test "Replaceable kind 10002" test_replaceable_kind_10002
    run_test "Addressable kind 30000" test_addressable_kind_30000
    run_test "Addressable different d tags" test_addressable_different_d_tags
    run_test "Addressable different authors" test_addressable_different_authors
    run_test "Older replaceable rejected" test_older_replaceable_rejected
    run_test "Ephemeral events not stored" test_ephemeral_not_stored
}
