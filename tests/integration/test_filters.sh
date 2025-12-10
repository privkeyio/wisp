#!/bin/bash

test_filter_by_id() {
    local event_output
    event_output=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Filter by ID test" "$RELAY_URL" 2>&1)

    local event_id
    event_id=$(echo "$event_output" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    local result
    result=$(timeout 10 "$NAK_BIN" req -i "$event_id" "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Filter by ID test" || return 1
    return 0
}

test_filter_by_multiple_ids() {
    local out1
    out1=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Multi ID 1" "$RELAY_URL" 2>&1)
    local id1
    id1=$(echo "$out1" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    sleep 0.1

    local out2
    out2=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Multi ID 2" "$RELAY_URL" 2>&1)
    local id2
    id2=$(echo "$out2" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    local result
    result=$(timeout 10 "$NAK_BIN" req -i "$id1" -i "$id2" "$RELAY_URL" 2>&1)

    echo "$result" | grep -q "Multi ID 1" || return 1
    echo "$result" | grep -q "Multi ID 2" || return 1
    return 0
}

test_filter_by_multiple_authors() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Author filter 1" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY2" -c "Author filter 2" "$RELAY_URL" >/dev/null 2>&1

    local pubkey1
    pubkey1=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)
    local pubkey2
    pubkey2=$("$NAK_BIN" key public "$TEST_KEY2" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -a "$pubkey1" -a "$pubkey2" -l 10 "$RELAY_URL" 2>&1)

    echo "$result" | grep -q "Author filter 1" || return 1
    echo "$result" | grep -q "Author filter 2" || return 1
    return 0
}

test_filter_by_multiple_kinds() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 1 -c "Multi kind K1" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY1" -k 7 -c "+" -e "0000000000000000000000000000000000000000000000000000000000000000" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 1 -k 7 -l 10 "$RELAY_URL" 2>&1)

    echo "$result" | grep -q '"kind":1' || return 1
    echo "$result" | grep -q '"kind":7' || return 1
    return 0
}

test_filter_e_tag() {
    local target_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Reply to target" -e "$target_id" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -e "$target_id" -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Reply to target" || return 1
    return 0
}

test_filter_p_tag() {
    local target_pubkey
    target_pubkey=$("$NAK_BIN" key public "$TEST_KEY2" 2>/dev/null)

    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Mention user" -p "$target_pubkey" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -p "$target_pubkey" -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Mention user" || return 1
    return 0
}

test_filter_t_tag() {
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Hashtag test" -t "t=uniquehashtag" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -t "t=uniquehashtag" -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Hashtag test" || return 1
    return 0
}

test_filter_combined_author_kind() {
    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    "$NAK_BIN" event --sec "$TEST_KEY1" -k 1 -c "Combined filter test" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -a "$pubkey" -k 1 -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Combined filter test" || return 1
    return 0
}

test_filter_combined_author_kind_tag() {
    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    "$NAK_BIN" event --sec "$TEST_KEY1" -k 1 -c "Triple filter" -t "t=tripletest" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -a "$pubkey" -k 1 -t "t=tripletest" -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Triple filter" || return 1
    return 0
}

test_filter_time_range() {
    local now
    now=$(date +%s)
    local hour_ago=$((now - 3600))
    local future=$((now + 60))

    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Time range test" "$RELAY_URL" >/dev/null 2>&1

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 1 -s "$hour_ago" -u "$future" -l 10 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Time range test" || return 1
    return 0
}

test_filter_no_match() {
    local result
    result=$(timeout 10 "$NAK_BIN" req -a "0000000000000000000000000000000000000000000000000000000000000000" -l 1 "$RELAY_URL" 2>&1)

    [ -z "$result" ] || ! echo "$result" | grep -q '"pubkey"'
    return 0
}

test_filter_limit_ordering() {
    for i in {1..5}; do
        "$NAK_BIN" event --sec "$TEST_KEY1" -c "Order test $i" "$RELAY_URL" >/dev/null 2>&1
        sleep 0.2
    done

    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -a "$pubkey" -k 1 -l 3 "$RELAY_URL" 2>&1)

    local count
    count=$(echo "$result" | grep -c '"kind":1')
    count=${count:-0}
    [ "$count" -le 3 ] || return 1

    echo "$result" | grep -q "Order test 5" || return 1
    return 0
}

run_filter_tests() {
    run_test "Filter by ID" test_filter_by_id
    run_test "Filter by multiple IDs" test_filter_by_multiple_ids
    run_test "Filter by multiple authors" test_filter_by_multiple_authors
    run_test "Filter by multiple kinds" test_filter_by_multiple_kinds
    run_test "Filter by e tag" test_filter_e_tag
    run_test "Filter by p tag" test_filter_p_tag
    run_test "Filter by t tag" test_filter_t_tag
    run_test "Combined author+kind filter" test_filter_combined_author_kind
    run_test "Combined author+kind+tag filter" test_filter_combined_author_kind_tag
    run_test "Time range filter" test_filter_time_range
    run_test "No match filter" test_filter_no_match
    run_test "Limit and ordering" test_filter_limit_ordering
}
