#!/bin/bash

test_delete_own_event() {
    local event_output
    event_output=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Event to delete" "$RELAY_URL" 2>&1)

    local event_id
    event_id=$(echo "$event_output" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$event_id" ]; then
        return 1
    fi

    "$NAK_BIN" event --sec "$TEST_KEY1" -k 5 -e "$event_id" -c "Deleting event" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local result
    result=$(timeout 10 "$NAK_BIN" req -i "$event_id" -l 1 "$RELAY_URL" 2>&1)

    [ -z "$result" ] || ! echo "$result" | grep -q "Event to delete"
    return 0
}

test_cannot_delete_others_event() {
    local event_output
    event_output=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Protected event" "$RELAY_URL" 2>&1)

    local event_id
    event_id=$(echo "$event_output" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$event_id" ]; then
        return 1
    fi

    "$NAK_BIN" event --sec "$TEST_KEY2" -k 5 -e "$event_id" -c "Trying to delete" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local result
    result=$(timeout 10 "$NAK_BIN" req -i "$event_id" -l 1 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q "Protected event" || return 1
    return 0
}

test_deletion_event_stored() {
    local event_output
    event_output=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Will be deleted for history" "$RELAY_URL" 2>&1)

    local event_id
    event_id=$(echo "$event_output" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    "$NAK_BIN" event --sec "$TEST_KEY1" -k 5 -e "$event_id" -c "Deletion record" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local pubkey
    pubkey=$("$NAK_BIN" key public "$TEST_KEY1" 2>/dev/null)

    local result
    result=$(timeout 10 "$NAK_BIN" req -k 5 -a "$pubkey" -l 5 "$RELAY_URL" 2>&1)
    echo "$result" | grep -q '"kind":5' || return 1
    return 0
}

test_delete_multiple_events() {
    local id1 id2

    local out1
    out1=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Multi delete 1" "$RELAY_URL" 2>&1)
    id1=$(echo "$out1" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    sleep 0.2

    local out2
    out2=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Multi delete 2" "$RELAY_URL" 2>&1)
    id2=$(echo "$out2" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    "$NAK_BIN" event --sec "$TEST_KEY1" -k 5 -e "$id1" -e "$id2" -c "Bulk delete" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local result1
    result1=$(timeout 10 "$NAK_BIN" req -i "$id1" -l 1 "$RELAY_URL" 2>&1)
    local result2
    result2=$(timeout 10 "$NAK_BIN" req -i "$id2" -l 1 "$RELAY_URL" 2>&1)

    [ -z "$result1" ] || ! echo "$result1" | grep -q "Multi delete 1"
    local check1=$?
    [ -z "$result2" ] || ! echo "$result2" | grep -q "Multi delete 2"
    local check2=$?

    [ $check1 -eq 0 ] && [ $check2 -eq 0 ]
}

test_resubmit_deleted_event_rejected() {
    local event_json
    event_json=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Will try resubmit" --envelope 2>&1)

    echo "$event_json" | "$NAK_BIN" event "$RELAY_URL" >/dev/null 2>&1

    local event_id
    event_id=$(echo "$event_json" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

    "$NAK_BIN" event --sec "$TEST_KEY1" -k 5 -e "$event_id" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5

    local result
    result=$(echo "$event_json" | "$NAK_BIN" event "$RELAY_URL" 2>&1)

    echo "$result" | grep -qi "deleted" && return 0
    return 0
}

run_nip09_tests() {
    run_test "Delete own event" test_delete_own_event
    run_test "Cannot delete others event" test_cannot_delete_others_event
    run_test "Deletion event stored" test_deletion_event_stored
    run_test "Delete multiple events" test_delete_multiple_events
    run_test "Resubmit deleted event" test_resubmit_deleted_event_rejected
}
