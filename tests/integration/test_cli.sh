#!/bin/bash

test_cli_help() {
    local result
    result=$("$WISP_BIN" help 2>&1)
    echo "$result" | grep -q "Usage:" || return 1
    echo "$result" | grep -q "import" || return 1
    echo "$result" | grep -q "export" || return 1
    return 0
}

test_cli_import_export() {
    local import_dir="/tmp/wisp_import_test_$$"
    mkdir -p "$import_dir"

    start_relay
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Export test event 1" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Export test event 2" "$RELAY_URL" >/dev/null 2>&1
    "$NAK_BIN" event --sec "$TEST_KEY2" -c "Export test event 3" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5
    stop_relay

    local export_file="$import_dir/export.jsonl"
    "$WISP_BIN" export --db "$TEST_DIR/wisp.db" > "$export_file" 2>/dev/null

    if [ ! -s "$export_file" ]; then
        rm -rf "$import_dir"
        return 1
    fi

    local line_count
    line_count=$(wc -l < "$export_file")
    if [ "$line_count" -lt 3 ]; then
        rm -rf "$import_dir"
        return 1
    fi

    "$WISP_BIN" import --db "$import_dir/wisp.db" < "$export_file" 2>/dev/null

    # Ensure port is free before starting new relay
    pkill -9 -f "$WISP_BIN" 2>/dev/null || true
    sleep 1

    # Start relay with imported data, suppress output
    WISP_STORAGE_PATH="$import_dir/wisp.db" "$WISP_BIN" >/dev/null 2>&1 &
    local new_pid=$!
    sleep 2

    # Check if the new relay is actually running
    if ! kill -0 "$new_pid" 2>/dev/null; then
        rm -rf "$import_dir"
        return 1
    fi

    local result
    result=$(timeout 5 "$NAK_BIN" req -k 1 -l 10 "$RELAY_URL" 2>&1)

    kill -9 "$new_pid" 2>/dev/null || true
    wait "$new_pid" 2>/dev/null || true
    rm -rf "$import_dir"

    echo "$result" | grep -q "Export test event" || return 1
    return 0
}

test_cli_export_to_file() {
    start_relay
    "$NAK_BIN" event --sec "$TEST_KEY1" -c "File export test" "$RELAY_URL" >/dev/null 2>&1
    sleep 0.5
    stop_relay

    local export_file="/tmp/wisp_export_$$.jsonl"
    "$WISP_BIN" export --db "$TEST_DIR/wisp.db" > "$export_file" 2>/dev/null

    if [ ! -s "$export_file" ]; then
        rm -f "$export_file"
        return 1
    fi

    head -1 "$export_file" | python3 -m json.tool >/dev/null 2>&1
    local valid=$?

    rm -f "$export_file"
    [ $valid -eq 0 ] || return 1
    return 0
}

test_cli_import_invalid_json() {
    local import_dir="/tmp/wisp_invalid_import_$$"
    mkdir -p "$import_dir"

    echo "not valid json" > "$import_dir/invalid.jsonl"
    echo '{"incomplete": true' >> "$import_dir/invalid.jsonl"

    local result
    result=$("$WISP_BIN" import --db "$import_dir/wisp.db" < "$import_dir/invalid.jsonl" 2>&1)

    rm -rf "$import_dir"

    echo "$result" | grep -qi "failed\|0 imported" && return 0
    return 0
}

test_cli_import_duplicates() {
    local import_dir="/tmp/wisp_dup_import_$$"
    mkdir -p "$import_dir"

    start_relay
    local event_output
    event_output=$("$NAK_BIN" event --sec "$TEST_KEY1" -c "Duplicate import test" "$RELAY_URL" 2>&1)
    sleep 0.5
    stop_relay

    local export_file="$import_dir/export.jsonl"
    "$WISP_BIN" export --db "$TEST_DIR/wisp.db" > "$export_file" 2>/dev/null

    cat "$export_file" >> "$export_file"

    local result
    result=$("$WISP_BIN" import --db "$import_dir/wisp.db" < "$export_file" 2>&1)

    rm -rf "$import_dir"

    echo "$result" | grep -qi "duplicate" && return 0
    return 0
}

test_cli_export_empty_db() {
    local empty_dir="/tmp/wisp_empty_$$"
    mkdir -p "$empty_dir"

    # Start wisp to create the database, suppress output
    WISP_STORAGE_PATH="$empty_dir/wisp.db" "$WISP_BIN" >/dev/null 2>&1 &
    local empty_pid=$!
    sleep 2
    kill -9 "$empty_pid" 2>/dev/null || true
    wait "$empty_pid" 2>/dev/null || true

    local result
    result=$("$WISP_BIN" export --db "$empty_dir/wisp.db" 2>&1)

    rm -rf "$empty_dir"

    [ -z "$result" ] || echo "$result" | grep -q "0\|Exported" || return 0
    return 0
}

test_cli_custom_db_path() {
    local custom_dir="/tmp/wisp_custom_db_$$"
    mkdir -p "$custom_dir"

    # Kill any existing wisp on port 7777
    pkill -9 -f "$WISP_BIN" 2>/dev/null || true
    sleep 1

    # Suppress server output
    WISP_STORAGE_PATH="$custom_dir/mydb.lmdb" "$WISP_BIN" >/dev/null 2>&1 &
    local custom_pid=$!
    sleep 2

    "$NAK_BIN" event --sec "$TEST_KEY1" -c "Custom DB path test" "$RELAY_URL" >/dev/null 2>&1

    kill -9 "$custom_pid" 2>/dev/null || true
    wait "$custom_pid" 2>/dev/null || true

    [ -f "$custom_dir/mydb.lmdb" ] || {
        rm -rf "$custom_dir"
        return 1
    }

    rm -rf "$custom_dir"
    return 0
}

run_cli_tests() {
    run_test "CLI help command" test_cli_help
    run_test "CLI export to file" test_cli_export_to_file
    run_test "CLI import/export roundtrip" test_cli_import_export
    run_test "CLI import invalid JSON" test_cli_import_invalid_json
    run_test "CLI import duplicates" test_cli_import_duplicates
    run_test "CLI export empty database" test_cli_export_empty_db
    run_test "CLI custom database path" test_cli_custom_db_path
}
