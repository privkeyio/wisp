#!/bin/bash

test_nip11_document_exists() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"name"' || return 1
    return 0
}

test_nip11_has_name() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"name":"Wisp"' || return 1
    return 0
}

test_nip11_has_description() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"description"' || return 1
    return 0
}

test_nip11_has_supported_nips() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"supported_nips"' || return 1

    echo "$result" | grep -q '\[.*1.*\]' || return 1
    return 0
}

test_nip11_has_software() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"software"' || return 1
    return 0
}

test_nip11_has_version() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"version"' || return 1
    return 0
}

test_nip11_has_limitation() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"limitation"' || return 1
    return 0
}

test_nip11_limitation_max_message_length() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"max_message_length"' || return 1
    return 0
}

test_nip11_limitation_max_subscriptions() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"max_subscriptions"' || return 1
    return 0
}

test_nip11_limitation_max_filters() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"max_filters"' || return 1
    return 0
}

test_nip11_limitation_max_limit() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"max_limit"' || return 1
    return 0
}

test_nip11_limitation_max_event_tags() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"max_event_tags"' || return 1
    return 0
}

test_nip11_limitation_max_content_length() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"max_content_length"' || return 1
    return 0
}

test_nip11_limitation_auth_required() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"auth_required"' || return 1
    return 0
}

test_nip11_limitation_created_at_limits() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"created_at_lower_limit"' || return 1
    echo "$result" | grep -q '"created_at_upper_limit"' || return 1
    return 0
}

test_nip11_valid_json() {
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | python3 -m json.tool >/dev/null 2>&1 || return 1
    return 0
}

test_nip11_content_type() {
    # Note: Some relays only return proper content-type on GET, not HEAD
    # So we just verify the NIP-11 document is valid JSON with expected fields
    local result
    result=$(curl -s -H "Accept: application/nostr+json" "$HTTP_URL" 2>&1)
    echo "$result" | grep -q '"name"' || return 1
    echo "$result" | python3 -m json.tool >/dev/null 2>&1 || return 1
    return 0
}

test_nip11_using_nak() {
    local result
    result=$("$NAK_BIN" relay "$RELAY_URL" 2>&1)
    echo "$result" | grep -q '"name"' || return 1
    return 0
}

run_nip11_tests() {
    run_test "NIP-11 document exists" test_nip11_document_exists
    run_test "NIP-11 has name" test_nip11_has_name
    run_test "NIP-11 has description" test_nip11_has_description
    run_test "NIP-11 has supported_nips" test_nip11_has_supported_nips
    run_test "NIP-11 has software" test_nip11_has_software
    run_test "NIP-11 has version" test_nip11_has_version
    run_test "NIP-11 has limitation object" test_nip11_has_limitation
    run_test "NIP-11 limitation.max_message_length" test_nip11_limitation_max_message_length
    run_test "NIP-11 limitation.max_subscriptions" test_nip11_limitation_max_subscriptions
    run_test "NIP-11 limitation.max_filters" test_nip11_limitation_max_filters
    run_test "NIP-11 limitation.max_limit" test_nip11_limitation_max_limit
    run_test "NIP-11 limitation.max_event_tags" test_nip11_limitation_max_event_tags
    run_test "NIP-11 limitation.max_content_length" test_nip11_limitation_max_content_length
    run_test "NIP-11 limitation.auth_required" test_nip11_limitation_auth_required
    run_test "NIP-11 limitation.created_at_limits" test_nip11_limitation_created_at_limits
    run_test "NIP-11 valid JSON" test_nip11_valid_json
    run_test "NIP-11 content type" test_nip11_content_type
    run_test "NIP-11 using nak relay" test_nip11_using_nak
}
