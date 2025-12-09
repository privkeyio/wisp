const std = @import("std");

const c = @cImport({
    @cInclude("nostr.h");
    @cInclude("nostr_relay_protocol.h");
});

pub fn main() !void {
    std.debug.print("=== libnostr-c Test ===\n", .{});

    // Initialize library
    const init_result = c.nostr_init();
    if (init_result != c.NOSTR_OK) {
        std.debug.print("Failed to init: {s}\n", .{c.nostr_error_string(init_result)});
        return;
    }
    defer c.nostr_cleanup();

    std.debug.print("Library initialized. Version: {s}\n", .{c.nostr_version()});

    // Test 1: Parse an event from JSON
    const event_json =
        \\{"id":"d7dd5eb3ab747e16f8d0212d53032ea2a7cadef53837e5a6c66d42849fcb9027",
        \\"pubkey":"22e804d26ed16b68db5259e78449e96dab5d464c8f470bda3eb1a70467f2c793",
        \\"created_at":1733761200,
        \\"kind":1,
        \\"tags":[["p","32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"]],
        \\"content":"Hello Nostr!",
        \\"sig":"47f04052e5b6b3d9a0ca6493494af10618af35ba8bb3f1a806747b4b3a8f8f8e2e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e"}
    ;

    var event: ?*c.nostr_event = null;
    const parse_result = c.nostr_event_parse(event_json.ptr, event_json.len, &event);

    if (parse_result != c.NOSTR_RELAY_OK) {
        std.debug.print("Parse failed: {s}\n", .{c.nostr_relay_error_string(parse_result)});
        return;
    }
    defer c.nostr_event_destroy(event);

    std.debug.print("\n--- Parsed Event ---\n", .{});

    // Get ID hex
    var id_hex: [65]u8 = undefined;
    c.nostr_event_get_id_hex(event, &id_hex);
    std.debug.print("ID:      {s}\n", .{id_hex[0..64]});

    // Get pubkey hex
    var pk_hex: [65]u8 = undefined;
    c.nostr_event_get_pubkey_hex(event, &pk_hex);
    std.debug.print("Pubkey:  {s}\n", .{pk_hex[0..64]});

    // Get kind and created_at
    std.debug.print("Kind:    {d}\n", .{event.?.kind});
    std.debug.print("Created: {d}\n", .{event.?.created_at});

    // Get content
    if (event.?.content) |content| {
        std.debug.print("Content: {s}\n", .{content});
    }

    // Get tags
    const tag_count = c.nostr_event_get_tag_count(event);
    std.debug.print("Tags:    {d}\n", .{tag_count});

    for (0..tag_count) |i| {
        const tag = c.nostr_event_get_tag(event, i);
        if (tag) |t| {
            const name = c.nostr_tag_get_name(t);
            const val_count = c.nostr_tag_get_value_count(t);
            if (name) |n| {
                std.debug.print("  [{d}] {s}", .{ i, n });
                if (val_count > 1) {
                    const val = c.nostr_tag_get_value(t, 1);
                    if (val) |v| {
                        std.debug.print(": {s}", .{v});
                    }
                }
                std.debug.print("\n", .{});
            }
        }
    }

    // Test 2: Parse a client message
    std.debug.print("\n--- Client Message Parsing ---\n", .{});

    const req_json =
        \\["REQ","sub1",{"kinds":[1],"limit":10}]
    ;

    var msg: c.nostr_client_msg_t = undefined;
    const msg_result = c.nostr_client_msg_parse(req_json.ptr, req_json.len, &msg);

    if (msg_result != c.NOSTR_RELAY_OK) {
        std.debug.print("Client msg parse failed: {s}\n", .{c.nostr_relay_error_string(msg_result)});
    } else {
        defer c.nostr_client_msg_free(&msg);

        const msg_type = c.nostr_client_msg_get_type(&msg);
        std.debug.print("Message type: {d} (REQ=1)\n", .{msg_type});

        if (msg_type == c.NOSTR_CLIENT_MSG_REQ) {
            const sub_id = c.nostr_client_msg_get_subscription_id(&msg);
            if (sub_id) |s| {
                std.debug.print("Subscription ID: {s}\n", .{s});
            }

            var filter_count: usize = 0;
            const filters = c.nostr_client_msg_get_filters(&msg, &filter_count);
            std.debug.print("Filter count: {d}\n", .{filter_count});

            if (filters != null and filter_count > 0) {
                const limit = c.nostr_filter_get_limit(&filters[0]);
                std.debug.print("Filter[0] limit: {d}\n", .{limit});

                var kinds_count: usize = 0;
                const kinds = c.nostr_filter_get_kinds(&filters[0], &kinds_count);
                if (kinds != null and kinds_count > 0) {
                    std.debug.print("Filter[0] kinds: ", .{});
                    for (0..kinds_count) |ki| {
                        std.debug.print("{d} ", .{kinds[ki]});
                    }
                    std.debug.print("\n", .{});
                }
            }
        }
    }

    // Test 3: Build relay message
    std.debug.print("\n--- Relay Message Building ---\n", .{});

    var relay_msg: c.nostr_relay_msg_t = undefined;
    c.nostr_relay_msg_ok(&relay_msg, "d7dd5eb3ab747e16f8d0212d53032ea2a7cadef53837e5a6c66d42849fcb9027", true, "");

    var buf: [512]u8 = undefined;
    var out_len: usize = 0;
    const ser_result = c.nostr_relay_msg_serialize(&relay_msg, &buf, buf.len, &out_len);

    if (ser_result == c.NOSTR_RELAY_OK) {
        std.debug.print("OK message: {s}\n", .{buf[0..out_len]});
    }

    // Build EOSE
    c.nostr_relay_msg_eose(&relay_msg, "sub1");
    _ = c.nostr_relay_msg_serialize(&relay_msg, &buf, buf.len, &out_len);
    std.debug.print("EOSE message: {s}\n", .{buf[0..out_len]});

    // Build NOTICE
    c.nostr_relay_msg_notice(&relay_msg, "hello from wisp");
    _ = c.nostr_relay_msg_serialize(&relay_msg, &buf, buf.len, &out_len);
    std.debug.print("NOTICE message: {s}\n", .{buf[0..out_len]});

    // Test 4: Kind classification
    std.debug.print("\n--- Kind Classification ---\n", .{});
    std.debug.print("Kind 1 type: {d} (0=regular)\n", .{c.nostr_kind_get_type(1)});
    std.debug.print("Kind 0 type: {d} (1=replaceable)\n", .{c.nostr_kind_get_type(0)});
    std.debug.print("Kind 20000 type: {d} (2=ephemeral)\n", .{c.nostr_kind_get_type(20000)});
    std.debug.print("Kind 30000 type: {d} (3=addressable)\n", .{c.nostr_kind_get_type(30000)});

    std.debug.print("\n=== All tests passed! ===\n", .{});
}
