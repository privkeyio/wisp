const std = @import("std");
const Config = @import("config.zig").Config;

fn writeJsonString(w: anytype, value: []const u8) !void {
    try w.writeByte('"');
    for (value) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

pub fn write(config: *const Config, w: anytype) !void {
    try w.writeAll("{");

    try w.writeAll("\"name\":");
    try writeJsonString(w, config.name);
    try w.writeAll(",\"description\":");
    try writeJsonString(w, config.description);

    if (config.pubkey) |pk| {
        try w.writeAll(",\"pubkey\":");
        try writeJsonString(w, pk);
    }

    if (config.contact) |contact| {
        try w.writeAll(",\"contact\":");
        try writeJsonString(w, contact);
    }

    try w.writeAll(",\"supported_nips\":[1,9,11,16,33,40,42,45,50,65,70,77]");
    try w.writeAll(",\"software\":\"https://github.com/privkeyio/wisp\"");
    try w.writeAll(",\"version\":\"0.1.0\"");

    try w.writeAll(",\"limitation\":{");
    try w.print("\"max_message_length\":{d}", .{config.max_message_size});
    try w.print(",\"max_subscriptions\":{d}", .{config.max_subscriptions});
    try w.print(",\"max_filters\":{d}", .{config.max_filters});
    try w.writeAll(",\"max_subid_length\":64");
    try w.print(",\"max_event_tags\":{d}", .{config.max_event_tags});
    try w.print(",\"max_content_length\":{d}", .{config.max_content_length});
    try w.print(",\"max_limit\":{d}", .{config.query_limit_max});
    try w.print(",\"default_limit\":{d}", .{config.query_limit_default});
    try w.writeAll(",\"min_pow_difficulty\":0");
    try w.print(",\"auth_required\":{}", .{config.auth_required});
    try w.writeAll(",\"payment_required\":false");
    try w.print(",\"created_at_lower_limit\":{d}", .{config.max_event_age});
    try w.print(",\"created_at_upper_limit\":{d}", .{config.max_future_seconds});
    try w.writeAll("}");

    try w.writeAll("}");
}
