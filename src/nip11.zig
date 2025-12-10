const std = @import("std");
const Config = @import("config.zig").Config;

pub fn write(config: *const Config, w: anytype) !void {
    try w.writeAll("{");

    try w.print("\"name\":\"{s}\"", .{config.name});
    try w.print(",\"description\":\"{s}\"", .{config.description});

    if (config.pubkey) |pk| {
        try w.print(",\"pubkey\":\"{s}\"", .{pk});
    }

    if (config.contact) |contact| {
        try w.print(",\"contact\":\"{s}\"", .{contact});
    }

    try w.writeAll(",\"supported_nips\":[1,9,11,40,45]");
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
