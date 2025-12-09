const std = @import("std");
const Config = @import("config.zig").Config;

pub fn serialize(config: *const Config, buf: []u8) ![]u8 {
    var stream = std.io.fixedBufferStream(buf);
    const w = stream.writer();

    try w.writeAll("{");

    try w.print("\"name\":\"{s}\"", .{config.name});
    try w.print(",\"description\":\"{s}\"", .{config.description});

    if (config.pubkey) |pk| {
        try w.print(",\"pubkey\":\"{s}\"", .{pk});
    }

    if (config.contact) |contact| {
        try w.print(",\"contact\":\"{s}\"", .{contact});
    }

    try w.writeAll(",\"supported_nips\":[1,9,11,40]");
    try w.writeAll(",\"software\":\"wisp\"");
    try w.writeAll(",\"version\":\"0.1.0\"");

    try w.writeAll(",\"limitation\":{");
    try w.print("\"max_message_length\":{d}", .{config.max_message_size});
    try w.print(",\"max_subscriptions\":{d}", .{config.max_subscriptions});
    try w.print(",\"max_filters\":{d}", .{config.max_filters});
    try w.print(",\"max_event_tags\":{d}", .{config.max_event_tags});
    try w.print(",\"max_content_length\":{d}", .{config.max_content_length});
    try w.print(",\"max_limit\":{d}", .{config.query_limit_max});
    try w.writeAll(",\"auth_required\":false");
    try w.writeAll(",\"payment_required\":false");
    try w.writeAll("}");

    try w.writeAll("}");

    return buf[0..stream.pos];
}
