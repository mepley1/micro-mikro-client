//! Base64 encoding/decoding utils are contained in this file.

const std = @import("std");

// Some various stdlib options for b64 table:
const b64_table: []const u8 = &std.base64.standard_alphabet_chars;
// const b64_table = &std.fs.base64_alphabet;
// const b64_table = &std.base64.url_safe_alphabet_chars;
// const b64_table: []const u8 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const pad: u8 = '=';

/// Return a base64-encoded copy of `input`.
/// Caller must free returned slice.
pub fn b64EncodeAlloc(alloc: std.mem.Allocator, input: []const u8) error{OutOfMemory}![]u8 {
    const out_len = ((input.len + 2) / 3) * 4;
    var out = try alloc.alloc(u8, out_len);

    var i: usize = 0;
    var o: usize = 0;

    while (i < input.len) {
        const byte0 = input[i];
        const byte1 = if (i + 1 < input.len) input[i + 1] else 0;
        const byte2 = if (i + 2 < input.len) input[i + 2] else 0;

        const triple = (@as(u24, byte0) << 16) | (@as(u24, byte1) << 8) | byte2;

        out[o + 0] = b64_table[(triple >> 18) & 0x3F];
        out[o + 1] = b64_table[(triple >> 12) & 0x3F];
        out[o + 2] = if (i + 1 < input.len) b64_table[(triple >> 6) & 0x3F] else pad;
        out[o + 3] = if (i + 2 < input.len) b64_table[triple & 0x3F] else pad;

        i += 3;
        o += 4;
    }

    const populated_slice: []u8 = try alloc.realloc(out, out_len);
    return populated_slice;
}

/// Return a base64-encoded slice of `input`.
/// `buf` must be large enough to hold decoded output. (>= 4/3x input len)
/// Same algo as `b64EncodeAlloc` above, but no heap allocations.
pub fn b64Encode(buf: []u8, input: []const u8) error{OutOfMemory}![]const u8 {
    const out_len: usize = ((input.len + 2) / 3) * 4;
    if (out_len > buf.len) {
        @branchHint(.cold);
        return error.OutOfMemory;
    }

    var i: usize = 0;
    var o: usize = 0;

    while (i < input.len) {
        const byte0 = input[i];
        const byte1 = if (i + 1 < input.len) input[i + 1] else 0;
        const byte2 = if (i + 2 < input.len) input[i + 2] else 0;

        const triple = (@as(u24, byte0) << 16) | (@as(u24, byte1) << 8) | byte2;

        buf[o + 0] = b64_table[(triple >> 18) & 0x3F];
        buf[o + 1] = b64_table[(triple >> 12) & 0x3F];
        buf[o + 2] = if (i + 1 < input.len) b64_table[(triple >> 6) & 0x3F] else pad;
        buf[o + 3] = if (i + 2 < input.len) b64_table[triple & 0x3F] else pad;

        i += 3;
        o += 4;
    }

    return buf[0..out_len];
}

/// Return decoded copy of `input`. Caller must free returned slice.
pub fn b64DecodeAlloc(alloc: std.mem.Allocator, input: []const u8) error{ InvalidBase64InputLength, InvalidBase64Character, OutOfMemory }![]u8 {
    if (input.len % 4 != 0)
        return error.InvalidBase64InputLength;

    const out_len: usize = (input.len / 4) * 3;
    var out = try alloc.alloc(u8, out_len);
    defer alloc.free(out);

    var i: usize = 0;
    var o: usize = 0;

    while (i < input.len) : (i += 4) {
        const ch0 = input[i];
        const ch1 = input[i + 1];
        const ch2 = input[i + 2];
        const ch3 = input[i + 3];

        const byte0 = std.mem.indexOfScalar(u8, b64_table, ch0) orelse return error.InvalidBase64Character;
        const byte1 = std.mem.indexOfScalar(u8, b64_table, ch1) orelse return error.InvalidBase64Character;
        const byte2 = if (ch2 != pad) std.mem.indexOfScalar(u8, b64_table, ch2) orelse return error.InvalidBase64Character else 0;
        const byte3 = if (ch3 != pad) std.mem.indexOfScalar(u8, b64_table, ch3) orelse return error.InvalidBase64Character else 0;

        out[o] = @intCast((byte0 << 2) | ((byte1 & 0x30) >> 4));
        o += 1;

        if (ch2 != pad) {
            out[o] = @intCast(((byte1 & 0x0F) << 4) | ((byte2 & 0x3C) >> 2));
            o += 1;

            if (ch3 != pad) {
                out[o] = @intCast(((byte2 & 0x03) << 6) | byte3);
                o += 1;
            }
        }
    }

    return alloc.dupe(u8, out[0..o]);
}

test "b64EncodeAlloc" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const alloc = arena.allocator();
    defer _ = arena.deinit();

    try std.testing.expectEqualSlices(
        u8,
        "YWJjZA==",
        try b64EncodeAlloc(alloc, "abcd"),
    );
    try std.testing.expectEqualSlices(
        u8,
        "emln",
        try b64EncodeAlloc(alloc, "zig"),
    );
    try std.testing.expectEqualStrings(
        "TG9yZW0gSXBzdW0u",
        try b64EncodeAlloc(alloc, "Lorem Ipsum."),
    );
    try std.testing.expectEqualDeep(
        "RDNCVUd8TTBEMw==",
        try b64EncodeAlloc(alloc, "D3BUG|M0D3"),
    );
    try std.testing.expectEqualSlices(
        u8,
        "IQ==",
        try b64EncodeAlloc(alloc, "!"),
    );
    try std.testing.expectEqualSlices(
        u8,
        "Kyo=",
        try b64EncodeAlloc(alloc, "+*"),
    );
}

test "b64Encode" {
    var buf: [32]u8 = undefined;

    try std.testing.expectEqualStrings("emln", try b64Encode(
        &buf,
        "zig",
    ));
    try std.testing.expectEqualStrings("RDNCVUd8TTBEMw==", try b64Encode(
        &buf,
        "D3BUG|M0D3",
    ));
    try std.testing.expectEqualStrings("JCQ=", try b64Encode(
        &buf,
        "$$",
    ));

    var too_small: [2]u8 = undefined;
    try std.testing.expectError(error.OutOfMemory, b64Encode(&too_small, "abcd"));
}

test "b64DecodeAlloc" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const alloc = arena.allocator();
    defer _ = arena.deinit();

    try std.testing.expectEqualSlices(
        u8,
        "zig",
        try b64DecodeAlloc(alloc, "emln"),
    );
    try std.testing.expectEqualSlices(
        u8,
        "Lorem Ipsum.",
        try b64DecodeAlloc(alloc, "TG9yZW0gSXBzdW0u"),
    );
    try std.testing.expectEqualSlices(
        u8,
        "debug-mode",
        try b64DecodeAlloc(alloc, "ZGVidWctbW9kZQ=="),
    );
    try std.testing.expectEqualSlices(
        u8,
        "!",
        try b64DecodeAlloc(alloc, "IQ=="),
    );
    try std.testing.expectEqualSlices(
        u8,
        "+*",
        try b64DecodeAlloc(alloc, "Kyo="),
    );
    try std.testing.expectEqualSlices(
        u8,
        "$$",
        try b64DecodeAlloc(alloc, "JCQ="),
    );
    try std.testing.expectEqualSlices(
        u8,
        "D3BUG|M0D3",
        try b64DecodeAlloc(alloc, "RDNCVUd8TTBEMw=="),
    );
}
