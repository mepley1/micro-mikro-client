//! Base64 encoding/decoding utils are contained in this file.

const std = @import("std");

// Some various stdlib options for b64 table:
const base64_table: []const u8 = &std.base64.standard_alphabet_chars;
// const base64_table: []const u8 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// const base64_table = std.fs.base64_alphabet;
// const base64_table = std.base64.url_safe_alphabet_chars;

/// Return a base64-encoded copy of `input`.
/// Caller must free returned slice.
pub fn b64EncodeAlloc(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const output_len = ((input.len + 2) / 3) * 4;
    var out = try allocator.alloc(u8, output_len);
    var i: usize = 0;
    var o: usize = 0;

    while (i < input.len) {
        @branchHint(.likely);
        const byte0 = input[i];
        const byte1 = if (i + 1 < input.len) input[i + 1] else 0;
        const byte2 = if (i + 2 < input.len) input[i + 2] else 0;

        const triple = (@as(u24, byte0) << 16) | (@as(u24, byte1) << 8) | byte2;

        out[o + 0] = base64_table[(triple >> 18) & 0x3F];
        out[o + 1] = base64_table[(triple >> 12) & 0x3F];
        out[o + 2] = if (i + 1 < input.len) base64_table[(triple >> 6) & 0x3F] else '=';
        out[o + 3] = if (i + 2 < input.len) base64_table[triple & 0x3F] else '=';

        i += 3;
        o += 4;
    }

    const populated_slice: []u8 = try allocator.realloc(out, output_len);
    return populated_slice;
}

/// Return a base64-encoded slice of `input`.
/// Max size of encoded output is determined by size of `buf`.
/// Same algo as `b64EncodeAlloc` above, but no heap allocations - takes a &buffer instead of an allocator.
pub inline fn b64Encode(input: []const u8, buf: []u8) ![]const u8 {
    const output_len = ((input.len + 2) / 3) * 4;
    if (output_len > buf.len) {
        @branchHint(.cold);
        return error.OutOfMemory;
    }

    var i: usize = 0;
    var o: usize = 0;

    while (i < input.len) {
        @branchHint(.likely);
        const byte0 = input[i];
        const byte1 = if (i + 1 < input.len) input[i + 1] else 0;
        const byte2 = if (i + 2 < input.len) input[i + 2] else 0;

        const triple = (@as(u24, byte0) << 16) | (@as(u24, byte1) << 8) | byte2;

        buf[o + 0] = base64_table[(triple >> 18) & 0x3F];
        buf[o + 1] = base64_table[(triple >> 12) & 0x3F];
        buf[o + 2] = if (i + 1 < input.len) base64_table[(triple >> 6) & 0x3F] else '=';
        buf[o + 3] = if (i + 2 < input.len) base64_table[triple & 0x3F] else '=';

        i += 3;
        o += 4;
    }

    return buf[0..output_len];
}

/// Return decoded copy of `input`. Caller must free returned slice.
fn b64DecodeAlloc(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len % 4 != 0)
        return error.InvalidBase64InputLength;

    var decoded = try alloc.alloc(u8, (input.len / 4) * 3);
    defer alloc.free(decoded);

    var out_index: usize = 0;
    var i: usize = 0;
    while (i < input.len) : (i += 4) {
        const ch0 = input[i];
        const ch1 = input[i + 1];
        const ch2 = input[i + 2];
        const ch3 = input[i + 3];

        const byte0 = std.mem.indexOfScalar(u8, base64_table, ch0) orelse return error.InvalidBase64Character;
        const byte1 = std.mem.indexOfScalar(u8, base64_table, ch1) orelse return error.InvalidBase64Character;
        const byte2 = if (ch2 != '=') std.mem.indexOfScalar(u8, base64_table, ch2) orelse return error.InvalidBase64Character else 0;
        const byte3 = if (ch3 != '=') std.mem.indexOfScalar(u8, base64_table, ch3) orelse return error.InvalidBase64Character else 0;

        decoded[out_index] = @intCast((byte0 << 2) | ((byte1 & 0x30) >> 4));
        out_index += 1;

        if (ch2 != '=') {
            decoded[out_index] = @intCast(((byte1 & 0x0F) << 4) | ((byte2 & 0x3C) >> 2));
            out_index += 1;

            if (ch3 != '=') {
                decoded[out_index] = @intCast(((byte2 & 0x03) << 6) | byte3);
                out_index += 1;
            }
        }
    }

    return alloc.dupe(u8, decoded[0..out_index]);
}

test "b64Encode" {
    const str: []const u8 = "zig";

    var buf: [16]u8 = undefined;
    const enc: []const u8 = try b64Encode(str, &buf);
    try std.testing.expectEqualStrings("emln", enc);
}

test "b64EncodeAlloc" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const alloc = arena.allocator();
    defer _ = arena.deinit();

    try std.testing.expectEqualSlices(u8, "YWJjZA==", try b64EncodeAlloc(alloc, "abcd"));
    try std.testing.expectEqualStrings("emln", try b64EncodeAlloc(alloc, "zig"));
    try std.testing.expectEqualStrings("TG9yZW0gSXBzdW0u", try b64EncodeAlloc(alloc, "Lorem Ipsum."));
    try std.testing.expectEqualDeep("RDNCVUd8TTBEMw==", try b64EncodeAlloc(alloc, "D3BUG|M0D3"));
}

test "b64DecodeAlloc" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const alloc = arena.allocator();
    defer _ = arena.deinit();

    try std.testing.expectEqualSlices(u8, "zig", try b64DecodeAlloc(alloc, "emln"));
    try std.testing.expectEqualSlices(u8, "Lorem Ipsum.", try b64DecodeAlloc(alloc, "TG9yZW0gSXBzdW0u"));
    try std.testing.expectEqualSlices(u8, "debug-mode", try b64DecodeAlloc(alloc, "ZGVidWctbW9kZQ=="));
    try std.testing.expectEqualSlices(u8, "!", try b64DecodeAlloc(alloc, "IQ=="));
    try std.testing.expectEqualSlices(u8, "+*", try b64DecodeAlloc(alloc, "Kyo="));
    try std.testing.expectEqualSlices(u8, "$$", try b64DecodeAlloc(alloc, "JCQ="));
    try std.testing.expectEqualSlices(u8, "D3BUG|M0D3", try b64DecodeAlloc(alloc, "RDNCVUd8TTBEMw=="));
}
