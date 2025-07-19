//! Validation-related functions/utils are contained in this file.

const std = @import("std");

const base64_table: []const u8 = &std.base64.standard_alphabet_chars;

/// Check if input slice is "probably" b64-encoded data (or rather, it's not an un-encoded HTTP basic auth str). For the use case, it's not worth running through a whole decode algo to validate, this is more than enough.
pub fn validateB64(s: []const u8) bool {
    const valid_chars: []const u8 = base64_table ++ "=";
    if (s.len % 4 != 0) {
        return false;
    }
    for (s) |c| {
        // Could also use `std.ascii.isHex()` plus '+', '/', and '='
        if (!std.mem.containsAtLeastScalar(u8, valid_chars, 1, c)) {
            return false;
        }
    }
    return true;
}

/// Validate given IP address (either v4/v6)
pub fn validateIpAddr(addr: []const u8) bool {
    _ = std.net.Address.parseIp(addr, 0) catch {
        return false;
    };
    return true;
}

// Validate an IPv6 address.
pub fn validateIpAddrV6(addr: []const u8) bool {
    _ = std.net.Ip6Address.parse(addr, 0) catch
        return false;
    return true;
}

// Validate an IPv4 address.
pub fn validateIpAddrV4(addr: []const u8) bool {
    _ = std.net.Ip4Address.parse(addr, 0) catch
        return false;
    return true;
}

/// Validate a dns name.
/// Catch preceding hyphen in case of missing value, so arg's value doesn't become the name of the next arg.
/// Make it contain at least one '.' to prevent some issues.
pub fn validateDnsName(addr: []const u8) bool {
    if (std.mem.startsWith(u8, addr, "-") or !std.mem.containsAtLeastScalar(u8, addr, 1, '.')) {
        return false;
    }
    return std.net.isValidHostName(addr);
}

/// Validate given slice contains only Ascii printable chars (no control codes)
///
/// Similar to std.ascii.isPrint(), but flattened.
///
/// For each char: 0x1f (31) <= `char` <= 0x7f (127)
pub fn isAsciiPrintable(buf: []const u8) bool {
    for (buf) |char| {
        if (char < 0x1f or char > 0x7f) {
            @branchHint(.unlikely);
            return false;
        }
    }
    return true;
}

/// unused right now. Similar to `isAsciiPrintable` above, but allows value up to max 0xff (no control codes <0x1f).
/// TODO: Maybe use to validate password? Check mikrotik wiki for allowed pass chars.
pub fn validateUnicode(buf: []u8) bool {
    for (buf) |c| {
        if (c > 0xff or c < 0x1f) {
            @branchHint(.unlikely);
            return false;
        }
    }
    return true;
}

/// Validate given `--timeout` value. (format should be either 00:00:00 or i.e. "1d"/"4h 20m" etc)
///
/// Imperfect; will allow some jumbled values if all chars are in allowed range.
pub fn validateTimeout(buf: []const u8) bool {
    if (buf.len > 32) {
        @branchHint(.unlikely);
        return false;
    }
    for (buf) |c| {
        switch (c) {
            '0'...'9', ':', 's', 'm', 'h', 'd', 'w', ' ' => continue,
            else => {
                @branchHint(.unlikely);
                return false;
            },
        }
    }
    return true;
}

test "validate ip addrs - explicit v4/v6" {
    const addr6: []const u8 = "2001:db8::bad:c0de";
    const bad_addr: []const u8 = "xyz:1234";
    const loopback6: []const u8 = "::1";
    const localhost4: []const u8 = "127.0.0.1";

    // v6 good
    try std.testing.expect(validateIpAddrV6(addr6));
    try std.testing.expect(validateIpAddrV6(loopback6));
    // bad
    try std.testing.expect(!validateIpAddrV6(bad_addr));
    try std.testing.expect(!validateIpAddrV6(localhost4));

    // v4 good
    try std.testing.expect(validateIpAddrV4(localhost4));
    // bad
    try std.testing.expect(!validateIpAddrV4(addr6));
    try std.testing.expect(!validateIpAddrV4(loopback6));
    try std.testing.expect(!validateIpAddrV4(bad_addr));
    try std.testing.expect(!validateIpAddrV4("10.0.0.x"));
}

test "validate hostname" {
    // Good
    try std.testing.expect(validateDnsName("test.example.tld"));
    // Bad
    try std.testing.expect(!validateDnsName("bad+name"));
    try std.testing.expect(!validateDnsName("host@name"));
    try std.testing.expect(!validateDnsName("hostname1"));
    // Catch starts with dash (fail)
    try std.testing.expect(!validateDnsName("-dash"));
}

test "validateB64" {
    const str: []const u8 = "dXNlcjpwdw==";
    const bad_chars: []const u8 = "bad $*!";
    const not_mult_of_four: []const u8 = "xyz";

    try std.testing.expect(validateB64(str));

    try std.testing.expect(!validateB64(not_mult_of_four));
    try std.testing.expect(!validateB64(bad_chars));
}
