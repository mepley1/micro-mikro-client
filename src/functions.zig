//! Helper functions that don't belong in any other file.

const std = @import("std");
const builtin = @import("builtin");

pub fn assert(ok: bool) void {
    if (!ok) unreachable;
}

/// Check if kdialog is available on system. Called by `getPassDispatch()`, not intended to be called directly.
fn checkForKdialog(alloc: std.mem.Allocator) bool {
    var cmd = std.process.Child.init(&[_][]const u8{ "which", "kdialog" }, alloc);
    cmd.stdout_behavior, cmd.stderr_behavior = .{ .Ignore, .Ignore };

    const x = cmd.spawnAndWait() catch @panic("Error spawning child process.");
    switch (x.Exited) {
        0 => return true,
        else => return false,
    }
}

const pass_prompt: []const u8 = "Enter RouterOS password: ";

/// Dispatch to either `getPassGraphical()` or `getPassCli()`, based on result of `checkForKdialog()`.
pub fn getPassDispatch(alloc: std.mem.Allocator) ![]const u8 {
    switch (checkForKdialog(alloc)) {
        true => return try getPassGraphical(alloc),
        false => return try getPassCli(alloc),
    }
}

/// Retreive password via a kdialog password box.
/// Caller owns returned slice.
///
/// Requires kdialog package installed (less than 1 MB) (`pacman -S kdialog`).
///
/// Called by `getPassDispatch()` after verifying kdialog availability; don't call directly.
///
/// Ref: https://stackoverflow.com/questions/78825834/how-to-run-shell-commands-which-require-input-in-zig
fn getPassGraphical(alloc: std.mem.Allocator) (std.process.Child.SpawnError || std.process.Child.WaitError || error{ OutOfMemory, ChildProcessError })![]const u8 {
    switch (builtin.os.tag) {
        .linux => {
            @branchHint(.likely);
        },
        else => {
            @branchHint(.unlikely);
            return error.UnsupportedOS;
        },
    }

    var cmd = std.process.Child.init(&[_][]const u8{ "kdialog", "--password", pass_prompt, "--title", "Password" }, alloc);
    cmd.stderr_behavior = .Pipe;
    cmd.stdout_behavior = .Pipe;
    try cmd.spawn();

    var buf_out = try std.ArrayListUnmanaged(u8).initCapacity(alloc, 1024);
    var buf_err = try std.ArrayListUnmanaged(u8).initCapacity(alloc, 1024);

    cmd.collectOutput(alloc, &buf_out, &buf_err, 1024) catch return error.ChildProcessError;

    const term = try cmd.wait();

    if (term.Exited == 0) {
        @branchHint(.likely);
        _ = buf_out.pop(); //remove trailing byte left over
        return buf_out.toOwnedSlice(alloc);
    } else {
        @branchHint(.unlikely);
        return error.ChildProcessError;
    }
}

/// Get password via stdin. Caller must free returned slice.
/// Not called directly; Called by `getPassDispatch()`
///
/// TODO: Hide input via control codes while typing.
fn getPassCli(alloc: std.mem.Allocator) (std.mem.Allocator.Error || error{ StreamTooLong, ReadError, WriteError })![]const u8 {
    const stdin = std.io.getStdIn().reader();
    const stderr = std.io.getStdErr().writer();

    stderr.print(pass_prompt, .{}) catch return error.WriteError;
    const pw = stdin.readUntilDelimiterOrEofAlloc(alloc, '\n', 512) catch |err| {
        std.log.err("Failure reading stdin: {s}", .{@errorName(err)});
        return error.ReadError;
    };

    if (pw) |val| return val else {
        std.log.warn("Value null!", .{});
        return "";
    }
}

/// Return full absolute path to config file.
///
/// Read $XDG_CONFIG_HOME envvar, if not found then fall back to $HOME (append "/.config" to HOME).
/// If neither found, use `/home/$(whoami)/.config/`
pub fn getConfigPath(alloc: std.mem.Allocator) ![]const u8 {
    var temp_arena = std.heap.ArenaAllocator.init(alloc);
    defer temp_arena.deinit();
    var temp_alloc = temp_arena.allocator();

    var conf_dir: []u8 = undefined;
    const conf_file_rel: []const u8 = "/micro-mikro-client/.env.json";

    if (std.process.hasNonEmptyEnvVarConstant("XDG_CONFIG_HOME")) {
        conf_dir = std.process.getEnvVarOwned(temp_alloc, "XDG_CONFIG_HOME") catch {
            @panic("Error reading envvar.");
        };
        std.log.debug("Found $XDG_CONFIG_HOME", .{});
    } else if (std.process.hasNonEmptyEnvVarConstant("HOME")) {
        conf_dir = std.process.getEnvVarOwned(temp_alloc, "HOME") catch {
            @panic("Error reading envvar.");
        };
        conf_dir = concatRuntime(temp_alloc, u8, conf_dir, "/.config");
        std.log.debug("Found $HOME", .{});
    } else {
        // Get username and format conf_dir to include it
        const usern = try getUsernameDispatch(temp_alloc);
        defer temp_alloc.free(usern);
        conf_dir = try std.fmt.allocPrint(temp_alloc, "/home/{s}/.config", .{usern});
        // conf_dir = @constCast(concatRuntimeMulti(temp_alloc, u8, &[3][]const u8{ "/home/", usern, "/.config" }));
    }
    defer temp_alloc.free(conf_dir);

    // Now concatenate `conf_dir` ++ `conf_file_rel`, to assemble absolute path to config file.
    const conf_path_abs: []const u8 = concatRuntime(temp_alloc, u8, conf_dir, conf_file_rel);
    defer temp_alloc.free(conf_path_abs);

    assert(conf_path_abs.len <= std.fs.max_path_bytes);

    return try alloc.dupe(u8, conf_path_abs);
}

/// Get username, first by trying `$USER`, falling back to `$(whoami)`, and finally error if neither found.
fn getUsernameDispatch(alloc: std.mem.Allocator) error{UsernameDiscoveryFailure}![]const u8 {
    const usern: ?[]const u8 = getUsernameEnv(alloc) orelse getUsernameWhoami(alloc) catch null;
    errdefer if (usern) |val| alloc.free(val);

    if (usern != null and usern.?.len > 0) {
        return usern.?;
    } else {
        return error.UsernameDiscoveryFailure;
    }
}

/// Get current username by calling `whoami` in a child process. Linux only.
///
/// Caller owns returned slice.
fn getUsernameWhoami(alloc: std.mem.Allocator) !?[]const u8 {
    switch (builtin.os.tag) {
        .linux => {
            @branchHint(.likely);
        },
        else => {
            @branchHint(.unlikely);
            return error.UnsupportedOS;
        },
    }

    var cmd = std.process.Child.init(&[_][]const u8{"whoami"}, alloc);
    cmd.stderr_behavior = .Pipe;
    cmd.stdout_behavior = .Pipe;

    try cmd.spawn();
    var buf_out = std.ArrayListUnmanaged(u8).initCapacity(alloc, 1024) catch @panic("Out of memory");
    var buf_err = std.ArrayListUnmanaged(u8).initCapacity(alloc, 1024) catch @panic("Out of memory");
    errdefer buf_out.deinit(alloc);
    defer buf_err.deinit(alloc);

    try cmd.collectOutput(alloc, &buf_out, &buf_err, 1024);

    const x: std.process.Child.Term = try cmd.wait();

    if (x.Exited == 0) {
        _ = buf_out.pop(); // Remove trailing newline
        return buf_out.toOwnedSlice(alloc) catch @panic("OOM");
    } else {
        return error.ChildProcessError;
    }
}

/// Get username by reading value of $USER envvar.
fn getUsernameEnv(alloc: std.mem.Allocator) ?[]const u8 {
    const env = std.posix.getenv("USER");

    if (env) |u| {
        return alloc.dupe(u8, std.mem.span(u.ptr)) catch @panic("OOM");
    } else {
        return null;
    }
}

/// Concatenate two runtime-known slices. Caller must free returned slice.
pub fn concatRuntime(alloc: std.mem.Allocator, comptime T: type, arr1: []const T, arr2: []const T) []T {
    var combined = alloc.alloc(T, arr1.len + arr2.len) catch @panic("Out of memory!");
    errdefer alloc.free(combined);
    @memcpy(combined[0..arr1.len], arr1);
    @memcpy(combined[arr1.len..], arr2);
    return combined;
}

/// Similar to `concatRuntime`, but for arbitrary number of slices. Caller must free returned slice.
pub fn concatRuntimeMulti(alloc: std.mem.Allocator, comptime T: type, arrs: []const []const T) []const T {
    const out_len = blk: {
        var n: usize = 0;
        for (arrs) |arr| {
            n += arr.len;
        }
        break :blk n;
    };

    var out = alloc.alloc(T, out_len) catch @panic("OOM");
    errdefer alloc.free(out);

    var cursor: usize = 0;
    for (arrs) |arr| {
        @memcpy(out[cursor .. cursor + arr.len], arr);
        cursor += arr.len;
    }

    return out;
}

// Tests

test "getUserNameWhoami" {
    // NOTE: Will fail if either: 1.) whoami not available, or 2.) envvar $USER not found.

    const whoami = try getUsernameWhoami(std.testing.allocator);
    defer std.testing.allocator.free(whoami.?);

    const env = std.posix.getenv("USER");
    try std.testing.expectEqualStrings(std.mem.span(env.?.ptr), whoami.?);
}

test "getUserNameEnv" {
    const env = getUsernameEnv(std.testing.allocator);
    const whoami = try getUsernameWhoami(std.testing.allocator);
    defer std.testing.allocator.free(env.?);
    defer std.testing.allocator.free(whoami.?);

    try std.testing.expectEqualStrings(env.?, whoami.?);
}

test "concatRuntime" {
    const alloc = std.testing.allocator;
    const a: []const u8 = "a";
    const b: []const u8 = "b";
    const c: []const u8 = concatRuntime(alloc, u8, a, b);
    defer alloc.free(c);
    try std.testing.expectEqualSlices(u8, "ab", c);
}

test "getConfigPath" {
    // TODO
    // check for env vars, then call function, and compare values (or lack thereof in case of envvar doesn't exist)
    // then do similar test for getUserName
}

test "concatRuntimeMulti" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const a1: []const u8, const a2: []const u8, const a3: []const u8 = .{ "one", "two", "three" };
    const arrs = [_][]const u8{ a1, a2, a3 };

    const result = concatRuntimeMulti(alloc, u8, &arrs);

    try std.testing.expectEqualSlices(u8, "onetwothree", result);
    try std.testing.expectEqualDeep("onetwothree", result);
    try std.testing.expectEqualSlices(u8, "one", concatRuntimeMulti(alloc, u8, &[_][]const u8{"one"}));
    try std.testing.expectEqualSlices(u8, "", concatRuntimeMulti(alloc, u8, &[_][]const u8{ "", "" }));

    const nums = [_][]const u64{ &[_]u64{1}, &[_]u64{ 2, 3 } };
    try std.testing.expectEqualSlices(u64, &[_]u64{ 1, 2, 3 }, concatRuntimeMulti(alloc, u64, &nums));

    const floats = [_][]const f32{ &[_]f32{1.1}, &[_]f32{ 2.22, 3.333 } };
    try std.testing.expectEqualSlices(f32, &[_]f32{ 1.1, 2.22, 3.333 }, concatRuntimeMulti(alloc, f32, &floats));
}
