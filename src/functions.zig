//! Helper functions that don't belong in any other file.

const std = @import("std");
const builtin = @import("builtin");

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
        false => return getPassCli(alloc),
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
fn getPassGraphical(alloc: std.mem.Allocator) ![]const u8 {
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

    try cmd.collectOutput(alloc, &buf_out, &buf_err, 1024);

    const term = try cmd.wait();

    if (term.Exited == 0) {
        @branchHint(.likely);
        buf_out.items = buf_out.items[0 .. buf_out.items.len - 1]; //kdialog adds an extra byte (c-string)
        return buf_out.toOwnedSlice(alloc);
    } else {
        @branchHint(.unlikely);
        return error.ChildProcessError;
    }
}

/// Get password via stdin. Not called directly; Called by `getPassDispatch()`
///
/// TODO: Hide input via control codes while typing.
fn getPassCli(alloc: std.mem.Allocator) []const u8 {
    const stdin = std.io.getStdIn().reader();
    const stderr = std.io.getStdErr().writer();

    stderr.print(pass_prompt, .{}) catch unreachable;
    const p = stdin.readUntilDelimiterAlloc(alloc, '\n', 512) catch unreachable;
    return p;
}

/// Return full absolute path to config file.
///
/// Read $XDG_CONFIG_HOME envvar, if not found then fall back to $HOME (append "/.config" to HOME).
/// If neither found, use `/home/$(whoami)/.config/`
pub fn getConfigPath(alloc: std.mem.Allocator) ![]const u8 {
    var conf_dir: []u8 = undefined;
    const conf_file_rel: []const u8 = "/micro-mikro-client/.env.json";

    if (std.process.hasNonEmptyEnvVarConstant("XDG_CONFIG_HOME")) {
        conf_dir = std.process.getEnvVarOwned(alloc, "XDG_CONFIG_HOME") catch {
            @panic("Error reading envvar.");
        };
        std.log.debug("Found $XDG_CONFIG_HOME", .{});
    } else if (std.process.hasNonEmptyEnvVarConstant("HOME")) {
        conf_dir = std.process.getEnvVarOwned(alloc, "HOME") catch {
            @panic("Error reading envvar.");
        };
        conf_dir = concatRuntime(u8, alloc, conf_dir, "./config");
        std.log.debug("Found $HOME", .{});
    } else {
        // Get username and format conf_dir to include it
        const usern = getUserNameEnv(alloc) catch getUserName(alloc) catch @panic("Couldn't discover username!");
        conf_dir = try std.fmt.allocPrint(alloc, "/home/{s}/.config", .{usern});
    }
    defer alloc.free(conf_dir);

    // Now concatenate conf_dir + conf_file_rel, to assemble absolute path to config file.
    const conf_path_abs: []const u8 = concatRuntime(u8, alloc, conf_dir, conf_file_rel);
    defer alloc.free(conf_path_abs);

    std.debug.assert(conf_path_abs.len <= std.fs.max_path_bytes);

    return try alloc.dupe(u8, conf_path_abs);
}

/// Get current username by calling whoami in a child process. Linux only.
///
/// Caller owns returned slice.
fn getUserName(alloc: std.mem.Allocator) ![]const u8 {
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
    defer buf_err.deinit(alloc);

    try cmd.collectOutput(alloc, &buf_out, &buf_err, 1024);

    const x = try cmd.wait();

    if (x.Exited == 0) {
        _ = buf_out.pop(); // Remove trailing null byte
        // std.log.debug("user: {s}", .{buf_out.items});
        return buf_out.toOwnedSlice(alloc);
    } else {
        return error.ChildProcessError;
    }
}

/// Get username by reading value of $USER envvar.
fn getUserNameEnv(alloc: std.mem.Allocator) ![]const u8 {
    const env = std.posix.getenv("USER");
    if (env) |u| {
        return try alloc.dupe(u8, std.mem.span(u.ptr));
    } else {
        return error.EnvironmentVarNotFound;
    }
}

/// Concatenate two runtime-known arrays. Caller must free returned slice.
pub fn concatRuntime(comptime T: type, allocator: std.mem.Allocator, arr1: []const T, arr2: []const T) []T {
    var combined = allocator.alloc(T, arr1.len + arr2.len) catch @panic("Out of memory!");
    errdefer allocator.free(combined);
    @memcpy(combined[0..arr1.len], arr1);
    @memcpy(combined[arr1.len..], arr2);
    return combined;
}

// Tests

test "getUserName" {
    // NOTE: Will fail if either: 1.) whoami not available, or 2.) envvar $USER not found.

    const whoami = try getUserName(std.testing.allocator);
    defer std.testing.allocator.free(whoami);

    const env = std.posix.getenv("USER");
    try std.testing.expectEqualStrings(std.mem.span(env.?.ptr), whoami);
}

test "getUserNameEnv" {
    const env = try getUserNameEnv(std.testing.allocator);
    const whoami = try getUserName(std.testing.allocator);
    defer std.testing.allocator.free(env);
    defer std.testing.allocator.free(whoami);

    try std.testing.expectEqualStrings(env, whoami);
}

test "concatRuntime" {
    const alloc = std.testing.allocator;
    const a: []const u8 = "a";
    const b: []const u8 = "b";
    const c: []const u8 = concatRuntime(u8, alloc, a, b);
    defer alloc.free(c);
    try std.testing.expectEqualSlices(u8, "ab", c);
}

test "getConfigPath" {
    // TODO
    // check for env vars, then call function, and compare values (or lack thereof in case of envvar doesn't exist)
    // then do similar test for getUserName
}
