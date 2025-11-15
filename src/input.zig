//! Functions related to reading input.

const std = @import("std");
const builtin = @import("builtin");

const funcs = @import("functions.zig");

const PW_PROMPT: []const u8 = "Enter RouterOS password: ";

/// Based on result of `checkForKdialog()`, dispatch to either `getPassGraphical()` or `getPassCli()`.
pub fn getPassDispatch(alloc: std.mem.Allocator) ![]const u8 {
    switch (checkForKdialog(alloc)) {
        true => return try getPassGraphical(alloc),
        false => return try getPassCli(alloc),
    }
}

/// Check if kdialog is available on system.
/// Called by `getPassDispatch()`, not intended to be called directly.
fn checkForKdialog(alloc: std.mem.Allocator) bool {
    var cmd = std.process.Child.init(&[_][]const u8{ "which", "kdialog" }, alloc);
    cmd.stdout_behavior, cmd.stderr_behavior = .{ .Ignore, .Ignore };

    const x = cmd.spawnAndWait() catch @panic("Error spawning child process.");
    switch (x.Exited) {
        0 => return true,
        else => return false,
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
fn getPassGraphical(alloc: std.mem.Allocator) (std.process.Child.SpawnError || std.process.Child.WaitError || error{ OutOfMemory, ChildProcessError, UnsupportedOS })![]const u8 {
    switch (builtin.os.tag) {
        .linux => {
            @branchHint(.likely);
        },
        else => {
            @branchHint(.unlikely);
            return error.UnsupportedOS;
        },
    }

    var cmd = std.process.Child.init(&[_][]const u8{ "kdialog", "--password", PW_PROMPT, "--title", "Password" }, alloc);
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

/// Prompt for pw + read from stdin. Caller must free returned slice.
///
/// Private; called by `getPassDispatch()`
fn getPassCli(alloc: std.mem.Allocator) ![]const u8 {
    const stdin = std.io.getStdIn();

    std.debug.print(PW_PROMPT, .{});

    try disableEcho(stdin.handle);
    defer enableEcho(stdin.handle) catch @panic("Couldn't re-enable echo!");
    var stdin_reader = stdin.reader();
    const password = try stdin_reader.readUntilDelimiterAlloc(alloc, '\n', 1024);

    if (password.len == 0) {
        return error.EmptyPassword;
    }
    return password;
}

/// Disable echo, to hide input. Don't forget to reset.
fn disableEcho(fd: std.posix.fd_t) !void {
    var termios: std.posix.termios = try std.posix.tcgetattr(fd);
    termios.lflag.ECHO = false;
    try std.posix.tcsetattr(fd, .NOW, termios);
}

fn enableEcho(fd: std.posix.fd_t) (std.posix.TermiosGetError || std.posix.TermiosSetError)!void {
    var termios: std.posix.termios = try std.posix.tcgetattr(fd);
    termios.lflag.ECHO = true;
    try std.posix.tcsetattr(fd, .NOW, termios);
}

test "getPassCli" {
    // TODO
    // const input = try getPassCli(std.testing.allocator_instance);
}
