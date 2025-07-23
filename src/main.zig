//! A tiny scriptable CLI client for RouterOS firewall.

const std = @import("std");
const builtin = @import("builtin");
const zli = @import("include/zli/src/root.zig");

const funcs = @import("functions.zig");
const b64 = @import("b64.zig");
const validation = @import("validation.zig");

const IS_DEBUG = switch (builtin.mode) {
    .Debug, .ReleaseSafe => true,
    .ReleaseFast, .ReleaseSmall => false,
};

/// Body of the http request.
const Payload = struct {
    address: []const u8 = "",
    list: []const u8 = "zigwang",
    timeout: []const u8 = "4h",
    comment: []const u8 = "",
};

pub const arg_spec = [_]zli.Arg{
    .{
        .name = .{ .long = .{ .full = "address", .short = 'a' } },
        .short_help = "(REQUIRED) IP address to append to address-list.",
        .type = []const u8,
    },
    .{
        .name = .{ .long = .{ .full = "router", .short = 'r' } },
        .short_help = "(REQUIRED) Firewall/router hostname or IP. May also be set via environment variable $MICROMIKRO_FIREWALL",
        .type = []const u8,
    },
    .{
        .name = .{ .long = .{ .full = "address-list", .short = 'l' } },
        .short_help = "Name of address-list (default: 'zigwang')",
        .type = []const u8,
    },
    .{
        .name = .{ .long = .{ .full = "comment", .short = 'c' } },
        .short_help = "Comment (printable ascii <= 127). (default: \"\")",
        .type = []const u8,
    },
    .{
        .name = .{ .long = .{ .full = "timeout", .short = 't' } },
        .short_help = "Timeout - i.e. 4h or 00:04:00 (default: 4h)",
        .type = []const u8,
    },

    // Network options

    .{
        .name = .{ .long = .{ .full = "port", .short = 'p' } },
        .short_help = "Port, in case of REST API on non-standard port. Optional.",
        .type = u16,
    },
    .{
        .name = .{ .long = .{ .full = "proxy", .short = 'x' } },
        .short_help = "HTTP(S) proxy. This option takes precedence over any proxies found in $HTTP_PROXY/$HTTPS_PROXY env vars (i.e. --proxy -> environment -> none). Optional.",
        .type = []const u8,
    },
    .{
        .name = .{ .long = .{ .full = "ignore-system-proxy", .short = 'P' } },
        .short_help = "Ignore $HTTP_PROXY/$HTTPS_PROXY environment variables. Might be useful for testing or odd networks.",
        .type = bool,
    },

    // Auth

    .{
        .name = .{ .long = .{ .full = "auth", .short = 'e' } },
        .short_help = "(REQUIRED*) Base64-encoded http basic auth string (i.e. result of `echo -n \"user:pass\" | base64`). May also be set via environment variable $MICROMIKRO_AUTH",
        .type = []const u8,
    },
    .{
        .name = .{ .long = .{ .full = "user", .short = 'u' } },
        .short_help = "Username of service account on firewall. If this arg is specified, a dialog (kdialog or stdin) will be spawned to prompt for password. Can only be used in an interactive shell - not scriptable. Recommended to pass `--auth` instead.",
        .type = []const u8,
    },

    // Misc Bool flags

    .{
        .name = .{ .long = .{ .full = "insecure", .short = 'I' } },
        .short_help = "Use plaintext http (no tls) (not recommended). Only for testing; be mindful that without TLS, you\'ll be sending RouterOS credentials, with write access to your firewall, in plaintext across the network. Do not use this option if the RouterOS host is not link-local. *See RouterOS wiki for help with certificates.",
        .type = bool,
    },
    .{
        .name = .{ .long = .{ .full = "ipv6", .short = '6' } },
        .short_help = "Target IPv6 firewall (i.e. call `/ipv6/firewall/address-list` endpoint as opposed to `/ip/firewall/address-list`). Use this option if `--address` is a v6 addr, thought that's not exactly what the option means; the v4 firewall does not accept a v6 addr. I have chosen to not detect/choose automatically, in favor of explicitness.",
        .type = bool,
    },
    .{
        .name = .{ .long = .{ .full = "dry-run" } },
        .short_help = "Dry run. Don\'t send request to RouterOS host; instead, print some info to stderr about what *would* have been sent.",
        .type = bool,
    },
    .{
        .name = .{ .long = .{ .full = "ignore-config" } },
        .short_help = "Ignore config - don't read options from config file OR environment vars. Mostly for development; CLI args will always override config anyways.",
        .type = bool,
    },
};

/// TODO: Increment version before publishing any tag/release
const app_ver: std.SemanticVersion = std.SemanticVersion{
    .major = 0,
    .minor = 0,
    .patch = 0,
};

const Cli = zli.CliCommand("micro-mikro-client", .{
    .parameters = &arg_spec,
    .version = app_ver,
});

pub fn main() !void {

    // Conditionally choose child allocator for arena
    // TODO: Use fixed buffer allocator for .ReleaseSmall mode, so I can run it on embedded more conveniently.
    var debug_allocator: ?std.heap.DebugAllocator(.{}) = comptime switch (IS_DEBUG) {
        true => .init,
        false => null,
    };
    defer if (IS_DEBUG) {
        _ = debug_allocator.?.deinit();
    };
    var arena = switch (IS_DEBUG) {
        true => std.heap.ArenaAllocator.init(debug_allocator.?.allocator()),
        false => std.heap.ArenaAllocator.init(std.heap.page_allocator),
    };
    defer arena.deinit();
    const alloc = arena.allocator();

    // Parse CLI args (zli)
    const parse_result = Cli.parse(alloc) catch |err| {
        std.log.err("{s}", .{@errorName(err)});
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
        std.process.exit(3);
    };
    defer parse_result.deinit(alloc);

    const params = switch (parse_result) {
        .ok => |ok| ok,
        .err => |err| {
            err.renderToStdErr();
            std.process.exit(2);
        },
    };

    // If --router and [--auth OR --user] weren't both given, read static config. (or skip if --ignore-config)
    var configs: *ConfigData = try alloc.create(ConfigData);
    configs.* = ConfigData{};
    if (!params.options.@"ignore-config") {
        @branchHint(.likely);
        if ((params.options.router == null) or (params.options.auth == null and params.options.user == null)) {
            if (IS_DEBUG) std.log.debug("Getting config...", .{});
            try configs.readFile(alloc);
            try configs.readEnv(alloc); // environment variables take precedence
        }
    } else {
        @branchHint(.unlikely);
        if (IS_DEBUG) std.log.debug("Option: --ignore-config.", .{});
    }
    defer {
        configs.cleanup(alloc);
        alloc.destroy(configs);
    }

    // Validate + consolidate params
    const validated_params = try validateParams(alloc, params);

    // Construct endpoint URI
    const router_addr: []const u8 = validated_params.router orelse configs.*.routeros_host orelse {
        @branchHint(.unlikely);
        std.log.err("Missing value for parameter -r/--router", .{});
        return error.MissingRouterAddr;
    };
    const scheme_modifier: []const u8 = if (params.options.insecure) "" else "s"; // Use TLS by default
    const ip_ver_modifier: []const u8 = if (params.options.ipv6) "v6" else ""; // If v6, use `/ipv6/firewall` endpoint

    var buf_url: [256]u8 = undefined;
    const url_full: []const u8 = try std.fmt.bufPrint(&buf_url, "http{s}://{s}:{d}/rest/ip{s}/firewall/address-list", .{ scheme_modifier, router_addr, validated_params.port.?, ip_ver_modifier });
    const uri = std.Uri.parse(url_full) catch {
        std.log.err("Attempted to parse invalid Uri - Probably invalid value for -r/--router", .{});
        return error.InvalidHostname;
    };

    // Set auth to passed value first, if null then fall back to config. (--user -> --auth -> config)
    var auth_raw: ?[]const u8 = validated_params.ubuf orelse params.options.auth orelse configs.*.auth orelse null;
    var auth_raw_needs_freed: bool = false;
    if (auth_raw) |val| {
        if (val.len > 4096) {
            std.log.err("Auth str too long (over 4KiB). You're doing too much!.", .{});
            return error.BadValue;
        }
        // If value doesn't look like base64, encode it.
        if (!validation.validateB64(val)) {
            std.log.debug("Auth str appears to be un-encoded. Encoding...", .{});
            auth_raw = try b64.b64EncodeAlloc(alloc, val);
            auth_raw_needs_freed = true;
        }
    } else {
        std.log.err("No auth string given! Must either pass as arg (--auth) or configure in ~/.config/.env.json", .{});
        return error.MissingCredentials;
    }
    defer if (auth_raw_needs_freed) {
        alloc.free(auth_raw.?);
        auth_raw_needs_freed = false;
    };

    const http_basic_auth: []const u8 = if (auth_raw) |val| funcs.concatRuntime(u8, alloc, "Basic ", val) else return error.DetectableIllegalUndefinedBehavior; //Should have errored by now if not given.
    defer alloc.free(http_basic_auth);

    // Set any additional PAYLOAD params here - all except .address have defaults
    var payload_items = Payload{
        .address = validated_params.bad_ip,
    };
    if (validated_params.comment) |v| payload_items.comment = v;
    if (validated_params.timeout) |v| payload_items.timeout = v;
    if (validated_params.addr_list) |v| payload_items.list = v;

    // Jsonify payload (method 1 - heap alloc)
    // const payload = try std.json.stringifyAlloc(alloc, payload_items, .{});
    // defer alloc.free(payload);

    // JSONify (method 2 - stack buffer)
    var payload_buf: [512]u8 = undefined;
    var payload_stream = std.io.fixedBufferStream(&payload_buf);
    try std.json.stringify(payload_items, .{ .emit_null_optional_fields = false, .whitespace = .minified }, payload_stream.writer());
    const payload: []const u8 = payload_stream.getWritten();

    var client = std.http.Client{ .allocator = alloc };
    defer client.deinit();

    // Use proxies from environment if present, unless either --ignore-system-proxy or --proxy given.
    if (params.options.@"ignore-system-proxy" == false and params.options.proxy == null) {
        @branchHint(.likely);
        client.initDefaultProxies(alloc) catch |err| {
            std.log.err("Proxy error.", .{});
            return err;
        };
    }

    if (params.options.proxy) |val| {
        try setClientProxy(alloc, &client, val);
        if (IS_DEBUG == true) {
            std.log.debug("http proxy: ({s}) {?any}", .{ client.http_proxy.?.*.host, client.http_proxy });
            std.log.debug("https proxy: ({s}) {?any}", .{ client.https_proxy.?.*.host, client.https_proxy });
        }
    }

    var hdr_buf: [512]u8 = undefined; // 512B should be plenty
    const req_options: std.http.Client.RequestOptions = .{
        .server_header_buffer = &hdr_buf,
        .extra_headers = &.{
            .{ .name = "authorization", .value = http_basic_auth },
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "connection", .value = "close" }, // HTTP <=1.1
        },
        .keep_alive = false,
    };

    // Open connection and send request, or if --dry-run, don't.
    switch (params.options.@"dry-run") {
        false => {
            @branchHint(.likely);
            var req = try client.open(std.http.Method.PUT, uri, req_options);
            defer req.deinit();
            req.transfer_encoding = .{ .content_length = payload.len };
            var wtr = req.writer();

            try req.send();
            try wtr.writeAll(payload);
            try req.finish();
            try req.wait();

            // Read the response and print ID to stdout.
            const result = try parseApiResponse(alloc, &req);

            if (result) |res| {
                defer alloc.free(result.?);
                try std.io.getStdOut().writer().writeAll(res);
            } else {
                std.log.debug("No entry created.", .{});
            }
        },
        true => {
            @branchHint(.unlikely);
            const out = DryRunOutput{
                .uri = url_full,
                .payload = payload,
                .extra_headers = req_options.extra_headers,
                .proxy = if (params.options.insecure == false) client.https_proxy else client.http_proxy,
            };

            const stderr = std.io.getStdErr().writer();
            try stderr.writeAll(out.asJson(alloc));
        },
    }

    return;
}

/// Set value of `client.http_proxy` and `client.https_proxy` based on `proxy`.
///
/// Refer to code for `std.http.Client.initDefaultProxies` for example.
///
/// TODO: Support Proxy.authorization
fn setClientProxy(arena: std.mem.Allocator, client: *std.http.Client, proxy: []const u8) !void {
    client.connection_pool.mutex.lock();
    defer client.connection_pool.mutex.unlock();
    std.debug.assert(client.connection_pool.used.first == null);

    const a = try std.Uri.parse(proxy);

    const proxy_http: *std.http.Client.Proxy = try arena.create(std.http.Client.Proxy);
    errdefer arena.destroy(proxy_http);
    proxy_http.* = .{
        .protocol = if (std.mem.eql(u8, "http", a.scheme)) .plain else .tls,
        .host = a.host.?.percent_encoded,
        .port = a.port.?,
        .supports_connect = true,
        .authorization = null,
    };

    const proxy_https = try arena.create(std.http.Client.Proxy);
    errdefer arena.destroy(proxy_https);
    proxy_https.* = .{
        .protocol = if (std.mem.eql(u8, "http", a.scheme)) .plain else .tls,
        .host = a.host.?.percent_encoded,
        .port = a.port.?,
        .supports_connect = true,
        .authorization = null,
    };

    client.*.http_proxy = proxy_http;
    client.*.https_proxy = proxy_https;

    return;
}

const DryRunOutput = struct {
    uri: []const u8,
    payload: []const u8,
    headers: ?std.http.Client.Request.Headers = null,
    extra_headers: []const std.http.Header,
    proxy: ?*std.http.Client.Proxy,

    const Self = @This();

    /// Caller owns returned slice.
    fn asJson(self: Self, alloc: std.mem.Allocator) []u8 {
        var out_str = std.ArrayListUnmanaged(u8).initCapacity(alloc, 4096) catch @panic("Out of memory!");
        errdefer alloc.free(out_str);

        std.json.stringify(self, .{ .whitespace = .indent_4, .emit_nonportable_numbers_as_strings = true }, out_str.writer(alloc)) catch @panic("Writer Error");
        return out_str.toOwnedSlice(alloc) catch @panic("Out of memory!");
    }
};

/// Parse API response, and return entry ID. In case of status other than 201, print some info to stderr.
fn parseApiResponse(alloc: std.mem.Allocator, req: *std.http.Client.Request) !?[]const u8 {
    var rdr = req.reader();

    const body = try rdr.readAllAlloc(alloc, 4096);
    defer alloc.free(body);

    const parsed = std.json.parseFromSliceLeaky(ApiResponse, alloc, body, .{ .ignore_unknown_fields = true }) catch unreachable;

    switch (req.response.status) {
        .created => {
            @branchHint(.likely);
            return alloc.dupe(u8, parsed.@".id".?) catch @panic("Out of memory!");
        },
        .bad_request => |st| { // 400
            @branchHint(.unlikely);
            std.log.err("FAILURE: {d} | response detail: {?s}", .{ st, parsed.detail });
            if (parsed.detail == null) {
                std.log.err("Response body: {s}", .{body});
            }
            return null;
        },
        .unauthorized => |st| { // 401
            @branchHint(.unlikely);
            std.log.err("FAILURE: {d} | Check credentials + service account access policies.", .{st});
            return null;
        },
        else => |st| {
            @branchHint(.unlikely);
            std.log.err("FAILURE: {d} | Server response: {s}", .{ st, body });
            return null;
        },
    }

    unreachable;
}

/// Contains data parsed from API response - see RouterOS rest api docs for structure
const ApiResponse = struct {
    // Success
    @".id": ?[]const u8 = undefined,
    address: ?[]const u8 = undefined,
    comment: ?[]const u8 = undefined,
    @"creation-time": ?[]const u8 = undefined,
    disabled: ?[]const u8 = undefined,
    dynamic: ?[]const u8 = undefined,
    list: ?[]const u8 = undefined,
    timeout: ?[]const u8 = undefined,
    // Errors
    @"error": ?u32 = null,
    message: ?[]const u8 = null,
    detail: ?[]const u8 = null,
};

/// Contains program config values, as read from conf file/environment
const ConfigData = struct {
    auth: ?[]const u8 = null,
    routeros_host: ?[]const u8 = null,

    const Self = @This();

    /// Not needed if using arena, but I prefer explicitness.
    /// TODO: Ensure each value is a result of an allocation that actually needs freed.
    fn cleanup(self: *Self, alloc: std.mem.Allocator) void {
        if (self.auth != null) {
            alloc.free(self.auth.?);
        }
        if (self.routeros_host != null) {
            alloc.free(self.routeros_host.?);
        }
    }

    /// Read config from environment variables.
    fn readEnv(self: *Self, alloc: std.mem.Allocator) error{ OutOfMemory, EnvironmentVariableNotFound, InvalidWtf8 }!void {
        if (IS_DEBUG) std.log.debug("Checking for config in environment variables ...", .{});

        // Names of envvars
        const envvar_auth: []const u8 = "MICROMIKRO_AUTH";
        const envvar_router: []const u8 = "MICROMIKRO_FIREWALL";

        if (std.process.hasNonEmptyEnvVarConstant(envvar_auth)) {
            self.*.auth = try std.process.getEnvVarOwned(alloc, envvar_auth);
        }
        if (std.process.hasNonEmptyEnvVarConstant(envvar_router)) {
            self.routeros_host = try std.process.getEnvVarOwned(alloc, envvar_router);
        }

        return;
    }

    /// Read and parse config file, then set self's attrs.
    fn readFile(self: *Self, alloc: std.mem.Allocator) !void {
        if (IS_DEBUG) std.log.debug("Loading config from file ...", .{});

        const CONF_FILE_PATH: []const u8 = try funcs.getConfigPath(alloc);
        defer alloc.free(CONF_FILE_PATH);

        if (IS_DEBUG) std.log.debug("CONF_FILE_PATH: {s}", .{CONF_FILE_PATH});

        const handle = std.fs.openFileAbsolute(CONF_FILE_PATH, .{
            .mode = .read_only,
        }) catch |err| {
            switch (err) {
                error.FileNotFound => {
                    std.log.debug("Config file not found.", .{});
                    return;
                },
                else => {
                    std.log.err("Failure opening config file: {}", .{err});
                    return err;
                },
            }
        };
        defer handle.close();

        const conf_file_data: ?[]u8 = handle.readToEndAlloc(alloc, 2048) catch |err| {
            std.log.err("Failure reading config file: {}", .{err});
            return err;
        };
        defer alloc.free(conf_file_data.?);

        const parsed: *ConfigData = try alloc.create(ConfigData);
        parsed.* = ConfigData{};

        parsed.* = std.json.parseFromSliceLeaky(ConfigData, alloc, conf_file_data.?, .{
            .ignore_unknown_fields = true,
            .duplicate_field_behavior = .use_last,
            // .allocate = .alloc_always,
        }) catch |err| {
            std.log.err("Failed parsing config! Ensure file contains valid JSON + valid values.", .{});
            return err;
        };
        defer {
            parsed.cleanup(alloc);
            alloc.destroy(parsed);
        }

        if (parsed.auth) |val| self.auth = try alloc.dupe(u8, val);
        if (parsed.routeros_host) |val| self.routeros_host = try alloc.dupe(u8, val);

        return;
    }
};

/// All fields are optionals, EXCEPT `.bad_ip`
const Options = struct {
    bad_ip: []const u8,
    timeout: ?[]const u8,
    comment: ?[]const u8,
    router: ?[]const u8,
    addr_list: ?[]const u8,
    ubuf: ?[]const u8,
    port: ?u16,
};

/// Testing / unused right now.
const InvalidIpAddr = error{ InvalidIpAddrV4, InvalidIpAddrV6 };

/// Validate and consolidate param values that will become parts of the http request.
/// Any possible bad values should be caught before being forwarded to api, to minimize wasted resources.
///
/// TODO: This could probably benefit from some multithreading.
fn validateParams(alloc: std.mem.Allocator, params: anytype) !Options {
    // IP addr - required
    // IPv4 endpoint accepts v4 addr; v6 endpoint accepts BOTH v4/v6 addr. Both endpoints accept a dns name. Validate accordingly.
    var bad_ip: []const u8 = undefined;
    if (params.options.address) |v| {
        @branchHint(.likely);
        switch (params.options.ipv6) {
            false => {
                // v4
                if (!(validation.validateIpAddrV4(v) or validation.validateDnsName(v))) {
                    @branchHint(.unlikely);
                    std.log.err("Invalid IPv4 address/fqdn (-a/--address) for /ip/ (IPv4) endpoint: {s}", .{v});

                    return error.InvalidIpAddrV4;
                }
            },
            true => {
                // v6
                if (!(validation.validateIpAddr(v) or validation.validateDnsName(v))) {
                    @branchHint(.unlikely);
                    std.log.err("Invalid IP address/fqdn (-a/--address) for /ipv6/ endpoint: {s}", .{v});

                    return error.InvalidIpAddrV6;
                }
            },
        }
        bad_ip = v;
    } else {
        @branchHint(.unlikely);

        return error.MissingRequiredParam;
    }

    // Timeout
    const timeout: ?[]const u8 = params.options.timeout orelse null;
    if (timeout) |v| {
        if (!validation.validateTimeout(v)) {
            std.log.err("Invalid value for parameter -t/--timeout.", .{});

            return error.InvalidTimeout;
        }
    }

    // Comment - params.options.comment
    var comment: ?[]const u8 = null;
    if (params.options.comment) |v| {
        if (!validation.isAsciiPrintable(v)) {
            @branchHint(.cold);
            std.log.err("Invalid value (of length {d}) for parameter -c/--comment.", .{v.len});

            return error.InvalidComment;
        }
        if (v.len > 128) {
            @branchHint(.cold);
            std.log.err("Comment too long (length {d})", .{v.len});

            return error.InvalidComment;
        }
        comment = v;
    }

    // Router addr
    var router: ?[]const u8 = null;
    if (params.options.router) |v| {
        @branchHint(.likely);
        if (!validation.validateDnsName(v) and !validation.validateIpAddr(v)) {
            @branchHint(.cold);
            std.log.err("Invalid host for parameter -r/--router.", .{});

            return error.InvalidRouterHost;
        }
        router = v;
    }

    // Address-list name
    var addr_list: ?[]const u8 = null;
    if (params.options.@"address-list") |v| {
        if (!validation.isAsciiPrintable(v)) {
            @branchHint(.cold);
            std.log.err("Invalid value for parameter -l/--address-list.", .{});

            return error.InvalidAddrList;
        }
        if (v.len > 128) {
            @branchHint(.cold);
            std.log.err("Value too long for parameter -l/--address-list. (length {d}) ", .{v.len});

            return error.InvalidAddrList;
        }
        addr_list = v;
    }

    // Username, for interactive auth
    // TODO: Check RouterOS wiki for max user length
    var ubuf: ?[]const u8 = null;
    if (params.options.user) |v| {
        if ((!validation.isAsciiPrintable(v)) or v.len > 512) {
            @branchHint(.cold);

            return error.InvalidUserName;
        }

        const _pw: []const u8 = try funcs.getPassDispatch(alloc); // Prompt for pw

        ubuf = std.fmt.allocPrint(alloc, "{s}:{s}", .{ v, _pw[0.._pw.len] }) catch @panic("Out of memory!");
    }

    // Port
    // Not much to do here, a bad value won't get past initial zli parsing.
    // If not given, default to 443; if --insecure, then 80.
    var port: ?u16 = null;
    if (params.options.port) |v| {
        port = v;
    } else {
        port = switch (params.options.insecure) {
            false => blk: {
                @branchHint(.likely);
                break :blk 443;
            },
            true => blk: {
                @branchHint(.unlikely);
                break :blk 80;
            },
        };
    }

    return Options{
        .bad_ip = bad_ip,
        .timeout = timeout,
        .comment = comment,
        .router = router,
        .addr_list = addr_list,
        .ubuf = ubuf,
        .port = port,
    };
}

// ---- TESTS ----

test "ConfigData optionals" {
    const x = ConfigData{};
    try std.testing.expect(x.auth == null and x.routeros_host == null);
}

test "ConfigData allocated" {
    const x: *ConfigData = try std.testing.allocator.create(ConfigData);
    defer std.testing.allocator.destroy(x);
    x.* = ConfigData{};
    try std.testing.expect(x.auth == null and x.routeros_host == null);
}

test "ConfigData.readFile + .readEnv" {
    // Run this test via `unit_test_config.sh` if default config doesn't exist.

    std.testing.log_level = .debug;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const configs = try alloc.create(ConfigData);
    defer alloc.destroy(configs);

    // Test `.readFile()` first
    try configs.readFile(alloc);

    // These 3 will pass with any valid configs.
    try std.testing.expect(configs.auth != null);
    try std.testing.expect(configs.routeros_host != null);
    try std.testing.expect(std.mem.containsAtLeastScalar(u8, configs.routeros_host.?, 1, '.'));
    // These depend on default configs.
    try std.testing.expectEqualSlices(u8, "dXNlcjpwdw==", configs.auth.?);
    try std.testing.expectEqualStrings("router.lan", configs.routeros_host.?);

    // Now test .readEnv()
    try configs.readEnv(alloc);

    // These 3 should pass with *any* valid configs.
    try std.testing.expect(configs.auth != null);
    try std.testing.expect(configs.routeros_host != null);
    try std.testing.expect(std.mem.containsAtLeastScalar(u8, configs.routeros_host.?, 1, '.'));
    // These depend on default config. (.env.json.default)
    try std.testing.expectEqualStrings("dXNlcjpwdw==", configs.auth.?);
    try std.testing.expectEqualSlices(u8, "router.lan", configs.routeros_host.?);
}

test "Payload" {
    const payload_items = Payload{ .address = "10.69.69.69" };
    var string = std.ArrayList(u8).init(std.testing.allocator);
    defer string.deinit();
    try std.json.stringify(payload_items, .{}, string.writer()); //This makes `string` the payload.
    const payload = string.items;

    // Get payload.len in case I change defaults:
    // std.debug.print("\n\npayload len: {d}\n\n", .{payload.len});

    try std.testing.expect(payload.len == 70);
}
