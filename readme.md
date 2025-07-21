# micro-mikro-client

A tiny scriptable CLI client for MikroTik RouterOS REST API, for manipulating IPv4/IPv6 firewall address lists. Can be used standalone or as an automated action for your IDS/firewall/honeypot. Written in Zig.

Appends an IP address to a RouterOS `/ip` or `/ipv6` `/firewall/address-list` for use in firewall filters or etc.

Uses around 2KB memory depending on how you build it, (~2K in `ReleaseFast`, slightly less in Small - plus some extra in case of errors), so can be used on smaller devices/systems.

# Usage

```
micro-mikro-client 0.0.0

Options:

  -a, --address                    (REQUIRED) IP address to append to address-list.
  -r, --router                     (REQUIRED) Firewall/router hostname or IP. May also be set
                                     via environment variable $MICROMIKRO_FIREWALL
  -l, --address-list               Name of address-list (default: 'zigwang')
  -c, --comment                    Comment (printable ascii <= 127). (default: "")
  -t, --timeout                    Timeout - i.e. 4h or 00:04:00 (default: 4h)
  -p, --port                       Port, in case of REST API on non-standard port. Optional.
  -x, --proxy                      HTTP(S) proxy. This option takes precedence over any proxies
                                     found in $HTTP_PROXY/$HTTPS_PROXY env vars (i.e. --proxy ->
                                     environment -> none). Optional.
  -P, --ignore-system-proxy        Ignore $HTTP_PROXY/$HTTPS_PROXY environment variables. Might
                                     be useful for testing or odd networks.
  -e, --auth                       (REQUIRED*) Base64-encoded http basic auth string (i.e.
                                     result of `echo -n "user:pass" | base64`). May also be set
                                     via environment variable $MICROMIKRO_AUTH
  -u, --user                       Username of service account on firewall. If this arg is
                                     specified, a dialog (kdialog or stdin) will be spawned to
                                     prompt for password. Can only be used in an interactive
                                     shell - not scriptable. Recommended to pass `--auth` instead.
  -I, --insecure                   Use plaintext http (no tls) (not recommended). Only for
                                     testing; be mindful that without TLS, you'll be sending
                                     RouterOS credentials, with write access to your firewall, in
                                     plaintext across the network. Do not use this option if the
                                     RouterOS host is not link-local. *See RouterOS wiki for help
                                     with certificates.
  -6, --ipv6                       Target IPv6 firewall (i.e. call
                                     `/ipv6/firewall/address-list` endpoint as opposed to
                                     `/ip/firewall/address-list`). Use this option if `--address`
                                     is a v6 addr, thought that's not exactly what the option
                                     means; the v4 firewall does not accept a v6 addr. I have
                                     chosen to not detect/choose automatically, in favor of explicitness.
      --dry-run                    Dry run. Don't send request to RouterOS host; instead, print
                                     some info to stderr about what *would* have been sent.
      --ignore-config              Ignore config - don't read options from config file OR
                                     environment vars. Mostly for development; CLI args will
                                     always override config anyways.
      --help                       print help information
      --version                    print version information
```

## Required args:

- `-a, --address` | The IP you want to add to the address-list. RouterOS will also accept a DNS name, which it will resolve on its own using whatever DNS is configured for its own queries.
- `-r, --router` | DNS name or IP addr of RouterOS host. (Can also set in static config)
- `--auth` or `--user` | Either of these two auth options may be used, OR auth can be set in config (see below). `--auth` expects the base64-encoded (or not) `user:pass` substring of a http basic auth header ([rfc7617](https://datatracker.ietf.org/doc/html/rfc7617)). Easy way to get this value: `echo -n "username:password" | base64`. If `--user` is passed instead, you'll be prompted interactively for a password via either kdialog (if available and in a graphical environment) or a stdin reader. (thus `--user` shouldn't be used in scripts).
- Recommended to also include `-l`/`--address-list`, `-t`/`--timeout`, and `-c, --comment`. If not included, some defaults will be used, which may or may not suit your preferences. (TODO: Allow these to be configured in conf file)

The RouterOS host address (`-r`/`--router`) and auth creds (`--auth`) can also be configured in `~/.config/micro-mikro-client/.env.json`, or via environment variables (`MICROMIKRO_AUTH` and `MICROMIKRO_FIREWALL`). (TODO: Rename these to be consistent with conf file)

Program also respects `$HTTP_PROXY` + `$HTTPS_PROXY` variables and will use them if found.

The RouterOS host's TLS cert must be trusted by the host running the program, otherwise you will need to use `-I/--insecure` (no TLS). Supports TLS v1.2 via stdlib's `std.http.Client`.
`mkcert` is useful for testing certs. If for some reason you haven't configured TLS on your RouterOS host, then you *really* need to do so anyways if you're enabling the APIs and/or web interface.

## Examples

If you have configured your auth string and RouterOS hostname in static config, you only need to pass `-a/--address`:
```sh
micro-mikro-client -a 10.20.30.40
```

Append an address to an __IPv4__ `address-list` named `badips`, timeout 4 hours, RouterOS host at `192.168.88.1`:

```sh
micro-mikro-client \
    -a 10.20.30.40 \
    -r 192.168.88.1 \
    -t 4h \
    --address-list "badips" \
    --comment "testing" \
    --auth "dXNlcjpwd2Q="
```

Similar to above, but append to an __IPv6__ `address-list`:

```sh
micro-mikro-client \
    -6 \
    -a 2001:db8::abcd:1234 \
    -r 192.168.88.1 \
    -t 4h \
    --address-list "badips" \
    --auth "dXNlcjpwd2Q="
```

Add own public IP addr to an address list:

```sh
micro-mikro-client -a $(curl https://ip.mepley.net) --address-list "self-public" -t 4h --comment "Automated" 
```

Pass auth str, encoded via bash expansion:
```sh
micro-mikro-client -6 -a 2001:db8::bad:add:2 -r 2001:db8::1 -l "example-list" --auth $(echo -n "user:pass" | base64)
```

## Config

Some options can be configured statically in `$XDG_CONFIG_HOME/micro-mikro-client/.env.json`, which is read at runtime; see `.env.json.default` for example config.

Command line options override static config.

# Build

- `zig build -Doptimize=ReleaseFast`

Or, for specific target triples:

- `zig build -Doptimize=ReleaseSmall -Dcpu=znver5 -Dtarget=x86_64-linux-gnu`
- For Extreme Networks ap3825i (Freescale p1020) running OpenWRT (haven't tested on it yet, but it builds): `zig build -Dtarget=powerpc-linux-musl -Doptimize=ReleaseSmall` (see [since 2015 OpenWRT is based on musl libc](https://ziggit.dev/t/zig-programming-language-as-first-class-citizen/6736/9))

## Dependencies

[zli](https://github.com/dweiller/zli) (note: there are currently several different libs named ZLI to be found, that do the same thing).

# Notes

- RouterOS will accept an IPv4 address to add to an IPv6 address-list, but not vice versa. If the API responds with "xxx is not a valid DNS name", check your `--address` value.
- To b64-encode your creds, you can use `echo -n "user:pass" | base64` in a bash shell.
- Lots of `@branchHint(.likely)`/`@branchHint(.unlikely)` are used throughout the code, particularly around validation flows- because you're passing valid parameter values, *right?* ;)
- http.client works fine with RouterOS's TLS v1.2, but seemingly only by domain name and not IP. Not sure whether issue is with RouterOS or http.Client, or on my part.

# To do

TODO: this

# Contributing

Any pull requests are welcome, but maybe open an issue before putting your time into it. Expect spontaneous breaking changes.

Search the code for comments beginning with `TODO` or see `TODO.md` to find some low-hanging fruit.
