#!/usr/bin/env bash

# The unit tests in src/main.zig depend on some example config values being configured, in both static file and env vars.
# This script sets these values, (storing existing file in a temp file) then runs the tests.

mv "/home/$(whoami)/.config/micro-mikro-client/.env.json" "/home/$(whoami)/.config/micro-mikro-client/.env.json.temp"

cp "./.env.json.default" "/home/$(whoami)/.config/micro-mikro-client/.env.json"

export MICROMIKRO_FIREWALL=router.lan
export MICROMIKRO_AUTH="dXNlcjpwdw=="

zig test src/main.zig
# zig test src/b64.zig
# zig test src/functions.zig
# zig test src/validation.zig


mv "/home/$(whoami)/.config/micro-mikro-client/.env.json.temp" "/home/$(whoami)/.config/micro-mikro-client/.env.json"
