#!/usr/bin/env bash

# Some of the unit tests in src/main.zig depend on default config values, in both static conf file and env vars.
# This script sets these values, (storing existing file in a temp file) then runs the tests.

# Backup existing config
mv "/home/$(whoami)/.config/micro-mikro-client/.env.json" "/home/$(whoami)/.config/micro-mikro-client/.env.json.temp"

# Copy default config to user `.config` dir
cp "./.env.json.default" "/home/$(whoami)/.config/micro-mikro-client/.env.json"

# Set up environment vars
MICROMIKRO_ROUTER=router.lan
MICROMIKRO_AUTH="dXNlcjpwdw=="

zig test src/main.zig
zig test src/b64.zig
zig test src/functions.zig
zig test src/validation.zig


mv "/home/$(whoami)/.config/micro-mikro-client/.env.json.temp" "/home/$(whoami)/.config/micro-mikro-client/.env.json"
