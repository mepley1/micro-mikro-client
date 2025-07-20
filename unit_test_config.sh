#!/usr/bin/env bash

# The unit tests in src/main.zig depend on some example config values being configured, in both static file and env vars.
# This script sets these values, then runs the tests.

cp ./.env.json.default /home/$(whoami)/.config/micro-mikro-client/.env.json

export MICROMIKRO_FIREWALL=router.lan
export MICROMIKRO_AUTH="dXNlcjpwdw=="

zig test src/main.zig
