#!/usr/bin/env bash

# Copy .env.json (config file) to user's ~/.config
# Execute this script after changing conf file.

cp ./.env.json /home/$(whoami)/.config/micro-mikro-client/.env.json
