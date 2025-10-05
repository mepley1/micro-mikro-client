# TO DO


## Accept an array of multiple IPs for --address
- parse arg as either an ArrayList or a filename
- Design to avoid being confused with --address-list (i.e. don't call it "address list" or similar)

## Add switch (or build option) to choose FixedBufferAllocator if building in ReleaseSmall mode
- embedded usually won't be able to use an OS allocator

## Rename config file from `.env.json` to something more standard?

## Fetch ZLS in build.zig, rather than including copy?
- I prefer to include any code used for stability/security, but it's more convenient to fetch it.

## Explicitly specify a config file path

## Enable reading encrypted config file/env values
- Preferably take a key at runtime as a command line option

## Update to Zig 0.15.1
