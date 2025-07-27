# TO DO

## Accept an array of multiple IPs for --address
- parse arg as either an ArrayList or a filename
- Design to avoid being confused with --address-list (i.e. don't call it "address list" or similar)

## Add switch to choose FixedBufferAllocator if building in ReleaseSmall mode
- embedded usually won't be able to use an OS allocator

## Rename config file from `.env.json` to something more standard?

## Fetch ZLS in build.zig, rather than including copy?
- I prefer to include any code used for stability/security, but it's more convenient to fetch it.
