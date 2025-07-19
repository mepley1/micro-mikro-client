//! Example cycle sort algorithm in Zig.
//! By rogueautomaton@mepley.net

const std = @import("std");

/// Perform in-place cycle sort on given array `arr`.
pub fn cycleSort(comptime T: type, arr: []T) void {
    const len = arr.len;

    for (arr, 0..) |item, cycle_start| {
        var pos = cycle_start;
        var item_copy = item;

        // Count the number of items that are smaller than the current item
        for (cycle_start + 1..len) |i| {
            if (arr[i] < item_copy) {
                pos += 1;
            }
        }

        // Skip if item is already in the correct position
        if (pos == cycle_start) continue;

        // Skip duplicates
        while (item_copy == arr[pos]) {
            pos += 1;
        }

        // Place the item in its correct position
        if (pos != cycle_start) {
            std.mem.swap(T, &item_copy, &arr[pos]);
        }

        // Rotate the rest of the cycle
        while (pos != cycle_start) {
            pos = cycle_start;

            for (cycle_start + 1..len) |i| {
                if (arr[i] < item_copy) {
                    pos += 1;
                }
            }

            while (item_copy == arr[pos]) {
                pos += 1;
            }

            std.mem.swap(T, &item_copy, &arr[pos]);
        }
    }
}

test "cycleSort" {
    var arr = [_]u8{ 3, 2, 4, 1, 0 };
    cycleSort(u8, &arr);
    try std.testing.expectEqual([5]u8{ 0, 1, 2, 3, 4 }, arr);
}
