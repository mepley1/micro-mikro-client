//! Cycle sort algorithm in Zig.
//! By rogueautomaton@mepley.net

const std = @import("std");

/// Perform in-place cycle sort on given array `arr`.
/// Infallible.
pub fn cycleSort(comptime T: type, arr: []T) void {
    const len = arr.len;

    for (arr, 0..) |item, cycle_start| {
        var pos = cycle_start;
        var item_copy = item;

        // Count the number of items that are < current item
        for (cycle_start + 1..len) |i| {
            if (arr[i] < item_copy) {
                pos += 1;
            }
        }

        // Skip if already in the correct position
        if (pos == cycle_start) continue;

        // Skip dupes
        while (item_copy == arr[pos]) {
            pos += 1;
        }

        // Place item in its correct position
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
    var arr = [_]u8{ 3, 64, 2, 4, 1, 0x00, 0b11111111 };
    cycleSort(u8, &arr);
    try std.testing.expectEqualSlices(u8, &[7]u8{ 0, 1, 2, 3, 4, 64, 255 }, &arr);

    var floats = [_]f32{ 5.0, 3.14, 1.1, 4.20, 2.2 };
    cycleSort(f32, &floats);
    try std.testing.expectEqualSlices(f32, &[_]f32{ 1.1, 2.2, 3.14, 4.20, 5.0 }, &floats);
}

test "alpha" {
    var letters = [_]u8{ 'd', 'c', 'b', 'a' };
    cycleSort(u8, &letters);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 'a', 'b', 'c', 'd' }, &letters);
}