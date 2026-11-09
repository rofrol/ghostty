//! Assembly of Kitty desktop notifications (OSC 99) from their chunks.
//!
//! A notification may arrive in several OSC 99 sequences of one identifier:
//! each with `d=0` adds to it, and the first with `d=1` (the default)
//! completes it. Title and body chunks are concatenated in order; a Base64
//! (`e=1`) chunk is decoded on its own.
//!
//! This is the text-only subset of the protocol that a callback taking a
//! title and a body can carry:
//!
//! - One notification is assembled at a time: a chunk of another identifier
//!   abandons the unfinished one.
//! - Payloads that are not part of the notification's text (icons, buttons)
//!   leave the text as it is, though their `d=1` completes it; a
//!   notification with neither title nor body is not reported.
//! - A query, a close or an alive request is no part of any notification,
//!   and is not answered.
//! - A later notification with the identifier of an earlier one is reported
//!   as a new notification, not as an update of the earlier one.
//!
//! Specification: https://sw.kovidgoyal.net/kitty/desktop-notifications/
const Assembly = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const osc = @import("../osc.zig");
const encoding = @import("../osc/encoding.zig");

const log = std.log.scoped(.kitty_desktop_notification);

/// The most bytes the title, and the body, may each reach, so a program
/// that never sends `d=1` cannot grow them without bound. A notification
/// longer than this is dropped whole.
pub const max_text_bytes = 16 * 1024;

pub const State = enum {
    /// No notification is unfinished. The buffers hold the last completed
    /// notification, or nothing.
    idle,

    /// The chunks of notification `id` are being collected.
    assembling,

    /// Notification `id` was dropped before its last chunk arrived; its
    /// remaining chunks are ignored until that chunk, so no part of it is
    /// reported.
    discarding,
};

state: State = .idle,

/// The identifier of the unfinished notification; empty when the program
/// sent none.
id: std.ArrayListUnmanaged(u8) = .empty,

title: std.ArrayListUnmanaged(u8) = .empty,
body: std.ArrayListUnmanaged(u8) = .empty,

/// A completed notification. Both strings are borrowed from the assembly
/// and valid until its next `add`, `reset` or `deinit`.
pub const Notification = struct {
    title: []const u8,
    body: []const u8,
};

pub fn deinit(self: *Assembly, alloc: Allocator) void {
    self.id.deinit(alloc);
    self.title.deinit(alloc);
    self.body.deinit(alloc);
    self.* = .{};
}

/// Abandon the unfinished notification, if any.
pub fn reset(self: *Assembly) void {
    self.state = .idle;
    self.id.clearRetainingCapacity();
    self.title.clearRetainingCapacity();
    self.body.clearRetainingCapacity();
}

/// Add one OSC 99 sequence. Returns the notification it completes, if any.
///
/// A chunk whose payload is not valid Base64, that makes the text too
/// long, or that cannot be stored, drops the notification it belongs to,
/// and so does a completed text that is not escape code safe UTF-8 once
/// decoded.
pub fn add(
    self: *Assembly,
    alloc: Allocator,
    cmd: osc.Command.KittyDesktopNotification,
) Allocator.Error!?Notification {
    const target: ?*std.ArrayListUnmanaged(u8) = switch (cmd.readOption(.p)) {
        .title => &self.title,
        .body => &self.body,
        .icon, .buttons => null,
        .query, .close, .alive, .unknown => return null,
    };
    const done = cmd.readOption(.d);

    const id = cmd.readOption(.i) orelse "";
    if (self.state == .idle or !std.mem.eql(u8, self.id.items, id)) {
        self.reset();
        errdefer self.reset();
        try self.id.appendSlice(alloc, id);
        self.state = .assembling;
    }

    if (self.state == .discarding) {
        if (done) self.reset();
        return null;
    }

    if (target) |text| {
        const usable = append(alloc, text, cmd) catch |err| {
            self.discard(done);
            return err;
        };
        if (!usable) {
            self.discard(done);
            return null;
        }
    }

    if (!done) return null;
    self.state = .idle;

    if (self.title.items.len == 0 and self.body.items.len == 0) return null;

    // A Base64 chunk may end inside a character, so the decoded text is
    // checked whole. A plain chunk was checked by the parser already.
    if (!encoding.isSafeUtf8(self.title.items) or
        !encoding.isSafeUtf8(self.body.items))
    {
        log.warn("notification text is not escape code safe UTF-8, dropping it", .{});
        self.reset();
        return null;
    }

    return .{ .title = self.title.items, .body = self.body.items };
}

/// Drop the unfinished notification: at once if this was its last chunk,
/// otherwise once its last chunk arrives.
fn discard(self: *Assembly, done: bool) void {
    self.title.clearRetainingCapacity();
    self.body.clearRetainingCapacity();
    if (done) {
        self.reset();
    } else {
        self.state = .discarding;
    }
}

/// Append the payload of `cmd` to `text`, decoding it first if it is
/// Base64. Returns false if the chunk is unusable.
fn append(
    alloc: Allocator,
    text: *std.ArrayListUnmanaged(u8),
    cmd: osc.Command.KittyDesktopNotification,
) Allocator.Error!bool {
    const start = text.items.len;
    if (!cmd.readOption(.e)) {
        if (start + cmd.payload.len > max_text_bytes) {
            log.warn("notification text is too long, dropping it", .{});
            return false;
        }
        try text.appendSlice(alloc, cmd.payload);
        return true;
    }

    const decoder = std.base64.standard.Decoder;
    const len = decoder.calcSizeForSlice(cmd.payload) catch {
        log.warn("invalid Base64 payload, dropping the notification", .{});
        return false;
    };
    if (start + len > max_text_bytes) {
        log.warn("notification text is too long, dropping it", .{});
        return false;
    }
    try text.resize(alloc, start + len);
    decoder.decode(text.items[start..], cmd.payload) catch {
        log.warn("invalid Base64 payload, dropping the notification", .{});
        return false;
    };
    return true;
}

fn testAdd(a: *Assembly, alloc: Allocator, metadata: []const u8, payload: []const u8) !?Notification {
    return a.add(alloc, .{ .metadata = metadata, .payload = payload, .terminator = .st });
}

test "Base64 chunks may split a character" {
    const testing = std.testing;
    var a: Assembly = .{};
    defer a.deinit(testing.allocator);

    // "é" is 0xC3 0xA9; each chunk carries one of its bytes.
    try testing.expect(try testAdd(&a, testing.allocator, "i=s:d=0:e=1", "ww==") == null);
    const n = (try testAdd(&a, testing.allocator, "i=s:e=1", "qQ==")).?;
    try testing.expectEqualStrings("é", n.title);
    try testing.expectEqualStrings("", n.body);
}

test "a dropped notification reports no part of it" {
    const testing = std.testing;
    var a: Assembly = .{};
    defer a.deinit(testing.allocator);

    // Invalid Base64 in a chunk before the last.
    try testing.expect(try testAdd(&a, testing.allocator, "i=1:d=0", "Head") == null);
    try testing.expect(try testAdd(&a, testing.allocator, "i=1:d=0:e=1", "!!!") == null);
    try testing.expectEqual(State.discarding, a.state);
    try testing.expect(try testAdd(&a, testing.allocator, "i=1:d=0:p=body", "middle") == null);
    try testing.expect(try testAdd(&a, testing.allocator, "i=1:p=body", "tail") == null);
    try testing.expectEqual(State.idle, a.state);

    // The next notification of the same identifier is a new one.
    const n = (try testAdd(&a, testing.allocator, "i=1", "Next")).?;
    try testing.expectEqualStrings("Next", n.title);

    // Text past the limit, in a chunk before the last.
    const chunk: [2048]u8 = @splat('a');
    for (0..max_text_bytes / chunk.len) |_| {
        try testing.expect(try testAdd(&a, testing.allocator, "i=l:d=0", &chunk) == null);
    }
    try testing.expectEqual(State.assembling, a.state);
    try testing.expect(try testAdd(&a, testing.allocator, "i=l:d=0", "a") == null);
    try testing.expectEqual(State.discarding, a.state);
    try testing.expect(try testAdd(&a, testing.allocator, "i=l:p=body", "tail") == null);
    try testing.expectEqual(State.idle, a.state);

    // A chunk of another identifier ends the discarding too.
    try testing.expect(try testAdd(&a, testing.allocator, "i=x:d=0:e=1", "!!!") == null);
    try testing.expectEqual(State.discarding, a.state);
    const other = (try testAdd(&a, testing.allocator, "i=y", "Other")).?;
    try testing.expectEqualStrings("Other", other.title);
}

test "an allocation failure drops the notification" {
    const testing = std.testing;
    var a: Assembly = .{};
    defer a.deinit(testing.allocator);

    try testing.expect(try testAdd(&a, testing.allocator, "i=1:d=0", "Head") == null);
    var failing: std.testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(
        error.OutOfMemory,
        testAdd(&a, failing.allocator(), "i=1:d=0:p=body", "a body longer than what was reserved before"),
    );
    try testing.expectEqual(State.discarding, a.state);
    try testing.expect(try testAdd(&a, testing.allocator, "i=1:p=body", "tail") == null);
    try testing.expectEqual(State.idle, a.state);
}

test "a notification without text is not reported" {
    const testing = std.testing;
    var a: Assembly = .{};
    defer a.deinit(testing.allocator);

    try testing.expect(try testAdd(&a, testing.allocator, "i=1:p=icon", "") == null);
    try testing.expect(try testAdd(&a, testing.allocator, "", "") == null);
    try testing.expectEqual(State.idle, a.state);
}
