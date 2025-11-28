const std = @import("std");
const Des = @import("des.zig");
const fmt = std.fmt;

pub fn main() !void {
    var des_key_buf: [8]u8 = undefined;
    const des_key = try fmt.hexToBytes(&des_key_buf, "937464bba4f8fed9");
    var des_text_buf: [8]u8 = undefined;
    const des_text = try fmt.hexToBytes(&des_text_buf, "0000000000000000");
    var des_ciph_buf: [8]u8 = undefined;
    const des_ciph = try fmt.hexToBytes(&des_ciph_buf, "5a1fce5847fffa37");

    var des = Des.Des.init();

    std.debug.print("\nDES-ENCRYPT", .{});
    std.debug.print("\nkey\t{x}", .{des_key});
    std.debug.print("\ntext\t{x}", .{des_text});

    des.encrypt(des_key, null, des_text);
    std.debug.print("\nciph\t{x}", .{des.cipher[0..des_ciph.len]});

    std.debug.print("\n\nDES-DECRYPT", .{});
    std.debug.print("\nkey\t{x}", .{des_key});
    std.debug.print("\nciph\t{x}", .{des_ciph});

    des.decrypt(des_key, null, des_ciph);
    std.debug.print("\ntext\t{x}", .{des.cipher[0..des_text.len]});

    const triple_des_key = Des.TripleDesKey.initFromHex("937464bba4f8fed94b3427b34835fbcf1012aa1c1c038bfd");
    var triple_des_iv_buf: [8]u8 = undefined;
    const triple_des_iv = try fmt.hexToBytes(&triple_des_iv_buf, "0000000000000000");
    var triple_des_text_buf: [8]u8 = undefined;
    const triple_des_text = try fmt.hexToBytes(&triple_des_text_buf, "0000000000000000");
    var triple_des_ciph_buf: [8]u8 = undefined;
    const triple_des_ciph = try fmt.hexToBytes(&triple_des_ciph_buf, "daa1a686939cdc51");

    var triple_des = Des.TripleDes.init();

    std.debug.print("\n\nTRIPLE-DES-ENCRYPT", .{});
    try printTripleDesKeySchedule(triple_des_key);
    std.debug.print("\niv\t{x}", .{triple_des_iv});
    std.debug.print("\ntext\t{x}", .{triple_des_text});

    triple_des.encrypt(triple_des_key, triple_des_iv, triple_des_text);
    std.debug.print("\nciph\t{x}", .{triple_des.cipher[2][0..triple_des_ciph.len]});

    std.debug.print("\n\nTRIPLE-DES-DECRYPT", .{});
    try printTripleDesKeySchedule(triple_des_key);
    std.debug.print("\niv\t{x}", .{triple_des_iv});
    std.debug.print("\nciph\t{x}", .{triple_des_ciph});

    triple_des.decrypt(triple_des_key, triple_des_iv, triple_des_ciph);
    std.debug.print("\ntext\t{x}\n", .{triple_des.cipher[2][0..triple_des_text.len]});
}

fn printTripleDesKeySchedule(tdk: Des.TripleDesKey) !void {
    std.debug.print("\nkey\t{x}{x}{x}", .{ &tdk.key[0], &tdk.key[1], &tdk.key[2] });
}
