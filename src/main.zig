const std = @import("std");
const Des = @import("des.zig");
const fmt = std.fmt;

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var des_key_buf: [8]u8 = undefined;
    const des_key = try fmt.hexToBytes(&des_key_buf, "937464bba4f8fed9");
    var des_text_buf: [8]u8 = undefined;
    const des_text = try fmt.hexToBytes(&des_text_buf, "0000000000000000");
    var des_ciph_buf: [8]u8 = undefined;
    const des_ciph = try fmt.hexToBytes(&des_ciph_buf, "5a1fce5847fffa37");

    var des = Des.Des.init();

    try stdout.print("\nDES-ENCRYPT", .{});
    try stdout.print("\nkey\t{s}", .{fmt.fmtSliceHexLower(des_key)});
    try stdout.print("\ntext\t{s}", .{fmt.fmtSliceHexLower(des_text)});

    des.encrypt(des_key, null, des_text);
    try stdout.print("\nciph\t{s}", .{fmt.fmtSliceHexLower(des.cipher[0..des_ciph.len])});

    try stdout.print("\n\nDES-DECRYPT", .{});
    try stdout.print("\nkey\t{s}", .{fmt.fmtSliceHexLower(des_key)});
    try stdout.print("\nciph\t{s}", .{fmt.fmtSliceHexLower(des_ciph)});

    des.decrypt(des_key, null, des_ciph);
    try stdout.print("\ntext\t{s}", .{fmt.fmtSliceHexLower(des.cipher[0..des_text.len])});

    var triple_des_key = Des.TripleDesKey.initFromHex("fb16b430a2393ded4b3427b34835fbcf1012aa1c1c038bfd");
    var triple_des_iv_buf: [8]u8 = undefined;
    const triple_des_iv = try fmt.hexToBytes(&triple_des_iv_buf, "a71d59c1afccad3f");
    var triple_des_text_buf: [1024]u8 = undefined;
    const triple_des_text = try fmt.hexToBytes(&triple_des_text_buf, "000000000000000000000000000000000000000000000000");
    var triple_des_ciph_buf: [1024]u8 = undefined;
    const triple_des_ciph = try fmt.hexToBytes(&triple_des_ciph_buf, "657e9511eb95f1c0c21689d8f18e494b20e9a654806d7ddb");

    var triple_des = Des.TripleDes.init();

    try stdout.print("\n\nTRIPLE-DES-ENCRYPT", .{});
    try printTripleDesKeySchedule(&triple_des_key);
    try stdout.print("\niv\t{s}", .{fmt.fmtSliceHexLower(triple_des_iv)});
    try stdout.print("\ntext\t{s}", .{fmt.fmtSliceHexLower(triple_des_text)});

    triple_des.encrypt(triple_des_key, triple_des_iv, triple_des_text);
    try stdout.print("\nciph\t{s}", .{fmt.fmtSliceHexLower(triple_des.cipher[2][0..triple_des_ciph.len])});

    try stdout.print("\n\nTRIPLE-DES-DECRYPT", .{});
    try printTripleDesKeySchedule(&triple_des_key);
    try stdout.print("\niv\t{s}", .{fmt.fmtSliceHexLower(triple_des_iv)});
    try stdout.print("\nciph\t{s}", .{fmt.fmtSliceHexLower(triple_des_ciph)});

    triple_des.decrypt(triple_des_key, triple_des_iv, triple_des_ciph);
    try stdout.print("\ntext\t{s}\n", .{fmt.fmtSliceHexLower(triple_des.cipher[2][0..triple_des_text.len])});
}

fn printTripleDesKeySchedule(tdk: *Des.TripleDesKey) !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("\nkey\t{s}{s}{s}", .{ fmt.fmtSliceHexLower(&tdk.key[0]), fmt.fmtSliceHexLower(&tdk.key[1]), fmt.fmtSliceHexLower(&tdk.key[2]) });
}
