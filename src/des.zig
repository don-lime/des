const std = @import("std");
const endian = @import("builtin").target.cpu.arch.endian();
const mem = std.mem;
const fmt = std.fmt;
const math = std.math;

pub const Des = struct {
    const Self = @This();
    ip: [64]u8,
    exp: [48]u8,
    sbox: [8][64]u4,
    p: [32]u8,
    fp: [64]u8,

    cipher: [1024]u8,
    block_sum: usize,

    pub fn init() Self {
        var self: Self = undefined;

        self.ip = [_]u8{
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9,  1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7,
        };

        self.p = [_]u8{
            16, 7,  20, 21, 29, 12, 28, 17,
            1,  15, 23, 26, 5,  18, 31, 10,
            2,  8,  24, 14, 32, 27, 3,  9,
            19, 13, 30, 6,  22, 11, 4,  25,
        };

        self.exp = [_]u8{ 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

        self.sbox = [_][64]u4{
            [_]u4{
                14, 0,  4,  15, 13, 7,  1,  4,  2,  14, 15, 2, 11, 13, 8,  1,
                3,  10, 10, 6,  6,  12, 12, 11, 5,  9,  9,  5, 0,  3,  7,  8,
                4,  15, 1,  12, 14, 8,  8,  2,  13, 4,  6,  9, 2,  1,  11, 7,
                15, 5,  12, 11, 9,  3,  7,  14, 3,  10, 10, 0, 5,  6,  0,  13,
            },
            [_]u4{
                15, 3,  1,  13, 8,  4,  14, 7,  6,  15, 11, 2,  3,  8,  4,  14,
                9,  12, 7,  0,  2,  1,  13, 10, 12, 6,  0,  9,  5,  11, 10, 5,
                0,  13, 14, 8,  7,  10, 11, 1,  10, 3,  4,  15, 13, 4,  1,  2,
                5,  11, 8,  6,  12, 7,  6,  12, 9,  0,  3,  5,  2,  14, 15, 9,
            },
            [_]u4{
                10, 13, 0,  7,  9,  0,  14, 9,  6,  3,  3,  4,  15, 6,  5, 10,
                1,  2,  13, 8,  12, 5,  7,  14, 11, 12, 4,  11, 2,  15, 8, 1,
                13, 1,  6,  10, 4,  13, 9,  0,  8,  6,  15, 9,  3,  8,  0, 7,
                11, 4,  1,  15, 2,  14, 12, 3,  5,  11, 10, 5,  14, 2,  7, 12,
            },
            [_]u4{
                7,  13, 13, 8,  14, 11, 3,  5,  0,  6,  6,  15, 9, 0,  10, 3,
                1,  4,  2,  7,  8,  2,  5,  12, 11, 1,  12, 10, 4, 14, 15, 9,
                10, 3,  6,  15, 9,  0,  0,  6,  12, 10, 11, 1,  7, 13, 13, 8,
                15, 9,  1,  4,  3,  5,  14, 11, 5,  12, 2,  7,  8, 2,  4,  14,
            },
            [_]u4{
                2,  14, 12, 11, 4,  2,  1,  12, 7,  4,  10, 7,  11, 13, 6,  1,
                8,  5,  5,  0,  3,  15, 15, 10, 13, 3,  0,  9,  14, 8,  9,  6,
                4,  11, 2,  8,  1,  12, 11, 7,  10, 1,  13, 14, 7,  2,  8,  13,
                15, 6,  9,  15, 12, 0,  5,  9,  6,  10, 3,  4,  0,  5,  14, 3,
            },
            [_]u4{
                12, 10, 1,  15, 10, 4,  15, 2,  9,  7, 2,  12, 6,  9,  8,  5,
                0,  6,  13, 1,  3,  13, 4,  14, 14, 0, 7,  11, 5,  3,  11, 8,
                9,  4,  14, 3,  15, 2,  5,  12, 2,  9, 8,  5,  12, 15, 3,  10,
                7,  11, 0,  14, 4,  1,  10, 7,  1,  6, 13, 0,  11, 8,  6,  13,
            },
            [_]u4{
                4,  13, 11, 0,  2,  11, 14, 7,  15, 4,  0,  9,  8, 1,  13, 10,
                3,  14, 12, 3,  9,  5,  7,  12, 5,  2,  10, 15, 6, 8,  1,  6,
                1,  6,  4,  11, 11, 13, 13, 8,  12, 1,  3,  4,  7, 10, 14, 7,
                10, 9,  15, 5,  6,  0,  8,  15, 0,  14, 5,  2,  9, 3,  2,  12,
            },
            [_]u4{
                13, 1,  2,  15, 8,  13, 4,  8,  6,  10, 15, 3,  11, 7, 1, 4,
                10, 12, 9,  5,  3,  6,  14, 11, 5,  0,  0,  14, 12, 9, 7, 2,
                7,  2,  11, 1,  4,  14, 1,  7,  9,  4,  12, 10, 14, 8, 2, 13,
                0,  15, 6,  12, 10, 9,  13, 0,  15, 3,  3,  5,  5,  6, 8, 11,
            },
        };

        self.fp = [_]u8{
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9,  49, 17, 57, 25,
        };

        return self;
    }

    fn feistel(self: *Self, subkeys: [16]u64, state: u64, enc: bool) u64 {
        var sum: u64 = permute(&self.ip, state, 64);
        var left: u32 = @truncate(sum >> 32);
        var right: u32 = @truncate(sum);

        for (0..16) |i| {
            var exp: u64 = permute(&self.exp, right, 32) ^ subkeys[if (enc) i else (15 - i)];
            var sbox: u32 = 0;
            for (0..8) |s| {
                sbox = sbox << 4 | self.sbox[s][(exp >> ((48 - (@as(u6, @truncate(s)) * 6)) - 6)) & 63];
            }
            const swap: u32 = right;
            right = @as(u32, @truncate(permute(&self.p, sbox, 32))) ^ left;
            left = swap;
        }

        sum = right;
        sum = sum << 32 | left;

        return permute(&self.fp, sum, 64);
    }

    fn encryptBlock(self: *Self, subkeys: [16]u64, state: u64) u64 {
        return feistel(self, subkeys, state, true);
    }

    fn decryptBlock(self: *Self, subkeys: [16]u64, state: u64) u64 {
        return feistel(self, subkeys, state, false);
    }

    pub fn encrypt(self: *Self, key: []const u8, iv: ?[]const u8, buf: []const u8) void {
        var des = Des.init();
        const bufLen: usize = buf.len;
        self.block_sum = bufLen / 8;

        for (0..self.block_sum) |block| {
            const dks: DesKeySchedule = DesKeySchedule.init(bytesToUint64(key));
            var pt: u64 = bytesToUint64(buf[(block * 8)..((block * 8) + 8)]);
            if (block == 0) {
                if (iv) |value| {
                    const xorValue: u64 = bytesToUint64(value);
                    pt ^= xorValue;
                }
            } else {
                if (iv) |_| {
                    pt ^= bytesToUint64(self.cipher[((block - 1) * 8)..(((block - 1) * 8) + 8)]);
                }
            }
            switch (endian) {
                .Big => {
                    pt = des.encryptBlock(dks.subkeys, pt);
                },
                .Little => {
                    pt = @byteSwap(des.encryptBlock(dks.subkeys, pt));
                },
            }
            std.mem.copy(u8, self.cipher[(block * 8)..((block * 8) + 8)], &@as([8]u8, @bitCast(pt)));
        }
    }

    pub fn decrypt(self: *Self, key: []const u8, iv: ?[]const u8, buf: []const u8) void {
        var des = Des.init();
        const bufLen: usize = buf.len;
        self.block_sum = bufLen / 8;

        for (0..self.block_sum) |block| {
            const dks: DesKeySchedule = DesKeySchedule.init(bytesToUint64(key[0..8]));
            var pt: u64 = undefined;
            if (self.block_sum == 1) {
                pt = des.decryptBlock(dks.subkeys, bytesToUint64(buf[0..8]));
                if (iv) |value| {
                    const xorValue: u64 = bytesToUint64(value);
                    pt ^= xorValue;
                }
            } else {
                pt = des.decryptBlock(dks.subkeys, bytesToUint64(buf[((self.block_sum - (block + 1)) * 8)..(((self.block_sum - (block + 1)) * 8) + 8)]));
                if (self.block_sum - (block + 1) > 0) {
                    if (iv) |_| {
                        pt ^= bytesToUint64(buf[(((self.block_sum - (block + 1)) - 1) * 8)..((((self.block_sum - (block + 1)) - 1) * 8) + 8)]);
                    }
                } else {
                    if (iv) |value| {
                        const xorValue: u64 = bytesToUint64(value);
                        pt ^= xorValue;
                    }
                }
            }
            if (endian == .Little) {
                pt = @byteSwap(pt);
            }
            std.mem.copy(u8, self.cipher[((self.block_sum - (block + 1)) * 8)..(((self.block_sum - (block + 1)) * 8) + 8)], &@as([8]u8, @bitCast(pt)));
        }
    }
};

pub const DesKeySchedule = struct {
    const Self = @This();
    subkeys: [16]u64,

    pub fn init(key: u64) Self {
        var self: Self = undefined;

        const shift: [16]u5 = [_]u5{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        const pc1: [56]u8 = [_]u8{ 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
        const pc2: [48]u8 = [_]u8{ 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

        const half_len: u5 = 28;
        const mask: u28 = math.maxInt(u28);
        const state: u64 = permute(&pc1, key, 64);

        var left: u32 = @truncate(state >> half_len);
        var right: u32 = @truncate(state & mask);
        for (0..16) |i| {
            left = ((left << shift[i]) | ((left >> (half_len - shift[i]))) & mask);
            right = ((right << shift[i]) | ((right >> (half_len - shift[i]))) & mask);
            self.subkeys[i] = permute(&pc2, (@as(u64, left)) << half_len | right, 56);
        }

        return self;
    }
};

pub const TripleDes = struct {
    const Self = @This();
    cipher: [3][1024]u8,
    blk_count: usize,

    pub fn init() Self {
        var self: Self = undefined;
        self.cipher = undefined;
        self.blk_count = undefined;
        return self;
    }

    pub fn encrypt(self: *Self, tk: TripleDesKey, iv: ?[]const u8, buf: []const u8) void {
        var des = Des.init();
        const bufLen: usize = buf.len;
        self.blk_count = bufLen / 8;

        for (0..self.blk_count) |block| {
            var pt: u64 = undefined;
            if (block == 0) {
                for (tk.key, 0..) |_, k| {
                    const dks: DesKeySchedule = DesKeySchedule.init(bytesToUint64(&tk.key[k]));
                    switch (k) {
                        0 => {
                            pt = bytesToUint64(buf[(block * 8)..((block * 8) + 8)]);
                            if (iv) |value| {
                                const xorValue: u64 = bytesToUint64(value);
                                pt ^= xorValue;
                            }
                            pt = des.encryptBlock(dks.subkeys, pt);
                        },
                        1 => {
                            pt = des.decryptBlock(dks.subkeys, bytesToUint64(self.cipher[k - 1][0..8]));
                        },
                        2 => {
                            pt = des.encryptBlock(dks.subkeys, bytesToUint64(self.cipher[k - 1][0..8]));
                        },
                        else => {
                            unreachable;
                        },
                    }
                    if (endian == .Little) {
                        pt = @byteSwap(pt);
                    }
                    std.mem.copy(u8, self.cipher[k][(block * 8)..((block * 8) + 8)], &@as([8]u8, @bitCast(pt)));
                }
            } else {
                for (tk.key, 0..) |_, k| {
                    const dks: DesKeySchedule = DesKeySchedule.init(bytesToUint64(&tk.key[k]));
                    switch (k) {
                        0 => {
                            pt = bytesToUint64(buf[(block * 8)..((block * 8) + 8)]);
                            if (iv) |_| {
                                pt ^= bytesToUint64(self.cipher[2][((block - 1) * 8)..(((block - 1) * 8) + 8)]);
                            }
                            pt = des.encryptBlock(dks.subkeys, pt);
                        },
                        1 => {
                            pt = des.decryptBlock(dks.subkeys, bytesToUint64(self.cipher[k - 1][(block * 8)..((block * 8) + 8)]));
                        },
                        2 => {
                            pt = des.encryptBlock(dks.subkeys, bytesToUint64(self.cipher[k - 1][(block * 8)..((block * 8) + 8)]));
                        },
                        else => {
                            unreachable;
                        },
                    }
                    if (endian == .Little) {
                        pt = @byteSwap(pt);
                    }
                    std.mem.copy(u8, self.cipher[k][(block * 8)..((block * 8) + 8)], &@as([8]u8, @bitCast(pt)));
                }
            }
        }
    }

    pub fn decrypt(self: *Self, tk: TripleDesKey, iv: ?[]const u8, buf: []const u8) void {
        var des = Des.init();
        const bufLen: usize = buf.len;
        self.blk_count = bufLen / 8;

        for (0..self.blk_count) |block| {
            var pt: u64 = undefined;
            if (self.blk_count == 1) {
                for (tk.key, 0..) |_, k| {
                    const dks: DesKeySchedule = DesKeySchedule.init(bytesToUint64(&tk.key[2 - k]));
                    switch (k) {
                        0 => {
                            pt = des.decryptBlock(dks.subkeys, bytesToUint64(buf[0..8]));
                        },
                        1 => {
                            pt = des.encryptBlock(dks.subkeys, bytesToUint64(self.cipher[k - 1][0..8]));
                        },
                        2 => {
                            pt = des.decryptBlock(dks.subkeys, bytesToUint64(self.cipher[k - 1][0..8]));
                            if (iv) |value| {
                                const xorValue: u64 = bytesToUint64(value);
                                pt ^= xorValue;
                            }
                        },
                        else => {
                            unreachable;
                        },
                    }
                    if (endian == .Little) {
                        pt = @byteSwap(pt);
                    }
                    std.mem.copy(u8, self.cipher[k][(block * 8)..((block * 8) + 8)], &@as([8]u8, @bitCast(pt)));
                }
            } else {
                for (tk.key, 0..) |_, k| {
                    const dks: DesKeySchedule = DesKeySchedule.init(bytesToUint64(&tk.key[2 - k]));
                    switch (k) {
                        0 => {
                            pt = des.decryptBlock(dks.subkeys, bytesToUint64(buf[((self.blk_count - (block + 1)) * 8)..(((self.blk_count - (block + 1)) * 8) + 8)]));
                        },
                        1 => {
                            pt = des.encryptBlock(dks.subkeys, bytesToUint64(self.cipher[k - 1][((self.blk_count - (block + 1)) * 8)..(((self.blk_count - (block + 1)) * 8) + 8)]));
                        },
                        2 => {
                            pt = des.decryptBlock(dks.subkeys, bytesToUint64(self.cipher[k - 1][((self.blk_count - (block + 1)) * 8)..(((self.blk_count - (block + 1)) * 8) + 8)]));
                            if (self.blk_count - (block + 1) > 0) {
                                if (iv) |_| {
                                    pt ^= bytesToUint64(buf[(((self.blk_count - (block + 1)) - 1) * 8)..((((self.blk_count - (block + 1)) - 1) * 8) + 8)]);
                                }
                            } else {
                                if (iv) |value| {
                                    const xorValue: u64 = bytesToUint64(value);
                                    pt ^= xorValue;
                                }
                            }
                        },
                        else => {
                            unreachable;
                        },
                    }
                    if (endian == .Little) {
                        pt = @byteSwap(pt);
                    }
                    std.mem.copy(u8, self.cipher[k][((self.blk_count - (block + 1)) * 8)..(((self.blk_count - (block + 1)) * 8) + 8)], &@as([8]u8, @bitCast(pt)));
                }
            }
        }
    }
};

pub const TripleDesKey = struct {
    const Self = @This();
    key: [3][8]u8,

    pub fn initFromHex(msg: []const u8) Self {
        var self: Self = undefined;
        var cBuf: [24]u8 = undefined;
        const cipher = fmt.hexToBytes(&cBuf, msg) catch unreachable;
        self.key[0] = cipher[0..8].*;
        self.key[1] = cipher[8..16].*;
        self.key[2] = cipher[16..24].*;
        return self;
    }
};

fn bytesToUint64(buf: []const u8) u64 {
    switch (endian) {
        .Big => {
            return @as(u64, @bitCast(buf[0..8].*));
        },
        .Little => {
            return @byteSwap(@as(u64, @bitCast(buf[0..8].*)));
        },
    }
}

fn permute(entropy: []const u8, state: u64, state_len: u8) u64 {
    var result: u64 = 0;
    for (0..@as(usize, entropy.len)) |i| {
        const num: u6 = @as(u6, @truncate(state_len - entropy[i]));
        result = (result << 1) | (state >> num & 1);
    }
    return result;
}
