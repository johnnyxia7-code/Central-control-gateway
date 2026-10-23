#include "ccg/crypto/aes_cmac.hpp"

#include <cstring>

namespace ccg::crypto {

namespace {

std::uint8_t xtime(std::uint8_t b) {
    return static_cast<std::uint8_t>((b << 1) ^ ((b & 0x80) ? 0x1B : 0x00));
}

std::uint8_t gfMul(std::uint8_t a, std::uint8_t b) {
    std::uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

std::uint8_t rotl8(std::uint8_t v, int n) {
    return static_cast<std::uint8_t>((v << n) | (v >> (8 - n)));
}

// S-box derived from its definition (multiplicative inverse in GF(2^8) followed
// by the affine transform), which avoids a hand-typed table.
const std::array<std::uint8_t, 256>& sbox() {
    static const std::array<std::uint8_t, 256> table = [] {
        std::array<std::uint8_t, 256> s{};
        for (int x = 0; x < 256; ++x) {
            std::uint8_t inv = 0;
            if (x != 0) {
                // x^254 = x^-1 in GF(2^8)
                std::uint8_t p = static_cast<std::uint8_t>(x);
                inv = 1;
                for (int e = 254; e > 0; e >>= 1) {
                    if (e & 1) inv = gfMul(inv, p);
                    p = gfMul(p, p);
                }
            }
            s[static_cast<std::size_t>(x)] = static_cast<std::uint8_t>(
                inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
        }
        return s;
    }();
    return table;
}

const std::array<std::uint8_t, 256>& inverseSbox() {
    static const std::array<std::uint8_t, 256> table = [] {
        std::array<std::uint8_t, 256> inv{};
        const auto& s = sbox();
        for (std::size_t x = 0; x < 256; ++x) inv[s[x]] = static_cast<std::uint8_t>(x);
        return inv;
    }();
    return table;
}

void shiftLeftOne(const Block& in, Block& out) {
    std::uint8_t carry = 0;
    for (int i = 15; i >= 0; --i) {
        const std::uint8_t b = in[static_cast<std::size_t>(i)];
        out[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>((b << 1) | carry);
        carry = b >> 7;
    }
}

}  // namespace

Aes128::Aes128(const Block& key) {
    const auto& s = sbox();
    std::memcpy(roundKeys_.data(), key.data(), 16);
    std::uint8_t rcon = 0x01;
    for (std::size_t i = 16; i < 176; i += 4) {
        std::uint8_t t[4] = {roundKeys_[i - 4], roundKeys_[i - 3], roundKeys_[i - 2], roundKeys_[i - 1]};
        if (i % 16 == 0) {
            const std::uint8_t first = t[0];
            t[0] = static_cast<std::uint8_t>(s[t[1]] ^ rcon);
            t[1] = s[t[2]];
            t[2] = s[t[3]];
            t[3] = s[first];
            rcon = xtime(rcon);
        }
        for (std::size_t j = 0; j < 4; ++j) {
            roundKeys_[i + j] = static_cast<std::uint8_t>(roundKeys_[i + j - 16] ^ t[j]);
        }
    }
}

Block Aes128::encrypt(const Block& plaintext) const {
    const auto& s = sbox();
    Block st = plaintext;
    auto addRoundKey = [&](std::size_t round) {
        for (std::size_t i = 0; i < 16; ++i) st[i] ^= roundKeys_[round * 16 + i];
    };
    auto subShift = [&] {
        Block t;
        for (std::size_t c = 0; c < 4; ++c) {
            for (std::size_t r = 0; r < 4; ++r) {
                t[r + 4 * c] = s[st[r + 4 * ((c + r) % 4)]];  // SubBytes + ShiftRows
            }
        }
        st = t;
    };
    addRoundKey(0);
    for (std::size_t round = 1; round <= 10; ++round) {
        subShift();
        if (round != 10) {
            for (std::size_t c = 0; c < 4; ++c) {  // MixColumns
                std::uint8_t* col = &st[4 * c];
                const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                const std::uint8_t t = static_cast<std::uint8_t>(a0 ^ a1 ^ a2 ^ a3);
                col[0] = static_cast<std::uint8_t>(a0 ^ t ^ xtime(static_cast<std::uint8_t>(a0 ^ a1)));
                col[1] = static_cast<std::uint8_t>(a1 ^ t ^ xtime(static_cast<std::uint8_t>(a1 ^ a2)));
                col[2] = static_cast<std::uint8_t>(a2 ^ t ^ xtime(static_cast<std::uint8_t>(a2 ^ a3)));
                col[3] = static_cast<std::uint8_t>(a3 ^ t ^ xtime(static_cast<std::uint8_t>(a3 ^ a0)));
            }
        }
        addRoundKey(round);
    }
    return st;
}

Block Aes128::decrypt(const Block& ciphertext) const {
    const auto& si = inverseSbox();
    Block st = ciphertext;
    auto addRoundKey = [&](std::size_t round) {
        for (std::size_t i = 0; i < 16; ++i) st[i] ^= roundKeys_[round * 16 + i];
    };
    auto invShiftSub = [&] {
        Block t;
        for (std::size_t c = 0; c < 4; ++c) {
            for (std::size_t r = 0; r < 4; ++r) {
                t[r + 4 * ((c + r) % 4)] = si[st[r + 4 * c]];  // InvShiftRows + InvSubBytes
            }
        }
        st = t;
    };
    addRoundKey(10);
    for (std::size_t round = 10; round-- > 0;) {
        invShiftSub();
        addRoundKey(round);
        if (round != 0) {
            for (std::size_t c = 0; c < 4; ++c) {  // InvMixColumns
                std::uint8_t* col = &st[4 * c];
                const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
                col[0] = static_cast<std::uint8_t>(gfMul(a0, 14) ^ gfMul(a1, 11) ^ gfMul(a2, 13) ^ gfMul(a3, 9));
                col[1] = static_cast<std::uint8_t>(gfMul(a0, 9) ^ gfMul(a1, 14) ^ gfMul(a2, 11) ^ gfMul(a3, 13));
                col[2] = static_cast<std::uint8_t>(gfMul(a0, 13) ^ gfMul(a1, 9) ^ gfMul(a2, 14) ^ gfMul(a3, 11));
                col[3] = static_cast<std::uint8_t>(gfMul(a0, 11) ^ gfMul(a1, 13) ^ gfMul(a2, 9) ^ gfMul(a3, 14));
            }
        }
    }
    return st;
}

Cmac::Cmac(const Block& key) : aes_(key) {
    const Block l = aes_.encrypt(Block{});
    shiftLeftOne(l, k1_);
    if (l[0] & 0x80) k1_[15] ^= 0x87;
    shiftLeftOne(k1_, k2_);
    if (k1_[0] & 0x80) k2_[15] ^= 0x87;
}

Block Cmac::compute(const std::uint8_t* data, std::size_t length) const {
    const std::size_t blocks = length == 0 ? 1 : (length + 15) / 16;
    const bool complete = length != 0 && length % 16 == 0;
    Block x{};
    for (std::size_t b = 0; b + 1 < blocks; ++b) {
        for (std::size_t i = 0; i < 16; ++i) x[i] ^= data[b * 16 + i];
        x = aes_.encrypt(x);
    }
    Block last{};
    const std::size_t offset = (blocks - 1) * 16;
    const std::size_t rest = length - offset;
    if (rest > 0) std::memcpy(last.data(), data + offset, rest);
    if (complete) {
        for (std::size_t i = 0; i < 16; ++i) last[i] ^= k1_[i];
    } else {
        last[rest] = 0x80;
        for (std::size_t i = 0; i < 16; ++i) last[i] ^= k2_[i];
    }
    for (std::size_t i = 0; i < 16; ++i) x[i] ^= last[i];
    return aes_.encrypt(x);
}

Block mpCompress(const std::uint8_t* data, std::size_t length) {
    Block out{};  // OUT_0 = 0
    for (std::size_t offset = 0; offset + 16 <= length; offset += 16) {
        Block x;
        std::memcpy(x.data(), data + offset, 16);
        const Block e = Aes128(out).encrypt(x);  // OUT_i = E(OUT_i-1, x_i) ^ x_i ^ OUT_i-1
        for (std::size_t i = 0; i < 16; ++i) out[i] = static_cast<std::uint8_t>(e[i] ^ x[i] ^ out[i]);
    }
    return out;
}

Block deriveKey(const Block& key, const Block& constant) {
    std::uint8_t data[32];
    std::memcpy(data, key.data(), 16);
    std::memcpy(data + 16, constant.data(), 16);
    return mpCompress(data, sizeof data);
}

bool equalBits(const std::uint8_t* a, const std::uint8_t* b, std::size_t bits) {
    std::uint8_t diff = 0;
    const std::size_t full = bits / 8;
    for (std::size_t i = 0; i < full; ++i) diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
    if (bits % 8) {
        const auto mask = static_cast<std::uint8_t>(0xFF << (8 - bits % 8));
        diff = static_cast<std::uint8_t>(diff | ((a[full] ^ b[full]) & mask));
    }
    return diff == 0;
}

}  // namespace ccg::crypto
