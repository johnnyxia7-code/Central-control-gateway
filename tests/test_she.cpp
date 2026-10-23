#include <string>
#include <vector>

#include "ccg/crypto/aes_cmac.hpp"
#include "ccg/keym/she.hpp"
#include "test_framework.hpp"

using namespace ccg;
using namespace ccg::keym;

namespace {

std::vector<std::uint8_t> fromHex(const std::string& hex) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> bytes(const std::string& hex) {
    std::array<std::uint8_t, N> b{};
    const auto v = fromHex(hex);
    std::copy(v.begin(), v.end(), b.begin());
    return b;
}

crypto::Block block(const std::string& hex) { return bytes<16>(hex); }

// SHE specification example (also used by NXP/Infineon application notes).
const she::Uid kSpecUid = bytes<15>("000000000000000000000000000001");
const crypto::Block kSpecAuthKey = block("000102030405060708090a0b0c0d0e0f");
const crypto::Block kSpecNewKey = block("0f0e0d0c0b0a09080706050403020100");

}  // namespace

TEST_CASE("aes-128: FIPS-197 appendix C.1 decryption") {
    const crypto::Aes128 aes(block("000102030405060708090a0b0c0d0e0f"));
    CHECK(aes.decrypt(block("69c4e0d86a7b0430d8cdb78070b4c55a")) == block("00112233445566778899aabbccddeeff"));
}

TEST_CASE("aes-128: decrypt inverts encrypt") {
    const crypto::Aes128 aes(block("2b7e151628aed2a6abf7158809cf4f3c"));
    crypto::Block p{};
    for (int round = 0; round < 50; ++round) {
        for (std::size_t i = 0; i < 16; ++i) p[i] = static_cast<std::uint8_t>(p[i] * 13 + i + round);
        CHECK(aes.decrypt(aes.encrypt(p)) == p);
    }
}

TEST_CASE("she: KDF (AES Miyaguchi-Preneel) known answers") {
    CHECK(crypto::deriveKey(kSpecAuthKey, she::keyUpdateEncC()) == block("118a46447a770d87828a69c222e2d17e"));
    CHECK(crypto::deriveKey(kSpecAuthKey, she::keyUpdateMacC()) == block("2ebb2a3da62dbd64b18ba6493e9fbe22"));
}

TEST_CASE("she: memory update protocol M1..M5 matches the specification example") {
    const auto r = she::buildUpdate(kSpecUid, she::kKey1, she::kMasterEcuKey, kSpecAuthKey, kSpecNewKey, 1,
                                    she::Flags{});
    CHECK(r.m1 == bytes<16>("00000000000000000000000000000141"));
    CHECK(r.m2 == bytes<32>("2b111e2d93f486566bcbba1d7f7a9797c94643b050fc5d4d7de14cff682203c3"));
    CHECK(r.m3 == bytes<16>("b9d745e5ace7d41860bc63c2b9f5bb46"));

    const auto p = she::buildProof(kSpecUid, she::kKey1, she::kMasterEcuKey, kSpecNewKey, 1);
    CHECK(p.m4 == bytes<32>("00000000000000000000000000000141b472e8d8727d70d57295e74849a27917"));
    CHECK(p.m5 == bytes<16>("820d8d95dc11b4668878160cb2a4e23e"));
}

TEST_CASE("she: flags and large counter are placed as in M2 (cross-checked with OpenSSL)") {
    // KEY_3 of the gateway, KEY_USAGE + WILDCARD, counter 0x0ABCDEF.
    const auto uid = bytes<15>("000000000000004343470000000001");
    crypto::Block auth{};
    for (std::size_t i = 0; i < 16; ++i) auth[i] = static_cast<std::uint8_t>(0x4D * 31 + i * 7);
    const auto newKey = block("a1a2a3a4a5a6a7a8a9aaabacadaeafb0");
    she::Flags flags;
    flags.keyUsage = true;
    flags.wildcard = true;
    const auto r = she::buildUpdate(uid, 0x6, she::kMasterEcuKey, auth, newKey, 0x0ABCDEF, flags);
    CHECK(r.m1 == bytes<16>("00000000000000434347000000000161"));
    CHECK(r.m2 == bytes<32>("c5c796d001f3de44b45ed40c1a848436c5b2430a2d3be07eec514bb5046fb966"));
    CHECK(r.m3 == bytes<16>("6dda7c08eeb92b550603c60cabc8e78c"));
    const auto p = she::buildProof(uid, 0x6, she::kMasterEcuKey, newKey, 0x0ABCDEF);
    CHECK(p.m4 == bytes<32>("000000000000004343470000000001617b89a45f7c5661fccec17b4d2f3f4942"));
    CHECK(p.m5 == bytes<16>("ad9ae15b4cdecada153bd36f32d66d01"));

    // Device side
    CHECK(she::verifyM3(r, auth));
    const auto payload = she::decryptM2(r, auth);
    CHECK_EQ(payload.counter, 0x0ABCDEFu);
    CHECK(payload.flags == flags);
    CHECK(payload.key == newKey);
    CHECK(she::uidOf(r) == uid);
    CHECK_EQ(she::slotOf(r), 0x6);
    CHECK_EQ(she::authSlotOf(r), she::kMasterEcuKey);
}

TEST_CASE("she: M3 detects tampering and the wrong authorising key") {
    auto r = she::buildUpdate(kSpecUid, she::kKey1, she::kMasterEcuKey, kSpecAuthKey, kSpecNewKey, 7,
                              she::Flags{});
    CHECK(she::verifyM3(r, kSpecAuthKey));
    CHECK(!she::verifyM3(r, kSpecNewKey));
    auto tampered = r;
    tampered.m1[15] = 0x51;  // other slot
    CHECK(!she::verifyM3(tampered, kSpecAuthKey));
    tampered = r;
    tampered.m2[20] ^= 0x01;
    CHECK(!she::verifyM3(tampered, kSpecAuthKey));
}

TEST_CASE("she: flags encode to the 5-bit FID") {
    she::Flags f;
    CHECK_EQ(f.encode(), 0x00);
    f.writeProtection = true;
    CHECK_EQ(f.encode(), 0x10);
    f = she::Flags::decode(0x1F);
    CHECK(f.writeProtection && f.bootProtection && f.debuggerProtection && f.keyUsage && f.wildcard);
    CHECK_EQ(she::Flags::decode(0x02).encode(), 0x02);
}
