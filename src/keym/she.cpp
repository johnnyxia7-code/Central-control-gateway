#include "ccg/keym/she.hpp"

#include <cstring>

namespace ccg::keym::she {

namespace {

using crypto::Block;

Block xorBlock(const Block& a, const std::uint8_t* b) {
    Block r;
    for (std::size_t i = 0; i < 16; ++i) r[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    return r;
}

std::array<std::uint8_t, 16> makeM1(const Uid& uid, std::uint8_t slot, std::uint8_t authSlot) {
    std::array<std::uint8_t, 16> m1{};
    std::memcpy(m1.data(), uid.data(), uid.size());
    m1[15] = static_cast<std::uint8_t>(((slot & 0x0F) << 4) | (authSlot & 0x0F));
    return m1;
}

}  // namespace

const char* toString(ErrorCode code) {
    switch (code) {
        case ErrorCode::NoError: return "ERC_NO_ERROR";
        case ErrorCode::SequenceError: return "ERC_SEQUENCE_ERROR";
        case ErrorCode::KeyNotAvailable: return "ERC_KEY_NOT_AVAILABLE";
        case ErrorCode::KeyInvalid: return "ERC_KEY_INVALID";
        case ErrorCode::KeyEmpty: return "ERC_KEY_EMPTY";
        case ErrorCode::KeyWriteProtected: return "ERC_KEY_WRITE_PROTECTED";
        case ErrorCode::KeyUpdateError: return "ERC_KEY_UPDATE_ERROR";
        case ErrorCode::Busy: return "ERC_BUSY";
        case ErrorCode::GeneralError: return "ERC_GENERAL_ERROR";
    }
    return "UNKNOWN";
}

std::uint8_t Flags::encode() const {
    return static_cast<std::uint8_t>((writeProtection << 4) | (bootProtection << 3) |
                                     (debuggerProtection << 2) | (keyUsage << 1) | wildcard);
}

Flags Flags::decode(std::uint8_t fid) {
    Flags f;
    f.writeProtection = fid & 0x10;
    f.bootProtection = fid & 0x08;
    f.debuggerProtection = fid & 0x04;
    f.keyUsage = fid & 0x02;
    f.wildcard = fid & 0x01;
    return f;
}

const Block& keyUpdateEncC() {
    static const Block c = {0x01, 0x01, 0x53, 0x48, 0x45, 0x00, 0x80, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
    return c;
}

const Block& keyUpdateMacC() {
    static const Block c = {0x01, 0x02, 0x53, 0x48, 0x45, 0x00, 0x80, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0};
    return c;
}

UpdateRequest buildUpdate(const Uid& uid, std::uint8_t slot, std::uint8_t authSlot, const Block& authKey,
                          const Block& newKey, std::uint32_t counter, const Flags& flags) {
    UpdateRequest r;
    r.m1 = makeM1(uid, slot, authSlot);

    // Counter (28) | FID (5) | 0 (95) as a 128-bit big-endian block.
    Block first{};
    const std::uint32_t head = ((counter & kMaxCounter) << 4) | (flags.encode() >> 1);
    first[0] = static_cast<std::uint8_t>(head >> 24);
    first[1] = static_cast<std::uint8_t>(head >> 16);
    first[2] = static_cast<std::uint8_t>(head >> 8);
    first[3] = static_cast<std::uint8_t>(head);
    first[4] = static_cast<std::uint8_t>((flags.encode() & 0x01) << 7);

    const crypto::Aes128 k1(crypto::deriveKey(authKey, keyUpdateEncC()));
    const Block c1 = k1.encrypt(first);  // CBC, IV = 0
    const Block c2 = k1.encrypt(xorBlock(c1, newKey.data()));
    std::memcpy(r.m2.data(), c1.data(), 16);
    std::memcpy(r.m2.data() + 16, c2.data(), 16);

    const crypto::Cmac k2(crypto::deriveKey(authKey, keyUpdateMacC()));
    std::uint8_t m1m2[48];
    std::memcpy(m1m2, r.m1.data(), 16);
    std::memcpy(m1m2 + 16, r.m2.data(), 32);
    const Block m3 = k2.compute(m1m2, sizeof m1m2);
    std::memcpy(r.m3.data(), m3.data(), 16);
    return r;
}

UpdateProof buildProof(const Uid& uid, std::uint8_t slot, std::uint8_t authSlot, const Block& newKey,
                       std::uint32_t counter) {
    UpdateProof p;
    const auto m1 = makeM1(uid, slot, authSlot);
    Block block{};
    const std::uint32_t head = ((counter & kMaxCounter) << 4) | 0x8;  // counter | 1 | 0...
    block[0] = static_cast<std::uint8_t>(head >> 24);
    block[1] = static_cast<std::uint8_t>(head >> 16);
    block[2] = static_cast<std::uint8_t>(head >> 8);
    block[3] = static_cast<std::uint8_t>(head);
    const Block enc = crypto::Aes128(crypto::deriveKey(newKey, keyUpdateEncC())).encrypt(block);
    std::memcpy(p.m4.data(), m1.data(), 16);
    std::memcpy(p.m4.data() + 16, enc.data(), 16);
    const Block m5 = crypto::Cmac(crypto::deriveKey(newKey, keyUpdateMacC())).compute(p.m4.data(), p.m4.size());
    std::memcpy(p.m5.data(), m5.data(), 16);
    return p;
}

bool verifyM3(const UpdateRequest& r, const Block& authKey) {
    const crypto::Cmac k2(crypto::deriveKey(authKey, keyUpdateMacC()));
    std::uint8_t m1m2[48];
    std::memcpy(m1m2, r.m1.data(), 16);
    std::memcpy(m1m2 + 16, r.m2.data(), 32);
    const Block expected = k2.compute(m1m2, sizeof m1m2);
    return crypto::equalBits(expected.data(), r.m3.data(), 128);
}

UpdatePayload decryptM2(const UpdateRequest& r, const Block& authKey) {
    const crypto::Aes128 k1(crypto::deriveKey(authKey, keyUpdateEncC()));
    Block c1;
    Block c2;
    std::memcpy(c1.data(), r.m2.data(), 16);
    std::memcpy(c2.data(), r.m2.data() + 16, 16);
    const Block first = k1.decrypt(c1);  // IV = 0
    UpdatePayload p;
    p.key = xorBlock(k1.decrypt(c2), c1.data());
    const std::uint32_t head = (static_cast<std::uint32_t>(first[0]) << 24) |
                               (static_cast<std::uint32_t>(first[1]) << 16) |
                               (static_cast<std::uint32_t>(first[2]) << 8) | first[3];
    p.counter = head >> 4;
    p.flags = Flags::decode(static_cast<std::uint8_t>(((head & 0x0F) << 1) | (first[4] >> 7)));
    return p;
}

Uid uidOf(const UpdateRequest& r) {
    Uid uid;
    std::memcpy(uid.data(), r.m1.data(), uid.size());
    return uid;
}

}  // namespace ccg::keym::she
