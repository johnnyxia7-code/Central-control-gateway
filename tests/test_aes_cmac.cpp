#include <string>
#include <vector>

#include "ccg/crypto/aes_cmac.hpp"
#include "test_framework.hpp"

using namespace ccg::crypto;

namespace {

std::vector<std::uint8_t> fromHex(const std::string& hex) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

Block block(const std::string& hex) {
    Block b{};
    const auto v = fromHex(hex);
    std::copy(v.begin(), v.end(), b.begin());
    return b;
}

const Block kRfcKey = block("2b7e151628aed2a6abf7158809cf4f3c");
const std::string kRfcMessage =
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

}  // namespace

TEST_CASE("aes-128: FIPS-197 appendix C.1 known answer") {
    const Aes128 aes(block("000102030405060708090a0b0c0d0e0f"));
    CHECK(aes.encrypt(block("00112233445566778899aabbccddeeff")) ==
          block("69c4e0d86a7b0430d8cdb78070b4c55a"));
}

TEST_CASE("aes-128: SP 800-38A ECB known answer") {
    const Aes128 aes(kRfcKey);
    CHECK(aes.encrypt(block("6bc1bee22e409f96e93d7e117393172a")) ==
          block("3ad77bb40d7a3660a89ecaf32466ef97"));
    CHECK(aes.encrypt(Block{}) == block("7df76b0c1ab899b33e42f047b91b546f"));  // RFC 4493 L
}

TEST_CASE("aes-cmac: RFC 4493 examples 1-4") {
    const Cmac cmac(kRfcKey);
    const auto m = fromHex(kRfcMessage);
    CHECK(cmac.compute(m.data(), 0) == block("bb1d6929e95937287fa37d129b756746"));
    CHECK(cmac.compute(m.data(), 16) == block("070a16b46b4d4144f79bdd9dd04a287c"));
    CHECK(cmac.compute(m.data(), 40) == block("dfa66747de9ae63030ca32611497c827"));
    CHECK(cmac.compute(m.data(), 64) == block("51f0bebf7e3b9d92fc49741779363cfe"));
}

TEST_CASE("aes-cmac: truncated comparison") {
    const auto a = block("51f0bebf7e3b9d92fc49741779363cfe");
    auto b = a;
    b[3] ^= 0x01;  // differs in bit 31
    CHECK(equalBits(a.data(), b.data(), 24));
    CHECK(equalBits(a.data(), b.data(), 31));
    CHECK(!equalBits(a.data(), b.data(), 32));
    CHECK(!equalBits(a.data(), b.data(), 128));
}
