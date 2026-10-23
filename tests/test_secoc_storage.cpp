#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include "secoc_storage.hpp"
#include "test_framework.hpp"

using namespace ccg;

namespace {

std::string tempPath(const std::string& name) {
    return (std::filesystem::temp_directory_path() / ("ccg_test_" + name)).string();
}

}  // namespace

TEST_CASE("secoc storage: key file parsing") {
    const auto path = tempPath("keys");
    {
        std::ofstream out(path);
        out << "# SecOC keys\n"
            << "K_RFC = 2b7e151628aed2a6abf7158809cf4f3c   # RFC 4493 key\n\n"
            << "K_TWO=000102030405060708090A0B0C0D0E0F\n";
    }
    secoc::SoftwareCryptoService crypto;
    CHECK_EQ(platform::loadKeyFile(path, crypto), 2U);
    CHECK(crypto.hasKey("K_RFC"));
    crypto::Block mac;
    REQUIRE(crypto.generateMac("K_RFC", nullptr, 0, mac));
    CHECK_EQ(mac[0], 0xBB);  // RFC 4493 example 1
    CHECK_EQ(mac[15], 0x46);

    {
        std::ofstream out(path);
        out << "K_BAD=1234\n";
    }
    bool thrown = false;
    try {
        platform::loadKeyFile(path, crypto);
    } catch (const std::runtime_error& e) {
        thrown = std::string(e.what()).find(":1: expected KEY_ID") != std::string::npos;
    }
    CHECK(thrown);
    std::remove(path.c_str());
}

TEST_CASE("secoc storage: freshness counters survive a restart") {
    const auto path = tempPath("fv");
    std::remove(path.c_str());
    CHECK(!platform::loadFreshness(path).has_value());

    secoc::FreshnessManager before;
    for (int i = 0; i < 5; ++i) before.nextTx(0x01B0, 64);
    before.acceptRx(0x1003, 77);
    REQUIRE(platform::saveFreshness(path, before.snapshot()));

    const auto loaded = platform::loadFreshness(path);
    REQUIRE(loaded.has_value());
    secoc::FreshnessManager after;
    after.restore(*loaded, 1000);
    CHECK_EQ(*after.nextTx(0x01B0, 64), 1006U);
    CHECK_EQ(after.latestRx(0x1003), 77U);
    std::remove(path.c_str());
}
