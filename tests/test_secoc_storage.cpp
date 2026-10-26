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
    before.setStoredTrip(9);
    REQUIRE(platform::saveFreshness(path, before.snapshot()));

    const auto loaded = platform::loadFreshness(path);
    REQUIRE(loaded.has_value());
    secoc::FreshnessManager after;
    after.restore(*loaded, 1000);
    CHECK_EQ(*after.nextTx(0x01B0, 64), 1006U);
    CHECK_EQ(after.latestRx(0x1003), 77U);
    CHECK_EQ(after.storedTrip(), 9U);  // FV master trip counter
    std::remove(path.c_str());
}

TEST_CASE("secoc storage: durable counters are restored exactly without periodic saves") {
    const auto path = tempPath("fv_durable");
    std::remove(path.c_str());
    for (std::uint64_t cycle = 1; cycle <= 3; ++cycle) {
        secoc::FreshnessManager manager;
        if (const auto saved = platform::loadFreshness(path)) manager.restore(*saved);
        manager.setPersistence([&](const secoc::FreshnessManager::Snapshot& next) {
            if (!platform::saveFreshness(path, next)) throw std::runtime_error("save failed");
        });
        CHECK_EQ(*manager.nextTx(0x1003, 64), cycle);
        manager.acceptRx(0x1004, cycle);
        manager.setStoredTrip(cycle);
        const auto disk = platform::loadFreshness(path);
        REQUIRE(disk.has_value());
        CHECK_EQ(disk->tx.at(0x1003), cycle);
        CHECK_EQ(disk->rx.at(0x1004), cycle);
        CHECK_EQ(disk->trip, cycle);
        CHECK(!std::filesystem::exists(path + ".tmp"));
        // No shutdown save: simulate losing all process memory now.
    }
    std::remove(path.c_str());
}

TEST_CASE("secoc storage: corrupt or incomplete state is never treated as a new store") {
    const auto path = tempPath("fv_corrupt");
    for (const std::string data : {"", "tx 1 2\n", "trip", "trip 1\ntx 1", "trip 1\nrx 1 2\nrx 1 3",
                                   "trip 1\ntrip 2", "trip -1", "trip 1\ntx 65536 2", "trip 1\nunknown 2 3",
                                   "trip 18446744073709551616", "trip 1\nrx 1 -2", "trip 1\nrx 1 2junk"}) {
        { std::ofstream out(path); out << data; }
        bool rejected = false;
        try { (void)platform::loadFreshness(path); }
        catch (const std::runtime_error&) { rejected = true; }
        CHECK(rejected);
    }
    std::remove(path.c_str());
}

TEST_CASE("secoc storage: a failed replacement preserves the committed state") {
    const auto path = tempPath("fv_failure");
    secoc::FreshnessManager::Snapshot saved;
    saved.tx[1] = 7;
    REQUIRE(platform::saveFreshness(path, saved));
    // A directory at the temporary path makes open fail even when running as root.
    REQUIRE(std::filesystem::create_directory(path + ".tmp"));
    auto next = saved;
    next.tx[1] = 8;
    CHECK(!platform::saveFreshness(path, next));
    CHECK_EQ(platform::loadFreshness(path)->tx.at(1), 7u);
    std::filesystem::remove(path + ".tmp");
    std::remove(path.c_str());
}
