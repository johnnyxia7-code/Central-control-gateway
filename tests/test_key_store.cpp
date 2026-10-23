#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <string>

#include "key_store.hpp"
#include "test_framework.hpp"
#include "vehicle_key_slots.hpp"

using namespace ccg;
using namespace std::chrono_literals;

namespace {

std::string tempPath(const char* name) {
    return "/tmp/ccg_test_" + std::to_string(::getpid()) + "_" + name;
}

}  // namespace

TEST_CASE("key store: round trip keeps every key state; file is private") {
    const auto path = tempPath("keys");
    keym::KeyManager km(config::makeVehicleKeySlots());
    const keym::TimePoint now = keym::TimePoint{} + 50s;
    config::provisionDemoKeyStore(km, now);
    keym::she::Flags f;
    f.keyUsage = true;
    const auto& cfg = km.config();
    auto load = [&](std::uint8_t slot, std::uint8_t seed, std::uint32_t counter) {
        crypto::Block k{};
        k.fill(seed);
        return km.loadKey(keym::she::buildUpdate(cfg.uid, slot, keym::she::kMasterEcuKey, config::demoMasterEcuKey(), k,
                                                 counter, f),
                          now);
    };
    REQUIRE(load(config::keyslot::kVcuGw, 0x11, 2).error == keym::she::ErrorCode::NoError);
    km.activatePending(now);
    REQUIRE(load(config::keyslot::kGwChs, 0x22, 3).error == keym::she::ErrorCode::NoError);

    const auto snap = km.snapshot(now + 1min);
    REQUIRE(platform::saveKeyStore(path, snap));
    struct stat st {};
    REQUIRE(::stat(path.c_str(), &st) == 0);
    CHECK_EQ(st.st_mode & 0777, 0600u);

    const auto loaded = platform::loadKeyStore(path);
    REQUIRE(loaded.has_value());
    REQUIRE(loaded->keys.size() == snap.keys.size());
    for (std::size_t i = 0; i < snap.keys.size(); ++i) {
        const auto& a = snap.keys[i];
        const auto& b = loaded->keys[i];
        CHECK(a.slot == b.slot && a.state == b.state && a.key == b.key && a.counter == b.counter &&
              a.flags == b.flags && a.remaining == b.remaining);
    }
    CHECK(snap.keys.size() == 9u);  // 7 active + 1 previous + 1 pending
    std::remove(path.c_str());
}

TEST_CASE("key store: missing file, malformed entries and change detection") {
    const auto path = tempPath("keys_bad");
    std::remove(path.c_str());
    CHECK(!platform::loadKeyStore(path).has_value());
    platform::FileWatcher watcher(path);
    CHECK(!watcher.changed());

    {
        std::ofstream out(path);
        out << "# comment\nactive 6 1 02 000102030405060708090a0b0c0d0e0f\n";
    }
    CHECK(watcher.changed());
    CHECK(!watcher.changed());
    CHECK_EQ(platform::loadKeyStore(path)->keys.size(), 1u);

    for (const char* bad : {"active 6 1 02 0001", "pending 6 x 02 000102030405060708090a0b0c0d0e0f",
                            "previous 6 1 02 000102030405060708090a0b0c0d0e0f", "stale 6 1 02 000102030405060708090a0b0c0d0e0f",
                            "active 6 1 20 000102030405060708090a0b0c0d0e0f"}) {
        {
            std::ofstream out(path);
            out << bad << "\n";
        }
        bool threw = false;
        try {
            platform::loadKeyStore(path);
        } catch (const std::runtime_error&) {
            threw = true;
        }
        CHECK(threw);
    }
    std::remove(path.c_str());
    CHECK(watcher.changed());
}
