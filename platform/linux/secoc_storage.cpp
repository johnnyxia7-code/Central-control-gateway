#include "secoc_storage.hpp"
#include "atomic_file.hpp"

#include <cstdio>
#include <cerrno>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <fcntl.h>
#include <unistd.h>

namespace ccg::platform {

namespace {

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r");
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1);
}

int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

std::size_t loadKeyFile(const std::string& path, secoc::SoftwareCryptoService& crypto) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open key file " + path);
    std::string line;
    std::size_t count = 0;
    for (int number = 1; std::getline(in, line); ++number) {
        line = trim(line.substr(0, line.find('#')));
        if (line.empty()) continue;
        const auto eq = line.find('=');
        const std::string id = eq == std::string::npos ? "" : trim(line.substr(0, eq));
        const std::string hex = eq == std::string::npos ? "" : trim(line.substr(eq + 1));
        crypto::Block key{};
        bool ok = !id.empty() && hex.size() == 32;
        for (std::size_t i = 0; ok && i < 16; ++i) {
            const int hi = hexDigit(hex[2 * i]);
            const int lo = hexDigit(hex[2 * i + 1]);
            ok = hi >= 0 && lo >= 0;
            key[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        }
        if (!ok) {
            throw std::runtime_error(path + ":" + std::to_string(number) +
                                     ": expected KEY_ID=<32 hex digits>");
        }
        crypto.setKey(id, key);
        ++count;
    }
    return count;
}

std::optional<secoc::FreshnessManager::Snapshot> loadFreshness(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        if (std::filesystem::exists(path)) throw std::runtime_error("cannot read freshness store " + path);
        return std::nullopt;
    }
    secoc::FreshnessManager::Snapshot snapshot;
    std::string kind;
    const auto readNumber = [&]() {
        std::string token;
        std::uint64_t number = 0;
        if (!(in >> token)) throw std::runtime_error("incomplete freshness store " + path);
        const auto parsed = std::from_chars(token.data(), token.data() + token.size(), number);
        if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size()) {
            throw std::runtime_error("invalid freshness counter in " + path);
        }
        return number;
    };
    bool haveTrip = false;
    while (in >> kind) {
        if (kind == "trip") {
            if (haveTrip) throw std::runtime_error("duplicate trip counter in " + path);
            snapshot.trip = readNumber();
            haveTrip = true;
            continue;
        }
        if (kind != "tx" && kind != "rx") {
            throw std::runtime_error("invalid freshness store " + path);
        }
        const auto id = readNumber();
        const auto value = readNumber();
        if (id > 0xFFFF) throw std::runtime_error("invalid freshness data ID in " + path);
        auto& map = kind == "tx" ? snapshot.tx : snapshot.rx;
        if (!map.emplace(static_cast<std::uint16_t>(id), value).second) {
            throw std::runtime_error("duplicate freshness counter in " + path);
        }
    }
    if (!in.eof() || !haveTrip) throw std::runtime_error("incomplete freshness store " + path);
    return snapshot;
}

bool saveFreshness(const std::string& path, const secoc::FreshnessManager::Snapshot& snapshot) {
    std::ostringstream out;
    out << "trip " << snapshot.trip << "\n";
    for (const auto& [id, v] : snapshot.tx) out << "tx " << id << " " << v << "\n";
    for (const auto& [id, v] : snapshot.rx) out << "rx " << id << " " << v << "\n";
    return atomicPrivateFile(path, out.str());
}

}  // namespace ccg::platform
