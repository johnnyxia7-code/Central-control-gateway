#include "secoc_storage.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>

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
    if (!in) return std::nullopt;
    secoc::FreshnessManager::Snapshot snapshot;
    std::string kind;
    unsigned long id = 0;
    unsigned long long value = 0;
    while (in >> kind) {
        if (kind == "trip") {
            if (!(in >> value)) break;
            snapshot.trip = value;
            continue;
        }
        if (!(in >> id >> value)) break;
        auto& map = kind == "tx" ? snapshot.tx : snapshot.rx;
        map[static_cast<std::uint16_t>(id)] = value;
    }
    return snapshot;
}

bool saveFreshness(const std::string& path, const secoc::FreshnessManager::Snapshot& snapshot) {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) return false;
        out << "trip " << snapshot.trip << "\n";
        for (const auto& [id, v] : snapshot.tx) out << "tx " << id << " " << v << "\n";
        for (const auto& [id, v] : snapshot.rx) out << "rx " << id << " " << v << "\n";
        out.flush();
        if (!out) return false;
    }
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

}  // namespace ccg::platform
