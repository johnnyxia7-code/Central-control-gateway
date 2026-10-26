#include "key_store.hpp"
#include "atomic_file.hpp"
#include <charconv>
#include <filesystem>
#include <set>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace ccg::platform {

namespace {

using StoredKey = keym::KeyManager::StoredKey;

int hexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parseHex(const std::string& hex, std::uint8_t* out, std::size_t n) {
    if (hex.size() != 2 * n) return false;
    for (std::size_t i = 0; i < n; ++i) {
        const int hi = hexDigit(hex[2 * i]);
        const int lo = hexDigit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

}  // namespace

std::optional<keym::KeyManager::Snapshot> loadKeyStore(const std::string& path) {
    std::error_code ec;
    const auto status = std::filesystem::status(path, ec);
    if (ec == std::errc::no_such_file_or_directory || status.type() == std::filesystem::file_type::not_found)
        return std::nullopt;
    if (ec || !std::filesystem::is_regular_file(status) || std::filesystem::file_size(path) > 65536)
        throw std::runtime_error("invalid key store file " + path);
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot read key store " + path);
    keym::KeyManager::Snapshot snapshot;
    std::set<std::pair<unsigned, std::string>> seen;
    bool versioned = false, ended = false, any = false;
    std::string line;
    const auto invalid = [&]() { throw std::runtime_error("malformed or incomplete key store " + path); };
    while (std::getline(in, line)) {
        line = line.substr(0, line.find('#'));
        std::istringstream is(line);
        std::string state;
        if (!(is >> state)) continue;
        if (ended) invalid();
        const auto number = [&](int base = 10) {
            std::string token;
            std::uint32_t value = 0;
            if (!(is >> token)) invalid();
            const auto r = std::from_chars(token.data(), token.data() + token.size(), value, base);
            if (r.ec != std::errc{} || r.ptr != token.data() + token.size()) invalid();
            return value;
        };
        const auto endLine = [&]() { std::string extra; if (is >> extra) invalid(); };
        if (state == "version") {
            if (any || versioned || number() != 2) invalid();
            versioned = true; endLine(); continue;
        }
        if (state == "end") { if (!versioned) invalid(); ended = true; endLine(); continue; }
        any = true;
        const auto slot = number(), counter = number();
        if (slot > 0xF || counter > keym::she::kMaxCounter || !seen.emplace(slot, state).second) invalid();
        if (state == "counter") {
            snapshot.updateCounters.emplace(static_cast<std::uint8_t>(slot), counter);
            endLine(); continue;
        }
        StoredKey k;
        const auto flags = number(16);
        std::string hex;
        if (!(is >> hex) || flags > 0x1F || !parseHex(hex, k.key.data(), 16)) invalid();
        if (state == "active") k.state = StoredKey::State::Active;
        else if (state == "pending") k.state = StoredKey::State::Pending;
        else if (state == "previous") {
            k.state = StoredKey::State::Previous;
            k.remaining = std::chrono::milliseconds(number());
        } else invalid();
        endLine();
        k.slot = static_cast<std::uint8_t>(slot); k.counter = counter; k.flags = static_cast<std::uint8_t>(flags);
        snapshot.keys.push_back(k);
    }
    if (!in.eof() || !any || (versioned && !ended)) invalid();
    for (const auto& k : snapshot.keys) {
        if (versioned && (!snapshot.updateCounters.count(k.slot) || snapshot.updateCounters.at(k.slot) < k.counter))
            invalid();
    }
    return snapshot;
}

bool saveKeyStore(const std::string& path, const keym::KeyManager::Snapshot& snapshot) {
    std::ostringstream os;
    os << "# ccg key store - SECRET KEY MATERIAL (bench HSM emulation)\n";
    os << "version 2\n";
    for (const auto& [slot, counter] : snapshot.updateCounters) os << "counter " << int{slot} << " " << counter << "\n";
    // Also support callers constructing a legacy snapshot in memory.
    std::map<std::uint8_t, std::uint32_t> inferred;
    for (const auto& k : snapshot.keys) inferred[k.slot] = std::max(inferred[k.slot], k.counter);
    for (const auto& [slot, counter] : inferred)
        if (!snapshot.updateCounters.count(slot)) os << "counter " << int{slot} << " " << counter << "\n";
    for (const auto& k : snapshot.keys) {
        const char* state = k.state == StoredKey::State::Active    ? "active"
                            : k.state == StoredKey::State::Pending ? "pending"
                                                                   : "previous";
        char hex[33];
        for (std::size_t i = 0; i < 16; ++i) std::snprintf(hex + 2 * i, 3, "%02x", k.key[i]);
        char flags[3];
        std::snprintf(flags, sizeof flags, "%02x", k.flags);
        os << state << " " << int{k.slot} << " " << k.counter << " " << flags << " " << hex;
        if (k.state == StoredKey::State::Previous) os << " " << k.remaining.count();
        os << "\n";
    }
    os << "end\n";
    return atomicPrivateFile(path, os.str());
}

FileWatcher::FileWatcher(std::string path) : path_(std::move(path)) { changed(); }

bool FileWatcher::changed() {
    struct stat st {};
    Signature now;
    if (::stat(path_.c_str(), &st) == 0) {
        now = {true, static_cast<std::uint64_t>(st.st_ino), static_cast<std::int64_t>(st.st_size),
               static_cast<std::int64_t>(st.st_mtim.tv_sec), static_cast<std::int64_t>(st.st_mtim.tv_nsec)};
    }
    if (now == signature_) return false;
    signature_ = now;
    return true;
}

}  // namespace ccg::platform
