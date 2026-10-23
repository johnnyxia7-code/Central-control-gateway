#include "key_store.hpp"

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
    std::ifstream in(path);
    if (!in) return std::nullopt;
    keym::KeyManager::Snapshot snapshot;
    std::string line;
    for (int number = 1; std::getline(in, line); ++number) {
        line = line.substr(0, line.find('#'));
        std::istringstream is(line);
        std::string state;
        if (!(is >> state)) continue;
        StoredKey k;
        unsigned slot = 0;
        unsigned long counter = 0;
        unsigned flags = 0;
        std::string hex;
        bool ok = static_cast<bool>(is >> slot >> counter >> std::hex >> flags >> std::dec >> hex) && slot <= 0xF &&
                  counter <= keym::she::kMaxCounter && flags <= 0x1F && parseHex(hex, k.key.data(), 16);
        if (state == "active") {
            k.state = StoredKey::State::Active;
        } else if (state == "pending") {
            k.state = StoredKey::State::Pending;
        } else if (state == "previous") {
            long long remaining = 0;
            ok = ok && static_cast<bool>(is >> remaining) && remaining >= 0;
            k.state = StoredKey::State::Previous;
            k.remaining = std::chrono::milliseconds(remaining);
        } else {
            ok = false;
        }
        if (!ok) throw std::runtime_error(path + ":" + std::to_string(number) + ": malformed key store entry");
        k.slot = static_cast<std::uint8_t>(slot);
        k.counter = static_cast<std::uint32_t>(counter);
        k.flags = static_cast<std::uint8_t>(flags);
        snapshot.keys.push_back(k);
    }
    return snapshot;
}

bool saveKeyStore(const std::string& path, const keym::KeyManager::Snapshot& snapshot) {
    std::ostringstream os;
    os << "# ccg key store - SECRET KEY MATERIAL (bench HSM emulation)\n";
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
    const std::string data = os.str();
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::write(fd, data.data() + done, data.size() - done);
        if (n <= 0) break;
        done += static_cast<std::size_t>(n);
    }
    const bool ok = done == data.size() && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok || std::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
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
