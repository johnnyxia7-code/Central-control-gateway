#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "ccg/keym/key_manager.hpp"

// File backed key store for the bench (stands in for the HSM's key NvM).
//
//   active   <slot> <counter> <flags> <key, 32 hex digits>
//   pending  <slot> <counter> <flags> <key>
//   previous <slot> <counter> <flags> <key> <remaining grace period in ms>
// New stores also contain "version 2", "counter <slot> <highest accepted>"
// and a terminal "end" marker. Legacy stores require controlled migration.
//
// The diagnostic gateway process owns the file (key updates over UDS); the
// Ethernet gateway process reloads it when it changes.
namespace ccg::platform {

// nullopt if the file does not exist. Throws on malformed content.
std::optional<keym::KeyManager::Snapshot> loadKeyStore(const std::string& path);

// Written to a unique mode-0600 file, synced, renamed, then directory synced.
bool saveKeyStore(const std::string& path, const keym::KeyManager::Snapshot& snapshot);

// Detects a replaced or modified file (inode, size, modification time).
class FileWatcher {
public:
    explicit FileWatcher(std::string path);
    bool changed();  // true once per change

private:
    struct Signature {
        bool exists = false;
        std::uint64_t inode = 0;
        std::int64_t size = 0;
        std::int64_t mtimeSec = 0;
        std::int64_t mtimeNsec = 0;
        bool operator==(const Signature& o) const {
            return exists == o.exists && inode == o.inode && size == o.size && mtimeSec == o.mtimeSec &&
                   mtimeNsec == o.mtimeNsec;
        }
    };
    std::string path_;
    Signature signature_;
};

}  // namespace ccg::platform
