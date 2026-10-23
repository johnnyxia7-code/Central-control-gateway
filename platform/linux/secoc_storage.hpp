#pragma once

#include <optional>
#include <string>

#include "ccg/secoc/secoc.hpp"

// File based SecOC key provisioning and freshness persistence for bench use.
// In a vehicle the keys live in the HSM and the counters in secure NvM.
namespace ccg::platform {

// Lines "KEY_ID=<32 hex digits>", '#' starts a comment. Throws on malformed input.
// Returns the number of keys loaded.
std::size_t loadKeyFile(const std::string& path, secoc::SoftwareCryptoService& crypto);

// Lines "trip <counter>" (FV master) and "tx|rx <data id> <counter>".
// nullopt if the file does not exist.
std::optional<secoc::FreshnessManager::Snapshot> loadFreshness(const std::string& path);

// Written to "<path>.tmp" and renamed, so a power loss never leaves a torn file.
bool saveFreshness(const std::string& path, const secoc::FreshnessManager::Snapshot& snapshot);

}  // namespace ccg::platform
