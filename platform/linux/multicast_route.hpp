#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace ccg::platform {

// Keeps a multicast route (default 224.0.0.0/4) on the vehicle network interface.
//
// vsomeip starts SOME/IP-SD only once the kernel has a route covering the SD
// multicast address on the interface that owns the configured unicast address
// (netlink_connector). Linux distributions usually have one; Android does not:
// netd programs per-network tables only for the networks ConnectivityService
// manages, and the vehicle network is typically kept out of it. The route is
// also flushed whenever the link goes down, so it is re-installed on every
// link change. Requires CAP_NET_ADMIN.
class MulticastRoute {
public:
    enum class Result : std::uint8_t { Installed, NoDevice, LinkDown, Failed };

    MulticastRoute(std::string interfaceName, std::string prefix = "224.0.0.0/4",
                   std::uint32_t table = 254 /* RT_TABLE_MAIN */);

    // One attempt: add or replace the route. Idempotent.
    Result install();

    // Re-installs the route whenever links or routes change (and every
    // `retryMs` while it could not be installed) until `running` is false.
    void supervise(const std::atomic<bool>& running, int retryMs = 1000);

    const std::string& interfaceName() const { return interface_; }
    std::string lastError() const { return lastError_; }

private:
    std::string interface_;
    std::uint32_t destination_ = 0;  // network byte order
    std::uint8_t prefixLength_ = 4;
    std::uint32_t table_;
    std::string lastError_;
};

const char* toString(MulticastRoute::Result result);

}  // namespace ccg::platform
