#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>

namespace ccg::platform {

// Keeps the vehicle network interface usable for SOME/IP (rtnetlink, CAP_NET_ADMIN):
//
//  - optionally the link up and an IPv4 address on it, for an interface that no
//    network manager owns (on Android: kept out of ConnectivityService);
//  - a multicast route (default 224.0.0.0/4) on the interface. vsomeip starts
//    SOME/IP-SD only once the kernel has a route covering the SD multicast
//    address on the interface that owns its unicast address (netlink_connector).
//    Linux distributions usually have one; Android does not (netd programs
//    per-network tables only for the networks ConnectivityService manages).
//
// Links going down flush routes, so supervise() re-applies everything on link,
// address and route changes.
class NetworkSetup {
public:
    enum class Result : std::uint8_t { Ok, NoDevice, LinkDown, Failed };

    explicit NetworkSetup(std::string interfaceName);

    // "192.168.10.30/24": bring the link up and add (or keep) this address.
    void setAddress(const std::string& cidr);
    // Multicast prefix routed to the interface, e.g. 224.0.0.0/4 or 224.244.224.245.
    void setMulticastRoute(const std::string& prefix = "224.0.0.0/4",
                           std::uint32_t table = 254 /* RT_TABLE_MAIN */);

    // One attempt; idempotent.
    Result apply();

    // Re-applies on every link / address / route change (and every `retryMs`
    // while not applied) until `running` is false.
    void supervise(const std::atomic<bool>& running, int retryMs = 1000);

    const std::string& interfaceName() const { return interface_; }
    std::string lastError() const { return lastError_; }
    unsigned applyCount() const { return applyCount_; }

private:
    struct Prefix {
        std::uint32_t address = 0;  // network byte order
        std::uint8_t length = 32;
    };
    static Prefix parsePrefix(const std::string& cidr);
    int request(void* message);  // 0 or errno

    std::string interface_;
    std::optional<Prefix> address_;
    std::optional<Prefix> route_;
    std::uint32_t table_ = 254;
    std::string lastError_;
    unsigned applyCount_ = 0;
};

const char* toString(NetworkSetup::Result result);

}  // namespace ccg::platform
