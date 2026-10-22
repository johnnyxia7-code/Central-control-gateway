#include "network_setup.hpp"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>

namespace ccg::platform {

namespace {

struct Fd {
    int fd;
    explicit Fd(int f) : fd(f) {}
    ~Fd() {
        if (fd >= 0) ::close(fd);
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

struct Request {
    alignas(nlmsghdr) std::array<char, 256> buffer{};

    Request(unsigned short type, unsigned short flags, const void* body, std::size_t length) {
        auto* h = header();
        h->nlmsg_len = static_cast<__u32>(NLMSG_LENGTH(length));
        h->nlmsg_type = type;
        h->nlmsg_flags = static_cast<unsigned short>(NLM_F_REQUEST | NLM_F_ACK | flags);
        h->nlmsg_seq = 1;
        std::memcpy(NLMSG_DATA(h), body, length);
    }
    nlmsghdr* header() { return reinterpret_cast<nlmsghdr*>(buffer.data()); }
    void add(unsigned short type, const void* data, std::size_t length) {
        auto* h = header();
        const auto attrLength = RTA_LENGTH(length);
        if (NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(attrLength) > buffer.size()) {
            throw std::length_error("netlink message buffer too small");
        }
        auto* rta = reinterpret_cast<rtattr*>(buffer.data() + NLMSG_ALIGN(h->nlmsg_len));
        rta->rta_type = type;
        rta->rta_len = static_cast<unsigned short>(attrLength);
        std::memcpy(RTA_DATA(rta), data, length);
        h->nlmsg_len = static_cast<__u32>(NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(attrLength));
    }
};

}  // namespace

const char* toString(NetworkSetup::Result result) {
    switch (result) {
        case NetworkSetup::Result::Ok: return "ok";
        case NetworkSetup::Result::NoDevice: return "no such device";
        case NetworkSetup::Result::LinkDown: return "link down";
        case NetworkSetup::Result::Failed: return "failed";
    }
    return "?";
}

NetworkSetup::NetworkSetup(std::string interfaceName) : interface_(std::move(interfaceName)) {}

NetworkSetup::Prefix NetworkSetup::parsePrefix(const std::string& cidr) {
    const auto slash = cidr.find('/');
    in_addr addr{};
    if (::inet_pton(AF_INET, cidr.substr(0, slash).c_str(), &addr) != 1) {
        throw std::invalid_argument("invalid IPv4 address: " + cidr);
    }
    int length = 32;
    if (slash != std::string::npos) {
        const std::string len = cidr.substr(slash + 1);
        if (len.empty() || len.find_first_not_of("0123456789") != std::string::npos ||
            (length = std::stoi(len)) > 32) {
            throw std::invalid_argument("invalid prefix length: " + cidr);
        }
    }
    return Prefix{addr.s_addr, static_cast<std::uint8_t>(length)};
}

void NetworkSetup::setAddress(const std::string& cidr) {
    const auto p = parsePrefix(cidr);
    if (p.length == 0 || (ntohl(p.address) >> 28) == 0xE) {
        throw std::invalid_argument("not a unicast interface address: " + cidr);
    }
    address_ = p;
}

void NetworkSetup::setMulticastRoute(const std::string& prefix, std::uint32_t table) {
    const auto p = parsePrefix(prefix);
    if (p.length < 4 || (ntohl(p.address) >> 28) != 0xE) {
        throw std::invalid_argument("not an IPv4 multicast prefix: " + prefix);
    }
    route_ = p;
    table_ = table;
}

int NetworkSetup::request(void* message) {
    Fd sock(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (sock.fd < 0) return errno;
    auto* h = static_cast<nlmsghdr*>(message);
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (::sendto(sock.fd, h, h->nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel), sizeof kernel) < 0) {
        return errno;
    }
    alignas(nlmsghdr) std::array<char, 1024> reply{};
    pollfd p{sock.fd, POLLIN, 0};
    if (::poll(&p, 1, 1000) <= 0) return ETIMEDOUT;
    const auto n = ::recv(sock.fd, reply.data(), reply.size(), 0);
    if (n < static_cast<ssize_t>(NLMSG_LENGTH(sizeof(nlmsgerr)))) return EPROTO;
    const auto* ack = reinterpret_cast<const nlmsghdr*>(reply.data());
    if (ack->nlmsg_type != NLMSG_ERROR) return EPROTO;
    return -static_cast<const nlmsgerr*>(NLMSG_DATA(ack))->error;
}

NetworkSetup::Result NetworkSetup::apply() {
    ++applyCount_;
    const unsigned int ifIndex = ::if_nametoindex(interface_.c_str());
    if (ifIndex == 0) {
        lastError_ = interface_ + ": " + std::strerror(errno);
        return Result::NoDevice;
    }
    auto failed = [this](const char* what, int error) {
        lastError_ = std::string(what) + ": " + std::strerror(error);
        if (error == ENETDOWN) return Result::LinkDown;
        if (error == ENODEV) return Result::NoDevice;
        return Result::Failed;
    };

    if (address_) {
        ifinfomsg link{};
        link.ifi_family = AF_UNSPEC;
        link.ifi_index = static_cast<int>(ifIndex);
        link.ifi_flags = IFF_UP;
        link.ifi_change = IFF_UP;
        Request up(RTM_NEWLINK, 0, &link, sizeof link);
        if (const int e = request(up.header())) return failed("link up", e);

        ifaddrmsg ifa{};
        ifa.ifa_family = AF_INET;
        ifa.ifa_prefixlen = address_->length;
        ifa.ifa_scope = RT_SCOPE_UNIVERSE;
        ifa.ifa_index = ifIndex;
        Request addr(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, &ifa, sizeof ifa);
        addr.add(IFA_LOCAL, &address_->address, sizeof address_->address);
        addr.add(IFA_ADDRESS, &address_->address, sizeof address_->address);
        if (const int e = request(addr.header())) return failed("address", e);
    }

    if (route_) {
        rtmsg rt{};
        rt.rtm_family = AF_INET;
        rt.rtm_dst_len = route_->length;
        rt.rtm_table = static_cast<unsigned char>(table_ < 256 ? table_ : unsigned{RT_TABLE_UNSPEC});
        rt.rtm_protocol = RTPROT_STATIC;
        rt.rtm_scope = RT_SCOPE_LINK;
        rt.rtm_type = RTN_UNICAST;
        Request route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, &rt, sizeof rt);
        route.add(RTA_DST, &route_->address, sizeof route_->address);
        const std::uint32_t oif = ifIndex;
        route.add(RTA_OIF, &oif, sizeof oif);
        route.add(RTA_TABLE, &table_, sizeof table_);
        if (const int e = request(route.header())) return failed("multicast route", e);
    }
    lastError_.clear();
    return Result::Ok;
}

void NetworkSetup::supervise(const std::atomic<bool>& running, int retryMs) {
    Fd monitor(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE));
    if (monitor.fd >= 0) {
        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        local.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
        if (::bind(monitor.fd, reinterpret_cast<sockaddr*>(&local), sizeof local) < 0) {
            ::close(monitor.fd);
            monitor.fd = -1;  // fall back to polling
        }
    }

    using Clock = std::chrono::steady_clock;
    constexpr auto kMinInterval = std::chrono::milliseconds(200);  // at most 5 applies/s
    bool applied = apply() == Result::Ok;
    bool pending = false;
    auto lastApply = Clock::now();
    while (running) {
        const int timeout = pending ? 50 : (applied ? 500 : retryMs);
        if (monitor.fd >= 0) {
            pollfd p{monitor.fd, POLLIN, 0};
            if (::poll(&p, 1, timeout) > 0) {
                alignas(nlmsghdr) std::array<char, 8192> buffer{};
                ssize_t n = 0;
                while ((n = ::recv(monitor.fd, buffer.data(), buffer.size(), 0)) > 0) {
                    auto len = static_cast<unsigned int>(n);
                    for (auto* h = reinterpret_cast<nlmsghdr*>(buffer.data()); NLMSG_OK(h, len);
                         h = NLMSG_NEXT(h, len)) {
                        // Additions (incl. our own) do not need a re-apply; link
                        // changes and removals (down, flush, DHCP client) do.
                        pending = pending || h->nlmsg_type == RTM_NEWLINK ||
                                  h->nlmsg_type == RTM_DELLINK || h->nlmsg_type == RTM_DELADDR ||
                                  h->nlmsg_type == RTM_DELROUTE;
                    }
                }
            }
        } else {
            ::usleep(static_cast<useconds_t>(timeout) * 1000U);
            pending = true;
        }
        if ((pending || !applied) && Clock::now() - lastApply >= kMinInterval) {
            applied = apply() == Result::Ok;
            pending = false;
            lastApply = Clock::now();
        }
    }
}

}  // namespace ccg::platform
