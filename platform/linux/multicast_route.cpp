#include "multicast_route.hpp"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
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

void addAttribute(nlmsghdr* msg, std::size_t capacity, unsigned short type, const void* data,
                  std::size_t length) {
    const auto attrLength = RTA_LENGTH(length);
    if (NLMSG_ALIGN(msg->nlmsg_len) + RTA_ALIGN(attrLength) > capacity) {
        throw std::length_error("netlink message buffer too small");
    }
    auto* rta = reinterpret_cast<rtattr*>(reinterpret_cast<char*>(msg) + NLMSG_ALIGN(msg->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = static_cast<unsigned short>(attrLength);
    std::memcpy(RTA_DATA(rta), data, length);
    msg->nlmsg_len = static_cast<__u32>(NLMSG_ALIGN(msg->nlmsg_len) + RTA_ALIGN(attrLength));
}

}  // namespace

const char* toString(MulticastRoute::Result result) {
    switch (result) {
        case MulticastRoute::Result::Installed: return "installed";
        case MulticastRoute::Result::NoDevice: return "no such device";
        case MulticastRoute::Result::LinkDown: return "link down";
        case MulticastRoute::Result::Failed: return "failed";
    }
    return "?";
}

MulticastRoute::MulticastRoute(std::string interfaceName, std::string prefix, std::uint32_t table)
    : interface_(std::move(interfaceName)), table_(table) {
    const auto slash = prefix.find('/');
    const std::string address = prefix.substr(0, slash);
    in_addr addr{};
    if (::inet_pton(AF_INET, address.c_str(), &addr) != 1) {
        throw std::invalid_argument("invalid IPv4 prefix: " + prefix);
    }
    const int length = slash == std::string::npos ? 32 : std::stoi(prefix.substr(slash + 1));
    if (length < 4 || length > 32 || (ntohl(addr.s_addr) >> 28) != 0xE) {
        throw std::invalid_argument("not an IPv4 multicast prefix: " + prefix);
    }
    destination_ = addr.s_addr;
    prefixLength_ = static_cast<std::uint8_t>(length);
}

MulticastRoute::Result MulticastRoute::install() {
    const unsigned int ifIndex = ::if_nametoindex(interface_.c_str());
    if (ifIndex == 0) {
        lastError_ = std::strerror(errno);
        return Result::NoDevice;
    }

    Fd sock(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
    if (sock.fd < 0) {
        lastError_ = std::string("socket(NETLINK_ROUTE): ") + std::strerror(errno);
        return Result::Failed;
    }

    alignas(nlmsghdr) std::array<char, 256> buffer{};
    auto* msg = reinterpret_cast<nlmsghdr*>(buffer.data());
    msg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    msg->nlmsg_type = RTM_NEWROUTE;
    msg->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    msg->nlmsg_seq = 1;
    auto* rt = static_cast<rtmsg*>(NLMSG_DATA(msg));
    rt->rtm_family = AF_INET;
    rt->rtm_dst_len = prefixLength_;
    rt->rtm_table = static_cast<unsigned char>(table_ < 256 ? table_ : unsigned{RT_TABLE_UNSPEC});
    rt->rtm_protocol = RTPROT_STATIC;
    rt->rtm_scope = RT_SCOPE_LINK;
    rt->rtm_type = RTN_UNICAST;
    addAttribute(msg, buffer.size(), RTA_DST, &destination_, sizeof destination_);
    const std::uint32_t oif = ifIndex;
    addAttribute(msg, buffer.size(), RTA_OIF, &oif, sizeof oif);
    addAttribute(msg, buffer.size(), RTA_TABLE, &table_, sizeof table_);

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    if (::sendto(sock.fd, msg, msg->nlmsg_len, 0, reinterpret_cast<sockaddr*>(&kernel),
                 sizeof kernel) < 0) {
        lastError_ = std::string("sendto(RTM_NEWROUTE): ") + std::strerror(errno);
        return Result::Failed;
    }

    alignas(nlmsghdr) std::array<char, 1024> reply{};
    pollfd p{sock.fd, POLLIN, 0};
    if (::poll(&p, 1, 1000) <= 0) {
        lastError_ = "no netlink acknowledgement";
        return Result::Failed;
    }
    const auto n = ::recv(sock.fd, reply.data(), reply.size(), 0);
    if (n < static_cast<ssize_t>(NLMSG_LENGTH(sizeof(nlmsgerr)))) {
        lastError_ = "short netlink acknowledgement";
        return Result::Failed;
    }
    const auto* ack = reinterpret_cast<const nlmsghdr*>(reply.data());
    if (ack->nlmsg_type != NLMSG_ERROR) {
        lastError_ = "unexpected netlink reply";
        return Result::Failed;
    }
    const int error = -static_cast<const nlmsgerr*>(NLMSG_DATA(ack))->error;
    if (error == 0) {
        lastError_.clear();
        return Result::Installed;
    }
    lastError_ = std::strerror(error);
    if (error == ENETDOWN) return Result::LinkDown;
    if (error == ENODEV) return Result::NoDevice;
    return Result::Failed;
}

void MulticastRoute::supervise(const std::atomic<bool>& running, int retryMs) {
    Fd monitor(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE));
    if (monitor.fd >= 0) {
        sockaddr_nl local{};
        local.nl_family = AF_NETLINK;
        local.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE;
        if (::bind(monitor.fd, reinterpret_cast<sockaddr*>(&local), sizeof local) < 0) {
            ::close(monitor.fd);
            monitor.fd = -1;  // fall back to polling
        }
    }

    bool installed = install() == Result::Installed;
    while (running) {
        bool changed = false;
        if (monitor.fd >= 0) {
            pollfd p{monitor.fd, POLLIN, 0};
            if (::poll(&p, 1, installed ? 500 : retryMs) > 0) {
                alignas(nlmsghdr) std::array<char, 8192> buffer{};
                ssize_t n = 0;
                while ((n = ::recv(monitor.fd, buffer.data(), buffer.size(), 0)) > 0) {
                    auto len = static_cast<unsigned int>(n);
                    for (auto* h = reinterpret_cast<nlmsghdr*>(buffer.data()); NLMSG_OK(h, len);
                         h = NLMSG_NEXT(h, len)) {
                        // Our own RTM_NEWROUTE must not trigger another install.
                        changed = changed || h->nlmsg_type == RTM_NEWLINK ||
                                  h->nlmsg_type == RTM_DELROUTE;
                    }
                }
            }
        } else {
            ::usleep(static_cast<useconds_t>(retryMs) * 1000U);
            changed = true;
        }
        // Link up / down and route deletions (e.g. a flush); install() is
        // idempotent (NLM_F_REPLACE), so simply re-apply.
        if (changed || !installed) {
            installed = install() == Result::Installed;
        }
    }
}

}  // namespace ccg::platform
