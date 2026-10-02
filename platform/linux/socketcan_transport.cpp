#include "socketcan_transport.hpp"

#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <system_error>

namespace ccg::platform {

namespace {

[[noreturn]] void throwErrno(const char* what) {
    throw std::system_error(errno, std::generic_category(), what);
}

}  // namespace

SocketCanTransport::SocketCanTransport(const std::string& interfaceName, bool enableFd)
    : fd_enabled_(enableFd) {
    fd_ = ::socket(PF_CAN, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, CAN_RAW);
    if (fd_ < 0) {
        throwErrno("socket(PF_CAN)");
    }
    if (enableFd) {
        const int on = 1;
        if (::setsockopt(fd_, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &on, sizeof on) < 0) {
            ::close(fd_);
            throwErrno("setsockopt(CAN_RAW_FD_FRAMES)");
        }
    }
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
        ::close(fd_);
        throwErrno("ioctl(SIOCGIFINDEX)");
    }
    sockaddr_can addr{};
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        ::close(fd_);
        throwErrno("bind(AF_CAN)");
    }
}

SocketCanTransport::~SocketCanTransport() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

void SocketCanTransport::setReceiveFilter(
    const std::vector<std::pair<std::uint32_t, bool>>& ids) {
    std::vector<can_filter> filters;
    filters.reserve(ids.size());
    for (const auto& [id, extended] : ids) {
        can_filter f{};
        f.can_id = extended ? (id | CAN_EFF_FLAG) : id;
        f.can_mask = extended ? (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_EFF_MASK)
                              : (CAN_EFF_FLAG | CAN_RTR_FLAG | CAN_SFF_MASK);
        filters.push_back(f);
    }
    if (::setsockopt(fd_, SOL_CAN_RAW, CAN_RAW_FILTER, filters.data(),
                     static_cast<socklen_t>(filters.size() * sizeof(can_filter))) < 0) {
        throwErrno("setsockopt(CAN_RAW_FILTER)");
    }
}

bool SocketCanTransport::transmit(const can::CanFrame& frame) {
    const canid_t id = frame.extended ? (frame.id | CAN_EFF_FLAG) : frame.id;
    if (frame.fd) {
        if (!fd_enabled_) {
            return false;
        }
        canfd_frame raw{};
        raw.can_id = id;
        raw.len = frame.length;
        raw.flags = CANFD_BRS;
        std::memcpy(raw.data, frame.data.data(), frame.length);
        return ::write(fd_, &raw, CANFD_MTU) == static_cast<ssize_t>(CANFD_MTU);
    }
    can_frame raw{};
    raw.can_id = id;
    raw.len = frame.length;
    std::memcpy(raw.data, frame.data.data(), frame.length);
    return ::write(fd_, &raw, CAN_MTU) == static_cast<ssize_t>(CAN_MTU);
}

std::optional<can::CanFrame> SocketCanTransport::receive() {
    for (;;) {
        canfd_frame raw{};
        const ssize_t n = ::read(fd_, &raw, sizeof raw);
        if (n != static_cast<ssize_t>(CAN_MTU) && n != static_cast<ssize_t>(CANFD_MTU)) {
            return std::nullopt;  // EAGAIN or short read
        }
        if (raw.can_id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
            continue;  // error / remote frames are not S2S data
        }
        can::CanFrame frame;
        frame.extended = (raw.can_id & CAN_EFF_FLAG) != 0;
        frame.id = raw.can_id & (frame.extended ? CAN_EFF_MASK : CAN_SFF_MASK);
        frame.fd = n == static_cast<ssize_t>(CANFD_MTU);
        frame.length = raw.len;
        std::memcpy(frame.data.data(), raw.data, raw.len);
        return frame;
    }
}

}  // namespace ccg::platform
