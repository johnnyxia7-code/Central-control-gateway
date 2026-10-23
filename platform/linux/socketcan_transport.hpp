#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ccg/s2s/transport.hpp"

namespace ccg::platform {

// Linux SocketCAN (CAN_RAW) adapter, e.g. "can0" or "vcan0".
class SocketCanTransport final : public s2s::ICanTransmitter {
public:
    SocketCanTransport(const std::string& interfaceName, bool enableFd);
    ~SocketCanTransport() override;
    SocketCanTransport(const SocketCanTransport&) = delete;
    SocketCanTransport& operator=(const SocketCanTransport&) = delete;

    // Kernel side acceptance filter: only the S2S Rx identifiers reach user space.
    void setReceiveFilter(const std::vector<std::pair<std::uint32_t, bool>>& ids);

    bool transmit(const can::CanFrame& frame) override;

    // Non-blocking; nullopt when no frame is pending.
    std::optional<can::CanFrame> receive();

    int fd() const { return fd_; }

private:
    int fd_ = -1;
    bool fd_enabled_ = false;
};

}  // namespace ccg::platform
