#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ccg/can/can_frame.hpp"
#include "ccg/isotp/isotp_channel.hpp"

// Simulated UDS ECU behind ISO-TP, for tests and the bench simulation.
namespace ccg::sim {

using TimePoint = isotp::TimePoint;
using Milliseconds = std::chrono::milliseconds;

class UdsEcu {
public:
    struct Config {
        std::string name;
        std::uint32_t requestId = 0;    // physical request (gateway -> ECU)
        std::uint32_t responseId = 0;   // ECU -> gateway
        std::uint32_t functionalId = 0x7DF;
        bool fd = false;
        std::uint8_t blockSize = 0;     // our flow control towards the gateway
        std::uint8_t stMin = 0;
        std::size_t maxRxLength = 0xFFFF;
        std::string vin = "WCCG0HPC0RT000001";
        std::string partNumber;
    };

    // (delay, response) pairs; an empty list means no response.
    using Responses = std::vector<std::pair<Milliseconds, std::vector<std::uint8_t>>>;
    using Handler = std::function<Responses(const std::vector<std::uint8_t>& request, bool functional)>;

    UdsEcu(Config config, std::function<bool(const can::CanFrame&)> transmit);
    UdsEcu(const UdsEcu&) = delete;  // callbacks capture `this`
    UdsEcu& operator=(const UdsEcu&) = delete;

    void setHandler(Handler handler) { handler_ = std::move(handler); }
    void setSilent(bool silent) { silent_ = silent; }  // powered off: ignores the bus

    void onFrame(const can::CanFrame& frame, TimePoint now);
    void mainFunction(TimePoint now);

    const Config& config() const { return cfg_; }
    const std::vector<std::vector<std::uint8_t>>& requests() const { return requests_; }

    // Default behaviour: 0x10, 0x3E, 0x22 F187/F190, 0x31 with response pending,
    // 0x34/0x36/0x37 download, NRC 0x11 otherwise.
    Responses defaultHandler(const std::vector<std::uint8_t>& request, bool functional) const;

private:
    void onRequest(std::vector<std::uint8_t>&& request, bool functional, TimePoint now);

    Config cfg_;
    std::unique_ptr<isotp::Channel> tp_;
    Handler handler_;
    bool silent_ = false;
    std::vector<std::vector<std::uint8_t>> requests_;
    std::vector<std::pair<TimePoint, std::vector<std::uint8_t>>> scheduled_;
    TimePoint now_{};
};

}  // namespace ccg::sim
