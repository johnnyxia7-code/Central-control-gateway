#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "ccg/can/can_frame.hpp"

// ISO 15765-2 (ISO-TP) transport protocol on CAN / CAN FD, normal addressing.
//
//   SF  0x0L data...                (classic, L = 1..7)
//   SF  0x00 L data...              (CAN FD escape, L = 8..62)
//   FF  0x1H LL data...             (12-bit length, 8..4095)
//   FF  0x10 0x00 LLLLLLLL data...  (escape, 32-bit length > 4095)
//   CF  0x2N data...                (sequence number N = 1, 2, ... 15, 0, 1 ...)
//   FC  0x3S BS STmin               (S: 0 = continue, 1 = wait, 2 = overflow)
namespace ccg::isotp {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Milliseconds = std::chrono::milliseconds;

enum class Result : std::uint8_t {
    Ok,
    TimeoutAs,       // a frame could not be handed to the CAN controller in time
    TimeoutBs,       // no flow control from the receiver
    TimeoutCr,       // no consecutive frame from the sender
    WrongSequence,   // consecutive frame with an unexpected sequence number
    InvalidFlowStatus,
    WaitLimit,       // more FC.WAIT frames than maxWft
    Overflow,        // receiver reported FC.OVFLW / message larger than our buffer
    UnexpectedPdu,   // new SF/FF while a reception was in progress
};

const char* toString(Result result);

struct Config {
    std::uint32_t txId = 0;
    std::uint32_t rxId = 0;
    bool extended = false;
    bool fd = false;              // TX_DL 64 (CAN FD) instead of 8
    bool padFrames = true;        // pad every frame to TX_DL (classic) / next valid FD length
    std::uint8_t padding = 0xCC;
    // Flow control we send when receiving.
    std::uint8_t blockSize = 0;   // 0 = no further FC
    std::uint8_t stMin = 0;       // raw STmin byte
    // Timing
    Milliseconds nAs{1000};
    Milliseconds nBs{1000};
    Milliseconds nCr{1000};
    std::uint8_t maxWft = 10;
    std::size_t maxRxLength = 4095;
};

struct Callbacks {
    std::function<bool(const can::CanFrame&)> transmit;      // false = controller busy, retry
    std::function<void(Result)> txDone;                      // Ok or the abort reason
    std::function<void(std::vector<std::uint8_t>&&)> rxDone; // complete message received
    std::function<void(Result)> rxError;                     // reception aborted
};

// Largest payload that fits into one single frame.
std::size_t maxSingleFrameLength(bool fd);

// Builds a single frame (used for functionally addressed requests, which must
// be single frames). nullopt if the data does not fit.
std::optional<can::CanFrame> makeSingleFrame(std::uint32_t id, bool extended, bool fd,
                                             std::uint8_t padding, const std::uint8_t* data,
                                             std::size_t length);

// STmin byte -> separation time (100..900 us rounded up to 1 ms, reserved -> 127 ms).
Milliseconds decodeStMin(std::uint8_t raw);

// One full-duplex ISO-TP connection (one tx ID, one rx ID).
// Single threaded: transmit(), onFrame() and mainFunction() come from one executor.
class Channel {
public:
    Channel(Config config, Callbacks callbacks);

    // Starts sending a message; false if a transmission is already running or the
    // message is empty / too long for ISO-TP.
    bool transmit(std::vector<std::uint8_t> data, TimePoint now);
    bool txBusy() const { return txPhase_ != TxPhase::Idle; }
    bool rxBusy() const { return rxActive_; }

    // Frames received with rxId (the caller filters by identifier).
    void onFrame(const can::CanFrame& frame, TimePoint now);

    // Timers, STmin pacing and retries. Call every 1 ms.
    void mainFunction(TimePoint now);

    const Config& config() const { return cfg_; }

private:
    enum class TxPhase : std::uint8_t { Idle, SendSf, SendFf, SendCf, WaitStMin, WaitFc };

    can::CanFrame makeFrame(const std::uint8_t* data, std::size_t length) const;
    void pumpTx(TimePoint now);
    void prepareConsecutiveFrame(TimePoint now);
    void finishTx(Result result);
    void onFlowControl(const can::CanFrame& frame, TimePoint now);
    void onSingleFrame(const can::CanFrame& frame);
    void onFirstFrame(const can::CanFrame& frame, TimePoint now);
    void onConsecutiveFrame(const can::CanFrame& frame, TimePoint now);
    void sendFlowControl(std::uint8_t flowStatus, TimePoint now);
    void abortRx(Result result);

    Config cfg_;
    Callbacks cb_;
    std::size_t txDl_;

    // transmitter
    TxPhase txPhase_ = TxPhase::Idle;
    std::vector<std::uint8_t> txData_;
    std::size_t txOffset_ = 0;
    std::uint8_t txSn_ = 0;
    can::CanFrame txFrame_;
    TimePoint asDeadline_{};
    TimePoint bsDeadline_{};
    TimePoint nextCf_{};
    std::uint8_t blockSize_ = 0;
    std::uint8_t blockRemaining_ = 0;
    Milliseconds stMin_{0};
    std::uint8_t wftCount_ = 0;

    // receiver
    bool rxActive_ = false;
    std::vector<std::uint8_t> rxData_;
    std::size_t rxExpected_ = 0;
    std::uint8_t rxSn_ = 0;
    std::uint8_t rxBlockRemaining_ = 0;
    TimePoint crDeadline_{};
    std::optional<can::CanFrame> pendingFc_;
    TimePoint arDeadline_{};
};

}  // namespace ccg::isotp
