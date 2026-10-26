#include "ccg/isotp/isotp_channel.hpp"

#include <algorithm>
#include <cstring>

namespace ccg::isotp {

namespace {

// Consecutive frames sent back-to-back (STmin 0) per call before yielding to
// the next mainFunction(); keeps one long transfer from monopolising the bus.
constexpr int kMaxBurst = 64;

std::size_t roundUpFdLength(std::size_t length) {
    static constexpr std::size_t kLengths[] = {8, 12, 16, 20, 24, 32, 48, 64};
    for (const auto l : kLengths) {
        if (length <= l) return l;
    }
    return 64;
}

can::CanFrame buildFrame(std::uint32_t id, bool extended, bool fd, bool pad, std::uint8_t padding,
                         const std::uint8_t* data, std::size_t length) {
    can::CanFrame f;
    f.id = id;
    f.extended = extended;
    f.fd = fd;
    std::size_t frameLength = length;
    if (pad && frameLength < 8) frameLength = 8;
    if (fd && frameLength > 8) frameLength = roundUpFdLength(frameLength);
    std::memset(f.data.data(), padding, frameLength);
    std::memcpy(f.data.data(), data, length);
    f.length = static_cast<std::uint8_t>(frameLength);
    return f;
}

}  // namespace

const char* toString(Result result) {
    switch (result) {
        case Result::Ok: return "OK";
        case Result::TimeoutAs: return "N_TIMEOUT_A";
        case Result::TimeoutBs: return "N_TIMEOUT_Bs";
        case Result::TimeoutCr: return "N_TIMEOUT_Cr";
        case Result::WrongSequence: return "N_WRONG_SN";
        case Result::InvalidFlowStatus: return "N_INVALID_FS";
        case Result::WaitLimit: return "N_WFT_OVRN";
        case Result::Overflow: return "N_BUFFER_OVFLW";
        case Result::UnexpectedPdu: return "N_UNEXP_PDU";
    }
    return "UNKNOWN";
}

std::size_t maxSingleFrameLength(bool fd) { return fd ? 62 : 7; }

std::optional<can::CanFrame> makeSingleFrame(std::uint32_t id, bool extended, bool fd,
                                             std::uint8_t padding, const std::uint8_t* data,
                                             std::size_t length) {
    if (length == 0 || length > maxSingleFrameLength(fd)) {
        return std::nullopt;
    }
    std::uint8_t buf[64];
    std::size_t n;
    if (length <= 7) {
        buf[0] = static_cast<std::uint8_t>(length);
        std::memcpy(buf + 1, data, length);
        n = length + 1;
    } else {
        buf[0] = 0x00;
        buf[1] = static_cast<std::uint8_t>(length);
        std::memcpy(buf + 2, data, length);
        n = length + 2;
    }
    return buildFrame(id, extended, fd, true, padding, buf, n);
}

Milliseconds decodeStMin(std::uint8_t raw) {
    if (raw <= 0x7F) return Milliseconds(raw);
    if (raw >= 0xF1 && raw <= 0xF9) return Milliseconds(1);  // 100..900 us
    return Milliseconds(0x7F);                              // reserved values
}

Channel::Channel(Config config, Callbacks callbacks)
    : cfg_(config), cb_(std::move(callbacks)), txDl_(config.fd ? 64 : 8) {}

can::CanFrame Channel::makeFrame(const std::uint8_t* data, std::size_t length) const {
    return buildFrame(cfg_.txId, cfg_.extended, cfg_.fd, cfg_.padFrames, cfg_.padding, data, length);
}

// ---------------------------------------------------------------------------
// Transmitter
// ---------------------------------------------------------------------------

bool Channel::transmit(std::vector<std::uint8_t> data, TimePoint now) {
    if (txPhase_ != TxPhase::Idle || data.empty() || data.size() > 0xFFFFFFFFULL) {
        return false;
    }
    txData_ = std::move(data);
    txOffset_ = 0;
    asDeadline_ = now + cfg_.nAs;

    std::uint8_t buf[64];
    const std::size_t size = txData_.size();
    if (size <= maxSingleFrameLength(cfg_.fd)) {
        txFrame_ = *makeSingleFrame(cfg_.txId, cfg_.extended, cfg_.fd, cfg_.padding, txData_.data(),
                                    size);
        if (!cfg_.padFrames && size <= 7) {
            txFrame_.length = static_cast<std::uint8_t>(size + 1);
        }
        txOffset_ = size;
        txPhase_ = TxPhase::SendSf;
    } else {
        std::size_t pci;
        if (size <= 4095) {
            buf[0] = static_cast<std::uint8_t>(0x10 | (size >> 8));
            buf[1] = static_cast<std::uint8_t>(size & 0xFF);
            pci = 2;
        } else {
            buf[0] = 0x10;
            buf[1] = 0x00;
            buf[2] = static_cast<std::uint8_t>(size >> 24);
            buf[3] = static_cast<std::uint8_t>(size >> 16);
            buf[4] = static_cast<std::uint8_t>(size >> 8);
            buf[5] = static_cast<std::uint8_t>(size);
            pci = 6;
        }
        const std::size_t n = std::min(txDl_ - pci, size);
        std::memcpy(buf + pci, txData_.data(), n);
        txFrame_ = makeFrame(buf, pci + n);
        txOffset_ = n;
        txSn_ = 1;
        txPhase_ = TxPhase::SendFf;
    }
    pumpTx(now);
    return true;
}

void Channel::prepareConsecutiveFrame(TimePoint now) {
    std::uint8_t buf[64];
    buf[0] = static_cast<std::uint8_t>(0x20 | txSn_);
    const std::size_t n = std::min(txDl_ - 1, txData_.size() - txOffset_);
    std::memcpy(buf + 1, txData_.data() + txOffset_, n);
    txFrame_ = makeFrame(buf, n + 1);
    txOffset_ += n;
    txSn_ = static_cast<std::uint8_t>((txSn_ + 1) & 0x0F);
    txPhase_ = TxPhase::SendCf;
    asDeadline_ = now + cfg_.nAs;
}

void Channel::pumpTx(TimePoint now) {
    int burst = 0;
    for (;;) {
        switch (txPhase_) {
            case TxPhase::Idle:
                return;
            case TxPhase::WaitFc:
                if (now >= bsDeadline_) finishTx(Result::TimeoutBs);
                return;
            case TxPhase::WaitStMin:
                if (now < nextCf_) return;
                prepareConsecutiveFrame(now);
                continue;
            case TxPhase::SendSf:
            case TxPhase::SendFf:
            case TxPhase::SendCf:
                break;
        }

        if (!cb_.transmit(txFrame_)) {
            if (now >= asDeadline_) finishTx(Result::TimeoutAs);
            return;  // retried by mainFunction()
        }
        if (txPhase_ == TxPhase::SendSf) {
            finishTx(Result::Ok);
            return;
        }
        if (txPhase_ == TxPhase::SendFf) {
            txPhase_ = TxPhase::WaitFc;
            bsDeadline_ = now + cfg_.nBs;
            wftCount_ = 0;
            return;
        }
        // consecutive frame sent
        if (txOffset_ >= txData_.size()) {
            finishTx(Result::Ok);
            return;
        }
        if (blockSize_ != 0 && --blockRemaining_ == 0) {
            txPhase_ = TxPhase::WaitFc;
            bsDeadline_ = now + cfg_.nBs;
            wftCount_ = 0;
            return;
        }
        if (stMin_.count() > 0) {
            txPhase_ = TxPhase::WaitStMin;
            nextCf_ = now + stMin_;
            return;
        }
        prepareConsecutiveFrame(now);
        if (++burst >= kMaxBurst) return;
    }
}

void Channel::finishTx(Result result) {
    txPhase_ = TxPhase::Idle;
    txData_.clear();
    if (cb_.txDone) cb_.txDone(result);
}

void Channel::onFlowControl(const can::CanFrame& frame, TimePoint now) {
    if (txPhase_ != TxPhase::WaitFc || frame.length < 3) {
        return;  // unexpected FC is ignored
    }
    switch (frame.data[0] & 0x0F) {
        case 0x0:  // continue to send
            blockSize_ = frame.data[1];
            blockRemaining_ = blockSize_;
            stMin_ = decodeStMin(frame.data[2]);
            prepareConsecutiveFrame(now);
            pumpTx(now);
            break;
        case 0x1:  // wait
            if (++wftCount_ > cfg_.maxWft) {
                finishTx(Result::WaitLimit);
            } else {
                bsDeadline_ = now + cfg_.nBs;
            }
            break;
        case 0x2:  // overflow
            finishTx(Result::Overflow);
            break;
        default:
            finishTx(Result::InvalidFlowStatus);
            break;
    }
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

void Channel::onFrame(const can::CanFrame& frame, TimePoint now) {
    if (frame.length == 0) {
        return;
    }
    switch (frame.data[0] >> 4) {
        case 0x0: onSingleFrame(frame); break;
        case 0x1: onFirstFrame(frame, now); break;
        case 0x2: onConsecutiveFrame(frame, now); break;
        case 0x3: onFlowControl(frame, now); break;
        default: break;  // unknown PCI: ignored
    }
}

void Channel::onSingleFrame(const can::CanFrame& frame) {
    const auto* d = frame.data.data();
    std::size_t length;
    std::size_t offset;
    if ((d[0] & 0x0F) != 0) {
        length = d[0] & 0x0F;
        offset = 1;
        if (frame.length > 8) return;  // CAN FD SF > 8 bytes must use the escape
    } else {
        if (frame.length <= 8 || frame.length < 2) return;  // SF_DL 0 only valid as FD escape
        length = d[1];
        offset = 2;
        if (length < 8) return;
    }
    if (offset + length > frame.length) {
        return;
    }
    if (rxActive_) {
        abortRx(Result::UnexpectedPdu);
    }
    if (cb_.rxDone) cb_.rxDone(std::vector<std::uint8_t>(d + offset, d + offset + length));
}

void Channel::onFirstFrame(const can::CanFrame& frame, TimePoint now) {
    if (frame.length < 8) {
        return;
    }
    const auto* d = frame.data.data();
    std::size_t length = (static_cast<std::size_t>(d[0] & 0x0F) << 8) | d[1];
    std::size_t offset = 2;
    if (length == 0) {
        length = (static_cast<std::size_t>(d[2]) << 24) | (static_cast<std::size_t>(d[3]) << 16) |
                 (static_cast<std::size_t>(d[4]) << 8) | d[5];
        offset = 6;
        if (length <= 4095) return;
    } else if (length < 8) {
        return;
    }
    if (rxActive_) {
        abortRx(Result::UnexpectedPdu);
    }
    if (length > cfg_.maxRxLength) {
        sendFlowControl(0x2, now);
        if (cb_.rxError) cb_.rxError(Result::Overflow);
        return;
    }
    const std::size_t n = std::min<std::size_t>(frame.length - offset, length);
    rxData_.assign(d + offset, d + offset + n);
    rxExpected_ = length;
    rxSn_ = 1;
    rxActive_ = true;
    rxBlockRemaining_ = cfg_.blockSize;
    crDeadline_ = now + cfg_.nCr;
    sendFlowControl(0x0, now);
}

void Channel::onConsecutiveFrame(const can::CanFrame& frame, TimePoint now) {
    if (!rxActive_) {
        return;
    }
    if ((frame.data[0] & 0x0F) != rxSn_) {
        abortRx(Result::WrongSequence);
        return;
    }
    const std::size_t n = std::min<std::size_t>(frame.length - 1, rxExpected_ - rxData_.size());
    rxData_.insert(rxData_.end(), frame.data.data() + 1, frame.data.data() + 1 + n);
    rxSn_ = static_cast<std::uint8_t>((rxSn_ + 1) & 0x0F);
    if (rxData_.size() >= rxExpected_) {
        rxActive_ = false;
        auto data = std::move(rxData_);
        rxData_.clear();
        if (cb_.rxDone) cb_.rxDone(std::move(data));
        return;
    }
    crDeadline_ = now + cfg_.nCr;
    if (cfg_.blockSize != 0 && --rxBlockRemaining_ == 0) {
        rxBlockRemaining_ = cfg_.blockSize;
        sendFlowControl(0x0, now);
    }
}

void Channel::sendFlowControl(std::uint8_t flowStatus, TimePoint now) {
    const std::uint8_t buf[3] = {static_cast<std::uint8_t>(0x30 | flowStatus), cfg_.blockSize,
                                 cfg_.stMin};
    const auto frame = makeFrame(buf, sizeof buf);
    if (!cb_.transmit(frame)) {
        pendingFc_ = frame;
        arDeadline_ = now + cfg_.nAs;
    }
}

void Channel::abortRx(Result result) {
    rxActive_ = false;
    rxData_.clear();
    pendingFc_.reset();
    if (cb_.rxError) cb_.rxError(result);
}

void Channel::mainFunction(TimePoint now) {
    if (pendingFc_) {
        if (cb_.transmit(*pendingFc_)) {
            pendingFc_.reset();
        } else if (now >= arDeadline_) {
            pendingFc_.reset();
            if (rxActive_) abortRx(Result::TimeoutAs);
        }
    }
    if (rxActive_ && now >= crDeadline_) {
        abortRx(Result::TimeoutCr);
    }
    pumpTx(now);
}

}  // namespace ccg::isotp
