#include "ccg/e2e/can_e2e.hpp"

#include "ccg/can/signal_codec.hpp"

namespace ccg::e2e {

namespace {

std::uint8_t crc8Update(std::uint8_t crc, std::uint8_t byte) {
    crc = static_cast<std::uint8_t>(crc ^ byte);
    for (int bit = 0; bit < 8; ++bit) {
        crc = (crc & 0x80U) ? static_cast<std::uint8_t>((crc << 1) ^ 0x1DU)
                            : static_cast<std::uint8_t>(crc << 1);
    }
    return crc;
}

can::SignalSpec counterSpec(const CanE2EConfig& cfg) {
    can::SignalSpec spec;
    spec.name = "E2E_Counter";
    spec.startBit = cfg.counterStartBit;
    spec.length = 4;
    spec.byteOrder = can::ByteOrder::Intel;
    return spec;
}

}  // namespace

std::uint8_t crc8SaeJ1850(const std::uint8_t* data, std::size_t length) {
    std::uint8_t crc = 0xFF;
    for (std::size_t i = 0; i < length; ++i) {
        crc = crc8Update(crc, data[i]);
    }
    return static_cast<std::uint8_t>(crc ^ 0xFFU);
}

std::uint8_t computeCrc(const CanE2EConfig& cfg, const std::uint8_t* data, std::size_t length) {
    std::uint8_t crc = 0xFF;
    crc = crc8Update(crc, static_cast<std::uint8_t>(cfg.dataId & 0xFFU));
    crc = crc8Update(crc, static_cast<std::uint8_t>(cfg.dataId >> 8));
    for (std::size_t i = 0; i < length; ++i) {
        if (i != cfg.crcByte) {
            crc = crc8Update(crc, data[i]);
        }
    }
    return static_cast<std::uint8_t>(crc ^ 0xFFU);
}

const char* toString(CheckStatus status) {
    switch (status) {
        case CheckStatus::Ok: return "OK";
        case CheckStatus::OkSomeLost: return "OK_SOME_LOST";
        case CheckStatus::Repeated: return "REPEATED";
        case CheckStatus::WrongSequence: return "WRONG_SEQUENCE";
        case CheckStatus::CrcError: return "CRC_ERROR";
    }
    return "UNKNOWN";
}

CheckStatus CanE2EReceiver::check(const std::uint8_t* data, std::size_t length) {
    if (cfg_.crcByte >= length || computeCrc(cfg_, data, length) != data[cfg_.crcByte]) {
        return CheckStatus::CrcError;
    }
    const auto counter = static_cast<std::uint8_t>(can::extractRaw(data, counterSpec(cfg_)));
    if (counter >= kCounterModulo) {
        initialized_ = false;
        return CheckStatus::WrongSequence;
    }
    if (!initialized_) {
        initialized_ = true;
        lastCounter_ = counter;
        return CheckStatus::Ok;
    }
    const auto delta =
        static_cast<std::uint8_t>((counter + kCounterModulo - lastCounter_) % kCounterModulo);
    if (delta == 0) {
        return CheckStatus::Repeated;
    }
    lastCounter_ = counter;  // resynchronise on a wrong sequence as well
    if (delta == 1) {
        return CheckStatus::Ok;
    }
    return delta <= cfg_.maxDeltaCounter ? CheckStatus::OkSomeLost : CheckStatus::WrongSequence;
}

void CanE2ESender::protect(std::uint8_t* data, std::size_t length) {
    counter_ = static_cast<std::uint8_t>((counter_ + 1) % kCounterModulo);
    can::insertRaw(data, counterSpec(cfg_), counter_);
    data[cfg_.crcByte] = computeCrc(cfg_, data, length);
}

}  // namespace ccg::e2e
