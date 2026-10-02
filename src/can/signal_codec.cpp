#include "ccg/can/signal_codec.hpp"

#include <cmath>
#include <limits>

namespace ccg::can {

namespace {

std::int64_t signedMin(std::uint8_t length) {
    return length >= 64 ? std::numeric_limits<std::int64_t>::min()
                        : -(std::int64_t{1} << (length - 1));
}

std::int64_t signedMax(std::uint8_t length) {
    return length >= 64 ? std::numeric_limits<std::int64_t>::max()
                        : (std::int64_t{1} << (length - 1)) - 1;
}

}  // namespace

std::uint64_t rawMask(std::uint8_t length) {
    return length >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << length) - 1);
}

bool fitsInFrame(const SignalSpec& spec, std::size_t frameLength) {
    if (spec.length == 0 || spec.length > 64) {
        return false;
    }
    const std::size_t bitCount = frameLength * 8;
    bool fits = true;
    forEachBitMsbFirst(spec, [&](std::size_t pos) {
        if (pos >= bitCount) {
            fits = false;
        }
    });
    return fits;
}

std::uint64_t extractRaw(const std::uint8_t* data, const SignalSpec& spec) {
    std::uint64_t value = 0;
    forEachBitMsbFirst(spec, [&](std::size_t pos) {
        value = (value << 1) | ((data[pos / 8] >> (pos % 8)) & 0x1U);
    });
    return value;
}

void insertRaw(std::uint8_t* data, const SignalSpec& spec, std::uint64_t raw) {
    int shift = spec.length - 1;
    forEachBitMsbFirst(spec, [&](std::size_t pos) {
        const auto mask = static_cast<std::uint8_t>(1U << (pos % 8));
        if ((raw >> shift) & 0x1U) {
            data[pos / 8] = static_cast<std::uint8_t>(data[pos / 8] | mask);
        } else {
            data[pos / 8] = static_cast<std::uint8_t>(data[pos / 8] & ~mask);
        }
        --shift;
    });
}

std::int64_t signExtend(std::uint64_t raw, std::uint8_t length) {
    if (length >= 64) {
        return static_cast<std::int64_t>(raw);
    }
    raw &= rawMask(length);
    const std::uint64_t signBit = std::uint64_t{1} << (length - 1);
    if (raw & signBit) {
        raw |= ~rawMask(length);
    }
    return static_cast<std::int64_t>(raw);
}

double rawToNumber(const SignalSpec& spec, std::uint64_t raw) {
    return spec.isSigned ? static_cast<double>(signExtend(raw, spec.length))
                         : static_cast<double>(raw & rawMask(spec.length));
}

double rawToPhysical(const SignalSpec& spec, std::uint64_t raw) {
    return rawToNumber(spec, raw) * spec.factor + spec.offset;
}

std::uint64_t physicalToRaw(const SignalSpec& spec, double physical) {
    if (std::isnan(physical) || spec.factor == 0.0) {
        return spec.initRaw;
    }
    const double scaled = std::round((physical - spec.offset) / spec.factor);
    if (spec.isSigned) {
        const std::int64_t lo = signedMin(spec.length);
        const std::int64_t hi = signedMax(spec.length);
        std::int64_t v;
        if (scaled <= static_cast<double>(lo)) {
            v = lo;
        } else if (scaled >= static_cast<double>(hi)) {
            v = hi;
        } else {
            v = static_cast<std::int64_t>(scaled);
        }
        return static_cast<std::uint64_t>(v) & rawMask(spec.length);
    }
    const std::uint64_t hi = rawMask(spec.length);
    if (scaled <= 0.0) {
        return 0;
    }
    if (scaled >= static_cast<double>(hi)) {
        return hi;
    }
    return static_cast<std::uint64_t>(scaled);
}

std::optional<std::uint64_t> numberToRaw(const SignalSpec& spec, double number) {
    if (std::isnan(number) || std::trunc(number) != number) {
        return std::nullopt;
    }
    if (spec.isSigned) {
        if (number < static_cast<double>(signedMin(spec.length)) ||
            number > static_cast<double>(signedMax(spec.length))) {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(static_cast<std::int64_t>(number)) &
               rawMask(spec.length);
    }
    if (number < 0.0 || number > static_cast<double>(rawMask(spec.length))) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(number);
}

}  // namespace ccg::can
