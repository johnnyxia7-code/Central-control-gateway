#include "ccg/s2s/data_type.hpp"

#include <cmath>
#include <limits>

namespace ccg::s2s {

namespace {

template <typename T>
T saturate(double v) {
    if (std::isnan(v)) {
        return T{};
    }
    const double r = std::round(v);
    if (r <= static_cast<double>(std::numeric_limits<T>::min())) {
        return std::numeric_limits<T>::min();
    }
    if (r >= static_cast<double>(std::numeric_limits<T>::max())) {
        return std::numeric_limits<T>::max();
    }
    return static_cast<T>(r);
}

}  // namespace

const char* toString(DataType type) {
    switch (type) {
        case DataType::Bool: return "boolean";
        case DataType::UInt8: return "uint8";
        case DataType::UInt16: return "uint16";
        case DataType::UInt32: return "uint32";
        case DataType::Int8: return "sint8";
        case DataType::Int16: return "sint16";
        case DataType::Int32: return "sint32";
        case DataType::Float32: return "float32";
        case DataType::Float64: return "float64";
    }
    return "unknown";
}

std::size_t wireSize(DataType type) {
    switch (type) {
        case DataType::Bool:
        case DataType::UInt8:
        case DataType::Int8: return 1;
        case DataType::UInt16:
        case DataType::Int16: return 2;
        case DataType::UInt32:
        case DataType::Int32:
        case DataType::Float32: return 4;
        case DataType::Float64: return 8;
    }
    return 0;
}

void writeValue(someip::PayloadWriter& w, DataType type, double value) {
    switch (type) {
        case DataType::Bool: w.writeU8(value != 0.0 ? 1 : 0); break;
        case DataType::UInt8: w.writeU8(saturate<std::uint8_t>(value)); break;
        case DataType::UInt16: w.writeU16(saturate<std::uint16_t>(value)); break;
        case DataType::UInt32: w.writeU32(saturate<std::uint32_t>(value)); break;
        case DataType::Int8:
            w.writeU8(static_cast<std::uint8_t>(saturate<std::int8_t>(value)));
            break;
        case DataType::Int16:
            w.writeU16(static_cast<std::uint16_t>(saturate<std::int16_t>(value)));
            break;
        case DataType::Int32:
            w.writeU32(static_cast<std::uint32_t>(saturate<std::int32_t>(value)));
            break;
        case DataType::Float32: w.writeF32(static_cast<float>(value)); break;
        case DataType::Float64: w.writeF64(value); break;
    }
}

std::optional<double> readValue(someip::PayloadReader& r, DataType type) {
    switch (type) {
        case DataType::Bool: {
            std::uint8_t v;
            if (!r.readU8(v) || v > 1) return std::nullopt;
            return v;
        }
        case DataType::UInt8: {
            std::uint8_t v;
            if (!r.readU8(v)) return std::nullopt;
            return v;
        }
        case DataType::UInt16: {
            std::uint16_t v;
            if (!r.readU16(v)) return std::nullopt;
            return v;
        }
        case DataType::UInt32: {
            std::uint32_t v;
            if (!r.readU32(v)) return std::nullopt;
            return v;
        }
        case DataType::Int8: {
            std::uint8_t v;
            if (!r.readU8(v)) return std::nullopt;
            return static_cast<std::int8_t>(v);
        }
        case DataType::Int16: {
            std::uint16_t v;
            if (!r.readU16(v)) return std::nullopt;
            return static_cast<std::int16_t>(v);
        }
        case DataType::Int32: {
            std::uint32_t v;
            if (!r.readU32(v)) return std::nullopt;
            return static_cast<std::int32_t>(v);
        }
        case DataType::Float32: {
            float v;
            if (!r.readF32(v)) return std::nullopt;
            return static_cast<double>(v);
        }
        case DataType::Float64: {
            double v;
            if (!r.readF64(v)) return std::nullopt;
            return v;
        }
    }
    return std::nullopt;
}

}  // namespace ccg::s2s
