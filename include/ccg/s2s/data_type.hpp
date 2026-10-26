#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

#include "ccg/someip/someip_message.hpp"

namespace ccg::s2s {

// SOME/IP basic data types used for service elements / method arguments.
enum class DataType : std::uint8_t {
    Bool,
    UInt8,
    UInt16,
    UInt32,
    Int8,
    Int16,
    Int32,
    Float32,
    Float64,
};

const char* toString(DataType type);
std::size_t wireSize(DataType type);

// Serializes `value`, rounding and saturating to the integer range where needed.
void writeValue(someip::PayloadWriter& writer, DataType type, double value);

// Deserializes one value; nullopt if the payload is too short or malformed.
std::optional<double> readValue(someip::PayloadReader& reader, DataType type);

}  // namespace ccg::s2s
