#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"

namespace ccg::can {

// Checks the signal layout of one PDU of `length` bytes: every signal fits, no two
// signals (including the E2E CRC byte and alive counter) share a bit, names are
// unique, factor != 0 and min <= max. Appends one line per problem, prefixed with
// `where`.
void checkSignalLayout(const std::string& where, std::size_t length,
                       const std::vector<SignalSpec>& signals,
                       const std::optional<e2e::CanE2EConfig>& e2e,
                       std::vector<std::string>& errors);

}  // namespace ccg::can
