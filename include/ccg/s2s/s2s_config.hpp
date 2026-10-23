#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/s2s/data_type.hpp"

// Signal-to-Service (S2S) mapping configuration.
//
//   CAN Rx PDU signals  --(EventMapping)-->   SOME/IP event / field notifier (+ getter)
//   SOME/IP method args --(MethodMapping)-->  CAN Tx PDU signals
//
// The structures mirror what is usually generated from the communication matrix
// (DBC/ARXML) and the service interface description (FIDL/ARXML).
namespace ccg::s2s {

using Milliseconds = std::chrono::milliseconds;

struct CanRxMessage {
    std::string name;
    std::uint32_t canId = 0;
    bool extended = false;
    bool fd = false;
    std::uint8_t length = 8;
    Milliseconds cycleTime{0};  // informative
    Milliseconds timeout{0};    // reception deadline monitoring, 0 = disabled
    std::vector<can::SignalSpec> signals;
    std::optional<e2e::CanE2EConfig> e2e;
};

struct CanTxMessage {
    std::string name;
    std::uint32_t canId = 0;
    bool extended = false;
    bool fd = false;
    std::uint8_t length = 8;
    Milliseconds cycleTime{0};             // 0 = no cyclic transmission
    std::uint8_t eventRepetitions = 1;     // frames sent on a signal write, 0 = wait for cycle
    Milliseconds repetitionInterval{0};    // spacing of the repeated frames
    Milliseconds minDelay{0};              // minimum delay time (MDT) between two frames
    std::vector<can::SignalSpec> signals;
    std::optional<e2e::CanE2EConfig> e2e;
};

struct SignalRef {
    std::string message;
    std::string signal;
};

// Physical: element carries raw*factor+offset. Raw: element carries the unscaled value.
enum class Representation : std::uint8_t { Physical, Raw };

// Value used for an element whose source signal is not Valid.
enum class SubstitutionKind : std::uint8_t { InitValue, HoldLastValid, Constant };

struct Substitution {
    SubstitutionKind kind = SubstitutionKind::InitValue;
    double constant = 0.0;  // in element units, used for SubstitutionKind::Constant
};

struct ElementMapping {
    std::string name;
    DataType type = DataType::UInt8;
    SignalRef source;
    Representation representation = Representation::Physical;
    Substitution substitution;
};

enum class UpdateMode : std::uint8_t { OnChange, Cyclic, OnChangeAndCyclic };

struct EventMapping {
    std::string name;
    std::uint16_t serviceId = 0;
    std::uint16_t instanceId = 0;
    std::uint16_t eventId = 0;  // must have bit 15 set
    std::uint16_t eventgroupId = 0;
    bool isField = false;                        // field notifier: initial event on subscribe
    std::optional<std::uint16_t> getterMethodId; // field getter (fields only)
    UpdateMode updateMode = UpdateMode::OnChange;
    Milliseconds cycleTime{0};    // Cyclic / OnChangeAndCyclic
    Milliseconds minInterval{0};  // debounce for on-change notifications
    bool appendStatus = true;     // uint8 SignalStatus after every element
    std::vector<ElementMapping> elements;
};

struct ArgumentMapping {
    std::string name;
    DataType type = DataType::UInt8;
    SignalRef target;
    Representation representation = Representation::Physical;
    bool pulse = false;  // request signal: back to init value once transmitted
};

struct MethodMapping {
    std::string name;
    std::uint16_t serviceId = 0;
    std::uint16_t instanceId = 0;
    std::uint16_t methodId = 0;  // bit 15 clear
    bool fireAndForget = false;
    std::vector<ArgumentMapping> arguments;
};

struct ServiceInstance {
    std::string name;
    std::uint16_t serviceId = 0;
    std::uint16_t instanceId = 0;
    std::uint8_t majorVersion = 1;
    std::uint32_t minorVersion = 0;
};

struct GatewayConfig {
    std::vector<ServiceInstance> services;
    std::vector<CanRxMessage> rxMessages;
    std::vector<CanTxMessage> txMessages;
    std::vector<EventMapping> events;
    std::vector<MethodMapping> methods;
};

// Consistency check of a configuration; returns one human readable line per problem.
std::vector<std::string> validateConfig(const GatewayConfig& config);

}  // namespace ccg::s2s
