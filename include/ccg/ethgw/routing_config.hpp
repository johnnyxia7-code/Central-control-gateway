#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/secoc/fv_sync.hpp"
#include "ccg/secoc/secoc.hpp"

// Routing table of the central Ethernet gateway.
//
//   Message (PDU) routing : a received PDU is forwarded unchanged to one or more
//                           target PDUs (CAN<->CAN, CAN<->Ethernet, Ethernet<->Ethernet),
//                           optionally with a new identifier and padding.
//   Signal routing        : a signal is taken out of a received PDU (frame
//                           decomposition) and written into a target PDU that the
//                           gateway assembles from several sources (frame assembly).
//   Ethernet framing      : PDUs on an Ethernet channel travel in UDP datagrams with
//                           AUTOSAR SoAd PDU headers; several PDUs are collected into
//                           one datagram and split up again on reception.
namespace ccg::ethgw {

using Milliseconds = std::chrono::milliseconds;

enum class BusType : std::uint8_t { Can, CanFd, Ethernet };

const char* toString(BusType type);

struct Channel {
    std::string name;
    BusType type = BusType::Can;
    // Ethernet only: transmission container (datagram assembly).
    Milliseconds collectionTimeout{0};  // max time a PDU waits for companions, 0 = send at once
    std::size_t maxDatagramSize = 1400;  // UDP payload limit incl. PDU headers
};

// How the gateway sends a PDU that it assembles from routed signals.
enum class TxMode : std::uint8_t {
    OnUpdate,           // every reception of a triggering source signal
    OnChange,           // a triggering signal changed its value
    Cyclic,             // fixed period only
    CyclicAndOnChange,  // fixed period plus immediate send on change
};

struct PduDefinition {
    std::string name;
    std::string channel;
    std::uint32_t id = 0;  // CAN identifier, or SoAd header ID on Ethernet
    bool extended = false; // CAN: 29-bit identifier
    bool fd = false;       // CAN FD frame format (CAN FD channels only)
    std::uint16_t length = 8;
    std::vector<can::SignalSpec> signals;
    std::optional<e2e::CanE2EConfig> e2e;  // checked on reception / applied on assembly
    // Secured I-PDU (SecOC): verified on reception, authenticated on transmission.
    // The last overheadBytes() of `length` carry the truncated FV and MAC; signals
    // and E2E live in the authentic part in front of them.
    std::optional<secoc::SecOcConfig> secoc;

    // Reception (source of signal routes)
    Milliseconds timeout{0};  // deadline monitoring, 0 = off

    // Transmission
    TxMode txMode = TxMode::OnChange;  // assembled PDUs only; routed PDUs are sent at once
    Milliseconds cycleTime{0};
    Milliseconds minDelay{0};          // minimum delay between two assembled frames
    std::uint8_t padding = 0x00;       // fill byte when the target is longer than the source
    bool urgent = false;               // Ethernet: flush the datagram right after this PDU
};

struct PduRoute {
    std::string name;
    std::string source;                // PDU received by the gateway
    std::vector<std::string> targets;  // PDUs sent by the gateway (fan-out)
};

struct SignalRef {
    std::string pdu;
    std::string signal;
};

// Raw: bit pattern is copied (same length required).
// Physical: decoded with the source scaling and re-encoded with the target scaling.
enum class Conversion : std::uint8_t { Raw, Physical };

// Target value while the source is unusable (Rx timeout or E2E failure).
enum class Substitution : std::uint8_t { HoldLast, InitValue, InvalidValue };

struct SignalRoute {
    SignalRef source;
    SignalRef target;
    Conversion conversion = Conversion::Raw;
    Substitution substitution = Substitution::InitValue;
    bool triggering = true;  // an update of this signal may trigger the target PDU
};

// The gateway as freshness value (FV) master: trip and reset counter for all
// SecOC PDUs with FreshnessMode::TripReset, distributed in sync messages.
struct FreshnessSyncConfig {
    secoc::TripResetLayout layout;
    secoc::SyncMessageConfig message;
    std::vector<std::string> syncPdus;  // the sync message is sent in each of them (one per bus)
};

struct RoutingConfig {
    std::vector<Channel> channels;
    std::vector<PduDefinition> pdus;
    std::vector<PduRoute> pduRoutes;
    std::vector<SignalRoute> signalRoutes;
    std::optional<FreshnessSyncConfig> freshnessSync;
};

// Length of the authentic part (the whole PDU when it is not secured).
std::size_t authenticLength(const PduDefinition& pdu);

std::vector<std::string> validateRoutingConfig(const RoutingConfig& config);

}  // namespace ccg::ethgw
