#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/keym/key_manager.hpp"

// UDS interface of the key manager on the gateway's own diagnostic address,
// used by the backend key server through the off-board tester / OTA client.
//
//   31 01 F2 00 <M1 M2 M3>  load key (SHE memory update protocol)
//                           -> 71 01 F2 00 <SHE error code> [<M4 M5>]
//   31 01 F2 01 [slot ..]   activate pending keys (all, or the listed slots) -> 71 01 F2 01 <count>
//   31 01 F2 02 [slot ..]   discard pending keys  (all, or the listed slots) -> 71 01 F2 02 <count>
//   22 F2 A0                key status: <n> { slot, state, counter (4), pending counter (4) }
//   22 F2 A1                SHE UID (15 bytes), needed to address an update container
//
// The routines need the extended session and a physical request. Their
// authorisation is the SHE protocol itself (M3, made with MASTER_ECU_KEY by the
// backend); repeated authentication failures answer NRC 0x37 for the lockout time.
// A changed key store is persisted before the response is sent: if that fails
// the answer is NRC 0x72 (generalProgrammingFailure) and the backend retries
// with the next counter value.
namespace ccg::keym {

namespace uds {
inline constexpr std::uint16_t kRidLoadKey = 0xF200;
inline constexpr std::uint16_t kRidActivateKeys = 0xF201;
inline constexpr std::uint16_t kRidDiscardKeys = 0xF202;
inline constexpr std::uint16_t kDidKeyStatus = 0xF2A0;
inline constexpr std::uint16_t kDidUid = 0xF2A1;

// key status byte
inline constexpr std::uint8_t kStatusActive = 0x01;
inline constexpr std::uint8_t kStatusPending = 0x02;
inline constexpr std::uint8_t kStatusPrevious = 0x04;
inline constexpr std::uint8_t kStatusWriteProtected = 0x08;
inline constexpr std::uint8_t kStatusMacKey = 0x10;
}  // namespace uds

class KeyManagementService final : public diag::ILocalServiceHandler {
public:
    // `persist` writes the key store to non-volatile memory (true = stored).
    explicit KeyManagementService(KeyManager& keys, std::function<bool()> persist = {})
        : keys_(keys), persist_(std::move(persist)) {}

    std::optional<std::vector<std::uint8_t>> handle(const std::vector<std::uint8_t>& request,
                                                    const diag::LocalRequestContext& context) override;

private:
    std::optional<std::vector<std::uint8_t>> routineControl(const std::vector<std::uint8_t>& request,
                                                            const diag::LocalRequestContext& context);
    std::vector<std::uint8_t> keyStatus() const;

    bool persisted() { return !persist_ || persist_(); }

    KeyManager& keys_;
    std::function<bool()> persist_;
};

}  // namespace ccg::keym
