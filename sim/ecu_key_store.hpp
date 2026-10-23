#pragma once

#include <cstdint>

#include "ccg/keym/key_management_service.hpp"
#include "ccg/keym/key_manager.hpp"
#include "uds_ecu.hpp"

// HSM of a simulated ECU: SHE key slots behind the ECU's UDS server
// (key update, activation, key status, UID), for the key master tests and
// simulation.
namespace ccg::sim {

class EcuKeyStore {
public:
    explicit EcuKeyStore(keym::KeyManagerConfig config) : keys_(std::move(config)) {}
    EcuKeyStore(const EcuKeyStore&) = delete;  // the service refers to keys_
    EcuKeyStore& operator=(const EcuKeyStore&) = delete;

    keym::KeyManager& keys() { return keys_; }

    // Serves the key management services on `ecu` (extended session needed);
    // other requests keep the ECU's default behaviour.
    void attach(UdsEcu& ecu);

    // Fault injection: corrupt M5 of the next confirmations (ECU that does not
    // really store the key).
    void setTamperProof(bool tamper) { tamperProof_ = tamper; }

private:
    keym::KeyManager keys_;
    keym::KeyManagementService service_{keys_};
    std::uint8_t session_ = 0x01;
    bool tamperProof_ = false;
};

}  // namespace ccg::sim
