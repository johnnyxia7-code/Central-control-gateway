#pragma once

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/keym/key_management_service.hpp"
#include "ccg/keym/key_manager.hpp"

// Simulated ECU on the vehicle Ethernet: a DoIP entity whose own UDS server
// offers session control and the SHE key management services of its HSM.
namespace ccg::sim {

class DoipEcu {
public:
    DoipEcu(diag::DiagRoutingConfig entity, keym::KeyManagerConfig keys, diag::IDiagTransport& transport)
        : keys_(std::move(keys)), entity_(std::move(entity), transport) {
        entity_.addLocalService(service_);
    }
    DoipEcu(const DoipEcu&) = delete;
    DoipEcu& operator=(const DoipEcu&) = delete;

    diag::DiagGateway& entity() { return entity_; }
    keym::KeyManager& keys() { return keys_; }

private:
    keym::KeyManager keys_;
    keym::KeyManagementService service_{keys_};
    diag::DiagGateway entity_;
};

}  // namespace ccg::sim
