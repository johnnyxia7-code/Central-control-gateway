#include "ecu_key_store.hpp"

namespace ccg::sim {

void EcuKeyStore::attach(UdsEcu& ecu) {
    ecu.setHandler([this, &ecu](const std::vector<std::uint8_t>& request, bool functional) {
        if (!request.empty() && request[0] == 0x10 && request.size() == 2) {
            session_ = request[1] & 0x7F;
        }
        auto response = service_.handle(request, diag::LocalRequestContext{session_, functional, ecu.now()});
        if (!response) return ecu.defaultHandler(request, functional);
        if (response->empty()) return UdsEcu::Responses{};
        if (tamperProof_ && response->size() == 5 + 48 && (*response)[0] == 0x71) response->back() ^= 0x01;
        return UdsEcu::Responses{{Milliseconds(2), std::move(*response)}};
    });
}

}  // namespace ccg::sim
