#include "vehicle_diag_routing.hpp"

namespace ccg::config {

diag::DiagRoutingConfig makeVehicleDiagRouting() {
    using namespace std::chrono_literals;
    diag::DiagRoutingConfig cfg;

    auto& e = cfg.entity;
    e.vin = "WCCG0HPC0RT000001";
    e.logicalAddress = dg::kGateway;
    e.eid = {0x02, 0x00, 0x5E, 0x10, 0x00, 0x01};
    e.gid = e.eid;
    e.protocolVersion = 0x02;
    e.functionalAddress = dg::kFunctional;
    e.maxTcpConnections = 2;
    e.maxDiagnosticMessageSize = 8192;  // flash TransferData blocks via CAN FD

    cfg.channels = {
        {"PT_CAN", true, 0x7DF, 0xCC},
        {"CHS_CAN", false, 0x7DF, 0xCC},
        {"BODY_CAN", false, 0x7DF, 0xCC},
    };

    auto ecu = [](const char* name, std::uint16_t la, const char* channel, std::uint32_t req,
                  std::uint32_t resp, bool fd) {
        diag::EcuRoute r;
        r.name = name;
        r.logicalAddress = la;
        r.channel = channel;
        r.requestId = req;
        r.responseId = resp;
        r.fd = fd;
        r.maxRequestLength = fd ? 8192 : 4095;  // escape first frames only towards CAN FD ECUs
        r.blockSize = 0;  // the gateway receives without further flow control
        r.stMin = 0;
        r.nBs = 1000ms;
        r.nCr = 1000ms;
        return r;
    };
    cfg.ecus = {
        ecu("VCU", dg::kVcu, "PT_CAN", 0x7E0, 0x7E8, true),
        ecu("BMS", dg::kBms, "PT_CAN", 0x7E1, 0x7E9, false),
        ecu("ESP", dg::kEsp, "CHS_CAN", 0x720, 0x728, false),
        ecu("EPS", dg::kEps, "CHS_CAN", 0x721, 0x729, false),
        ecu("BCM", dg::kBcm, "BODY_CAN", 0x740, 0x748, false),
    };
    return cfg;
}

}  // namespace ccg::config
