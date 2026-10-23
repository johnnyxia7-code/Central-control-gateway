#pragma once

#include <memory>

#include <vsomeip/vsomeip.hpp>

#include "ccg/someip/someip_message.hpp"

// Conversion between vsomeip messages and the stack-independent ccg::someip::Message.
namespace ccg::platform::vsomeip_adapter {

inline someip::Message fromVsomeip(const vsomeip::message& in) {
    someip::Message out;
    auto& h = out.header;
    h.serviceId = in.get_service();
    h.methodId = in.get_method();
    h.clientId = in.get_client();
    h.sessionId = in.get_session();
    h.protocolVersion = in.get_protocol_version();
    h.interfaceVersion = in.get_interface_version();
    h.messageType = static_cast<someip::MessageType>(in.get_message_type());
    h.returnCode = static_cast<someip::ReturnCode>(in.get_return_code());
    if (const auto payload = in.get_payload()) {
        out.payload.assign(payload->get_data(), payload->get_data() + payload->get_length());
    }
    h.length = static_cast<std::uint32_t>(out.payload.size() + 8);
    return out;
}

inline std::shared_ptr<vsomeip::payload> toPayload(const std::vector<std::uint8_t>& data) {
    return vsomeip::runtime::get()->create_payload(data);
}

}  // namespace ccg::platform::vsomeip_adapter
