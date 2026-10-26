#include "uds_ecu.hpp"

#include <algorithm>

namespace ccg::sim {

UdsEcu::UdsEcu(Config config, std::function<bool(const can::CanFrame&)> transmit)
    : cfg_(std::move(config)) {
    isotp::Config tp;
    tp.txId = cfg_.responseId;
    tp.rxId = cfg_.requestId;
    tp.fd = cfg_.fd;
    tp.blockSize = cfg_.blockSize;
    tp.stMin = cfg_.stMin;
    tp.maxRxLength = cfg_.maxRxLength;

    isotp::Callbacks cb;
    cb.transmit = std::move(transmit);
    cb.rxDone = [this](std::vector<std::uint8_t>&& request) {
        onRequest(std::move(request), false, now_);
    };
    tp_ = std::make_unique<isotp::Channel>(tp, std::move(cb));
    handler_ = [this](const std::vector<std::uint8_t>& r, bool f) { return defaultHandler(r, f); };
}

void UdsEcu::onFrame(const can::CanFrame& frame, TimePoint now) {
    if (silent_) return;
    now_ = now;
    if (frame.id == cfg_.requestId) {
        tp_->onFrame(frame, now);
    } else if (frame.id == cfg_.functionalId && frame.length >= 2) {
        const std::size_t n = frame.data[0] & 0x0F;  // functional requests are single frames
        if ((frame.data[0] >> 4) == 0 && n >= 1 && n + 1 <= frame.length) {
            onRequest(std::vector<std::uint8_t>(frame.data.begin() + 1, frame.data.begin() + 1 + n),
                      true, now);
        }
    }
}

void UdsEcu::onRequest(std::vector<std::uint8_t>&& request, bool functional, TimePoint now) {
    requests_.push_back(request);
    if (!handler_) return;
    for (auto& [delay, response] : handler_(request, functional)) {
        scheduled_.emplace_back(now + delay, std::move(response));
    }
}

void UdsEcu::mainFunction(TimePoint now) {
    if (silent_) return;
    now_ = now;
    tp_->mainFunction(now);
    if (!scheduled_.empty() && now >= scheduled_.front().first && !tp_->txBusy()) {
        auto response = std::move(scheduled_.front().second);
        scheduled_.erase(scheduled_.begin());
        tp_->transmit(std::move(response), now);
    }
}

UdsEcu::Responses UdsEcu::defaultHandler(const std::vector<std::uint8_t>& req, bool functional) const {
    using Bytes = std::vector<std::uint8_t>;
    const std::uint8_t sid = req[0];
    auto now = Milliseconds(0);
    auto negative = [&](std::uint8_t nrc) -> Responses {
        if (functional && (nrc == 0x11 || nrc == 0x12 || nrc == 0x31)) return {};
        return {{now, Bytes{0x7F, sid, nrc}}};
    };
    switch (sid) {
        case 0x10:
            if (req.size() != 2) return negative(0x13);
            if (req[1] & 0x80) return {};
            return {{now, Bytes{0x50, req[1], 0x00, 0x32, 0x01, 0xF4}}};
        case 0x3E:
            if (req.size() != 2) return negative(0x13);
            if (req[1] & 0x80) return {};
            return {{now, Bytes{0x7E, 0x00}}};
        case 0x22: {
            if (req.size() != 3) return negative(0x13);
            Bytes out = {0x62, req[1], req[2]};
            const std::string* text = nullptr;
            if (req[1] == 0xF1 && req[2] == 0x90) text = &cfg_.vin;
            if (req[1] == 0xF1 && req[2] == 0x87) text = &cfg_.partNumber;
            if (!text) return negative(0x31);
            out.insert(out.end(), text->begin(), text->end());
            return {{now, out}};
        }
        case 0x31:  // RoutineControl: long running, answered with "response pending" first
            if (req.size() < 4) return negative(0x13);
            return {{now, Bytes{0x7F, 0x31, 0x78}},
                    {Milliseconds(200), Bytes{0x71, req[1], req[2], req[3]}}};
        case 0x34:  // RequestDownload: max block length 0x1002 (4096 + SID + counter)
            return {{now, Bytes{0x74, 0x20, 0x10, 0x02}}};
        case 0x36:
            if (req.size() < 2) return negative(0x13);
            return {{now, Bytes{0x76, req[1]}}};
        case 0x37:
            return {{now, Bytes{0x77}}};
        default:
            return negative(0x11);
    }
}

}  // namespace ccg::sim
