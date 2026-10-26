#pragma once

#include "security_journal.hpp"
#include <iostream>
#include <stdexcept>

namespace ccg::platform {
// Separate paths for the diagnostic and Ethernet processes; never share writers.
class SecurityRuntime {
public:
    explicit SecurityRuntime(const std::string& path)
        : journal_(path), persistent_(!path.empty()), recorder_([this](const security::EventRecord& e) {
            if (persistent_) return journal_.append(e);
            std::cerr << "[security] event=" << static_cast<unsigned>(e.id) << " source=" << e.source
                      << " count=" << e.count << " sequence=" << e.sequence << "\n";
            return static_cast<bool>(std::cerr);
        }) {
        if (!persistent_) std::cerr << "[security] WARNING: no --security-log; events are not retained by this process\n";
        recorder_.report(security::EventId::Startup, 0, std::chrono::steady_clock::now());
        recorder_.flush(std::chrono::steady_clock::now());
        if (recorder_.sinkFailures()) throw std::runtime_error("cannot initialize security event sink");
    }
    security::EventRecorder& recorder() { return recorder_; }
    void flush(security::TimePoint now) {
        const auto before = recorder_.sinkFailures();
        recorder_.flush(now);
        if (recorder_.sinkFailures() != before)
            std::cerr << "[security] ERROR: evidence sink unavailable; bounded queue retained for retry; lost="
                      << recorder_.lost() << "\n";
    }
private:
    SecurityJournal journal_;
    bool persistent_;
    security::EventRecorder recorder_;
};
} // namespace ccg::platform
