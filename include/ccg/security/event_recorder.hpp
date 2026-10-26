#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <utility>

namespace ccg::security {

using TimePoint = std::chrono::steady_clock::time_point;
// Local reference IDs; map to the vehicle's approved IdsM event catalogue.
enum class EventId : std::uint16_t {
    Overflow = 0, SecOcMac = 1, SecOcFreshness = 2, SecOcInput = 3,
    MalformedDatagram = 4, SecOcTransmit = 5, DiagnosticDenied = 6, Startup = 7,
    KeyEventBase = 100
};
struct EventRecord {
    std::uint64_t sequence = 0;
    EventId id = EventId::Overflow;
    std::uint32_t source = 0;
    std::uint64_t count = 0;
    TimePoint first{}, last{};
};

// Single executor. report() does no I/O and aggregates at most 64 distinct
// event/source pairs. A failed sink retains records. Overflow is itself counted.
// No automatic traffic blocking: mitigation requires a vehicle safety policy.
class EventRecorder {
public:
    using Sink = std::function<bool(const EventRecord&)>;
    static constexpr std::size_t capacity = 64;
    static constexpr std::size_t batchSize = 16;
    explicit EventRecorder(Sink sink) : sink_(std::move(sink)) {}
    void report(EventId id, std::uint32_t source, TimePoint now) {
        for (auto& e : pending_) {
            if (e.id == id && e.source == source) {
                increment(e.count); e.last = std::max(e.last, now); return;
            }
        }
        if (pending_.size() == capacity) {
            if (lost_ == 0) lostFirst_ = now;
            lostLast_ = now; increment(lost_); increment(totalLost_); return;
        }
        pending_.push_back({++sequence_, id, source, 1, now, now});
    }
    void flush(TimePoint now) {
        if (flushed_ && now < nextFlush_) return;
        flushed_ = true; nextFlush_ = now + std::chrono::seconds(1);
        std::size_t budget = batchSize;
        if (lost_ != 0) {
            // Keep a stable identity if the sink reports a failed/uncertain write.
            if (!lostSequence_) lostSequence_ = ++sequence_;
            const EventRecord e{lostSequence_, EventId::Overflow, 0, lost_, lostFirst_, lostLast_};
            if (!write(e)) return;
            lost_ = 0; lostSequence_ = 0; --budget;
        }
        while (budget-- && !pending_.empty()) {
            if (!write(pending_.front())) return;
            pending_.pop_front();
        }
    }
    std::size_t pending() const { return pending_.size(); }
    std::uint64_t lost() const { return totalLost_; }
    std::uint64_t sinkFailures() const { return sinkFailures_; }
private:
    static void increment(std::uint64_t& n) { if (n != std::numeric_limits<std::uint64_t>::max()) ++n; }
    bool write(const EventRecord& record) {
        try { if (sink_ && sink_(record)) return true; } catch (...) { /* preserve evidence for retry */ }
        increment(sinkFailures_); return false;
    }
    Sink sink_;
    std::deque<EventRecord> pending_;
    std::uint64_t sequence_ = 0, lost_ = 0, totalLost_ = 0, lostSequence_ = 0, sinkFailures_ = 0;
    TimePoint lostFirst_{}, lostLast_{}, nextFlush_{};
    bool flushed_ = false;
};
} // namespace ccg::security
