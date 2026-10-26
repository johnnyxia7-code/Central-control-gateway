#include "ccg/security/event_recorder.hpp"
#include "test_framework.hpp"
#include <stdexcept>
#include <vector>

using namespace ccg::security;
using namespace std::chrono_literals;

TEST_CASE("IDPS: burst aggregation preserves counts and time range with bounded flush rate") {
    std::vector<EventRecord> written;
    EventRecorder r([&](const EventRecord& e) { written.push_back(e); return true; });
    const TimePoint start{};
    for (int i = 0; i < 10000; ++i) r.report(EventId::SecOcMac, 7, start + std::chrono::milliseconds(i));
    CHECK_EQ(r.pending(), 1u);
    r.flush(start + 10s);
    REQUIRE(written.size() == 1u);
    CHECK_EQ(written[0].count, 10000u);
    CHECK(written[0].first == start && written[0].last == start + 9999ms);
    r.report(EventId::SecOcMac, 7, start + 10s);
    r.flush(start + 10500ms); CHECK_EQ(written.size(), 1u);
    r.flush(start + 11s); CHECK_EQ(written.size(), 2u);
}

TEST_CASE("IDPS: unique-event flood is bounded and overflow evidence is emitted") {
    std::vector<EventRecord> written;
    EventRecorder r([&](const EventRecord& e) { written.push_back(e); return true; });
    const TimePoint now{};
    for (unsigned i = 0; i < 1000; ++i) r.report(EventId::MalformedDatagram, i, now);
    CHECK_EQ(r.pending(), EventRecorder::capacity);
    CHECK_EQ(r.lost(), 936u);
    r.flush(now);
    REQUIRE(written.size() == EventRecorder::batchSize);
    CHECK(written[0].id == EventId::Overflow);
    CHECK_EQ(written[0].count, 936u);
    CHECK_EQ(r.pending(), 49u);
    for (int i = 1; i < 6; ++i) r.flush(now + std::chrono::seconds(i));
    CHECK_EQ(r.pending(), 0u);
    CHECK_EQ(written.size(), 65u);
}

TEST_CASE("IDPS: failing and throwing sinks retain evidence for bounded retry") {
    int mode = 0;
    std::vector<EventRecord> attempted;
    EventRecorder r([&](const EventRecord& e) {
        attempted.push_back(e);
        if (mode == 1) throw std::runtime_error("storage unavailable");
        return mode == 2;
    });
    const TimePoint now{};
    r.report(EventId::DiagnosticDenied, 0x100, now);
    r.flush(now); CHECK_EQ(r.pending(), 1u);
    mode = 1; r.flush(now + 1s); CHECK_EQ(r.pending(), 1u);
    CHECK_EQ(r.sinkFailures(), 2u);
    mode = 2; r.flush(now + 2s); CHECK_EQ(r.pending(), 0u);
    REQUIRE(attempted.size() == 3u);
    CHECK_EQ(attempted[0].sequence, attempted[2].sequence);
}
