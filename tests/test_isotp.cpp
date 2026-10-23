#include <deque>
#include <memory>
#include <vector>

#include "ccg/isotp/isotp_channel.hpp"
#include "test_framework.hpp"

using namespace ccg;
using namespace ccg::isotp;
using namespace std::chrono_literals;

namespace {

using Bytes = std::vector<std::uint8_t>;

Bytes pattern(std::size_t n) {
    Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i * 7 + 3);
    return b;
}

// Two ISO-TP endpoints (A = tester side, B = ECU side) on one simulated bus.
struct Link {
    struct Side {
        std::unique_ptr<Channel> ch;
        std::vector<Result> txResults;
        std::vector<Bytes> received;
        std::vector<Result> rxErrors;
        std::vector<can::CanFrame> sent;
        std::vector<TimePoint> sentAt;
        int refuse = 0;      // transmissions to refuse (controller busy)
        bool connected = true;
    };
    Side a, b;
    std::deque<std::pair<bool, can::CanFrame>> bus;  // (fromA, frame)
    TimePoint now = TimePoint{} + 1s;

    Link(Config ca, Config cb) {
        a.ch = std::make_unique<Channel>(ca, callbacks(a, true));
        b.ch = std::make_unique<Channel>(cb, callbacks(b, false));
    }

    static Config config(std::uint32_t tx, std::uint32_t rx, bool fd = false) {
        Config c;
        c.txId = tx;
        c.rxId = rx;
        c.fd = fd;
        c.maxRxLength = 0xFFFFF;
        return c;
    }

    Callbacks callbacks(Side& side, bool fromA) {
        Callbacks cb;
        cb.transmit = [this, &side, fromA](const can::CanFrame& f) {
            if (side.refuse > 0) {
                --side.refuse;
                return false;
            }
            side.sent.push_back(f);
            side.sentAt.push_back(now);
            if (side.connected) bus.emplace_back(fromA, f);
            return true;
        };
        cb.txDone = [&side](Result r) { side.txResults.push_back(r); };
        cb.rxDone = [&side](Bytes&& d) { side.received.push_back(std::move(d)); };
        cb.rxError = [&side](Result r) { side.rxErrors.push_back(r); };
        return cb;
    }

    void deliver() {
        while (!bus.empty()) {
            auto [fromA, frame] = bus.front();
            bus.pop_front();
            (fromA ? b : a).ch->onFrame(frame, now);
        }
    }

    void run(std::chrono::milliseconds duration) {
        deliver();
        for (auto t = 0ms; t < duration; t += 1ms) {
            now += 1ms;
            a.ch->mainFunction(now);
            b.ch->mainFunction(now);
            deliver();
        }
    }
};

Link makeLink(bool fd = false) {
    return Link(Link::config(0x7E0, 0x7E8, fd), Link::config(0x7E8, 0x7E0, fd));
}

can::CanFrame frame(std::uint32_t id, Bytes bytes) {
    can::CanFrame f;
    f.id = id;
    f.length = static_cast<std::uint8_t>(bytes.size());
    std::copy(bytes.begin(), bytes.end(), f.data.begin());
    return f;
}

}  // namespace

TEST_CASE("isotp: single frame with padding") {
    auto link = makeLink();
    REQUIRE(link.a.ch->transmit({0x22, 0xF1, 0x90}, link.now));
    REQUIRE(link.a.sent.size() == 1);
    const Bytes expected = {0x03, 0x22, 0xF1, 0x90, 0xCC, 0xCC, 0xCC, 0xCC};
    CHECK(Bytes(link.a.sent[0].data.begin(), link.a.sent[0].data.begin() + 8) == expected);
    CHECK_EQ(link.a.sent[0].length, 8);
    link.run(0ms);
    REQUIRE(link.b.received.size() == 1);
    CHECK(link.b.received[0] == (Bytes{0x22, 0xF1, 0x90}));
    REQUIRE(link.a.txResults.size() == 1);
    CHECK(link.a.txResults[0] == Result::Ok);
}

TEST_CASE("isotp: unpadded single frame uses the minimum DLC") {
    auto ca = Link::config(0x7E0, 0x7E8);
    ca.padFrames = false;
    Link link(ca, Link::config(0x7E8, 0x7E0));
    link.a.ch->transmit({0x3E, 0x00}, link.now);
    CHECK_EQ(link.a.sent[0].length, 3);
    link.run(0ms);
    CHECK(link.b.received.size() == 1);
}

TEST_CASE("isotp: multi-frame transfer FF / FC / CF") {
    auto link = makeLink();
    const auto data = pattern(20);
    link.a.ch->transmit(data, link.now);
    link.run(5ms);
    REQUIRE(link.b.received.size() == 1);
    CHECK(link.b.received[0] == data);
    REQUIRE(link.a.sent.size() == 3);  // FF + 2 CF
    CHECK_EQ(link.a.sent[0].data[0], 0x10);
    CHECK_EQ(link.a.sent[0].data[1], 20);
    CHECK_EQ(link.a.sent[1].data[0], 0x21);
    CHECK_EQ(link.a.sent[2].data[0], 0x22);
    REQUIRE(link.b.sent.size() == 1);  // one FC
    CHECK_EQ(link.b.sent[0].data[0], 0x30);
    CHECK(link.a.txResults.at(0) == Result::Ok);
}

TEST_CASE("isotp: block size and STmin from the receiver are respected") {
    auto cb = Link::config(0x7E8, 0x7E0);
    cb.blockSize = 2;
    cb.stMin = 5;  // ms
    Link link(Link::config(0x7E0, 0x7E8), cb);
    const auto data = pattern(34);  // FF (6) + 4 CF (7 each)
    link.a.ch->transmit(data, link.now);
    link.run(100ms);
    REQUIRE(link.b.received.size() == 1);
    CHECK(link.b.received[0] == data);
    CHECK_EQ(link.b.sent.size(), 2U);  // FC after FF and after the first block of 2
    REQUIRE(link.a.sent.size() == 5);
    for (std::size_t i = 2; i < link.a.sentAt.size(); ++i) {
        if (i == 3) continue;  // first CF of the second block follows the FC
        CHECK(link.a.sentAt[i] - link.a.sentAt[i - 1] >= 5ms);
    }
}

TEST_CASE("isotp: sequence numbers wrap and long messages arrive intact") {
    auto link = makeLink();
    const auto data = pattern(4095);
    link.a.ch->transmit(data, link.now);
    link.run(20ms);
    REQUIRE(link.b.received.size() == 1);
    CHECK(link.b.received[0] == data);
    CHECK_EQ(link.a.sent[16].data[0], 0x20);  // SN 15 -> 0
}

TEST_CASE("isotp: escape first frame for more than 4095 bytes on CAN FD") {
    auto link = makeLink(true);
    const auto data = pattern(5000);
    link.a.ch->transmit(data, link.now);
    link.run(20ms);
    REQUIRE(link.b.received.size() == 1);
    CHECK(link.b.received[0] == data);
    const auto& ff = link.a.sent[0];
    CHECK(ff.fd);
    CHECK_EQ(ff.length, 64);
    const Bytes pci = {0x10, 0x00, 0x00, 0x00, 0x13, 0x88};
    CHECK(Bytes(ff.data.begin(), ff.data.begin() + 6) == pci);
    CHECK_EQ(link.a.sent[1].length, 64);
}

TEST_CASE("isotp: CAN FD single frame escape and DLC rounding") {
    auto link = makeLink(true);
    link.a.ch->transmit(pattern(20), link.now);
    const auto& sf = link.a.sent.at(0);
    CHECK_EQ(sf.data[0], 0x00);
    CHECK_EQ(sf.data[1], 20);
    CHECK_EQ(sf.length, 24);  // 22 bytes rounded up to the next CAN FD length
    link.run(0ms);
    REQUIRE(link.b.received.size() == 1);
    CHECK(link.b.received[0] == pattern(20));
}

TEST_CASE("isotp: missing flow control times out after N_Bs") {
    auto link = makeLink();
    link.a.connected = false;
    link.a.ch->transmit(pattern(30), link.now);
    link.run(999ms);
    CHECK(link.a.txResults.empty());
    CHECK(link.a.ch->txBusy());
    link.run(1ms);
    REQUIRE(link.a.txResults.size() == 1);
    CHECK(link.a.txResults[0] == Result::TimeoutBs);
    CHECK(!link.a.ch->txBusy());
}

TEST_CASE("isotp: missing consecutive frame times out after N_Cr") {
    auto link = makeLink();
    link.b.ch->onFrame(frame(0x7E0, {0x10, 0x14, 1, 2, 3, 4, 5, 6}), link.now);
    CHECK(link.b.ch->rxBusy());
    link.run(1000ms);
    REQUIRE(link.b.rxErrors.size() == 1);
    CHECK(link.b.rxErrors[0] == Result::TimeoutCr);
}

TEST_CASE("isotp: wrong sequence number and unexpected PDU abort the reception") {
    auto link = makeLink();
    link.b.ch->onFrame(frame(0x7E0, {0x10, 0x14, 1, 2, 3, 4, 5, 6}), link.now);
    link.b.ch->onFrame(frame(0x7E0, {0x22, 1, 2, 3, 4, 5, 6, 7}), link.now);
    REQUIRE(link.b.rxErrors.size() == 1);
    CHECK(link.b.rxErrors[0] == Result::WrongSequence);

    link.b.ch->onFrame(frame(0x7E0, {0x10, 0x14, 1, 2, 3, 4, 5, 6}), link.now);
    link.b.ch->onFrame(frame(0x7E0, {0x02, 0x3E, 0x00}), link.now);  // SF during reception
    CHECK(link.b.rxErrors.back() == Result::UnexpectedPdu);
    REQUIRE(link.b.received.size() == 1);
    CHECK(link.b.received[0] == (Bytes{0x3E, 0x00}));
}

TEST_CASE("isotp: receiver overflow is reported to the sender") {
    auto cb = Link::config(0x7E8, 0x7E0);
    cb.maxRxLength = 10;
    Link link(Link::config(0x7E0, 0x7E8), cb);
    link.a.ch->transmit(pattern(20), link.now);
    link.run(1ms);
    REQUIRE(link.a.txResults.size() == 1);
    CHECK(link.a.txResults[0] == Result::Overflow);
    CHECK_EQ(link.b.sent.at(0).data[0], 0x32);
    CHECK(link.b.rxErrors.at(0) == Result::Overflow);
}

TEST_CASE("isotp: FC.WAIT extends N_Bs up to maxWft") {
    auto link = makeLink();
    link.a.connected = false;
    link.a.ch->transmit(pattern(30), link.now);
    for (int i = 0; i < 10; ++i) {
        link.run(900ms);
        link.a.ch->onFrame(frame(0x7E8, {0x31, 0x00, 0x00}), link.now);
    }
    CHECK(link.a.txResults.empty());  // 10 waits tolerated
    link.a.ch->onFrame(frame(0x7E8, {0x30, 0x00, 0x00}), link.now);
    CHECK(link.a.txResults.at(0) == Result::Ok);

    link.a.ch->transmit(pattern(30), link.now);
    for (int i = 0; i < 11; ++i) link.a.ch->onFrame(frame(0x7E8, {0x31, 0, 0}), link.now);
    CHECK(link.a.txResults.at(1) == Result::WaitLimit);
}

TEST_CASE("isotp: busy channel, controller retries and N_As") {
    auto link = makeLink();
    link.a.connected = false;
    REQUIRE(link.a.ch->transmit(pattern(30), link.now));
    CHECK(!link.a.ch->transmit({0x01}, link.now));  // still busy
    CHECK(!link.a.ch->transmit({}, link.now));

    auto retry = makeLink();
    retry.a.refuse = 3;  // controller busy three times
    retry.a.ch->transmit({0x3E, 0x00}, retry.now);
    retry.run(5ms);
    CHECK(retry.a.txResults.at(0) == Result::Ok);
    CHECK_EQ(retry.b.received.size(), 1U);

    auto dead = makeLink();
    dead.a.refuse = 100000;
    dead.a.ch->transmit({0x3E, 0x00}, dead.now);
    dead.run(1000ms);
    CHECK(dead.a.txResults.at(0) == Result::TimeoutAs);
}

TEST_CASE("isotp: STmin decoding") {
    CHECK(decodeStMin(0x00) == 0ms);
    CHECK(decodeStMin(0x7F) == 127ms);
    CHECK(decodeStMin(0xF5) == 1ms);   // 500 us
    CHECK(decodeStMin(0x80) == 127ms);  // reserved
    CHECK(decodeStMin(0xFA) == 127ms);
    CHECK(!makeSingleFrame(0x7DF, false, false, 0xCC, pattern(8).data(), 8).has_value());
}
