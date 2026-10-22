#include <stdexcept>

#include "multicast_route.hpp"
#include "test_framework.hpp"

using ccg::platform::MulticastRoute;

TEST_CASE("multicast route: prefix validation") {
    bool threw = false;
    try {
        MulticastRoute("eth0", "10.0.0.0/8");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
    threw = false;
    try {
        MulticastRoute("eth0", "224.0.0.0/3");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
    MulticastRoute sdOnly("eth0", "224.244.224.245");  // host route for the SD address only
    CHECK(sdOnly.interfaceName() == "eth0");
}

TEST_CASE("multicast route: missing interface is reported, nothing installed") {
    MulticastRoute route("ccg-no-such-if0");
    CHECK(route.install() == MulticastRoute::Result::NoDevice);
    CHECK(!route.lastError().empty());
}
