#include <stdexcept>

#include "network_setup.hpp"
#include "test_framework.hpp"

using ccg::platform::NetworkSetup;

namespace {

template <typename Fn>
bool throwsInvalidArgument(Fn fn) {
    try {
        fn();
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

}  // namespace

TEST_CASE("network setup: address and prefix validation") {
    NetworkSetup net("eth1");
    CHECK(throwsInvalidArgument([&] { net.setMulticastRoute("10.0.0.0/8"); }));
    CHECK(throwsInvalidArgument([&] { net.setMulticastRoute("224.0.0.0/3"); }));
    CHECK(throwsInvalidArgument([&] { net.setAddress("224.244.224.245/24"); }));
    CHECK(throwsInvalidArgument([&] { net.setAddress("10.0.0.20/33"); }));
    CHECK(throwsInvalidArgument([&] { net.setAddress("10.0.0.20/"); }));
    CHECK(throwsInvalidArgument([&] { net.setAddress("10.0.0/24"); }));
    net.setAddress("10.0.0.20/24");
    net.setMulticastRoute("224.244.224.245");  // host route for the SD address only
    CHECK(net.interfaceName() == "eth1");
}

TEST_CASE("network setup: missing interface is reported, nothing changed") {
    NetworkSetup net("ccg-no-such-if0");
    net.setMulticastRoute();
    CHECK(net.apply() == NetworkSetup::Result::NoDevice);
    CHECK(!net.lastError().empty());
    CHECK_EQ(net.applyCount(), 1U);
}
