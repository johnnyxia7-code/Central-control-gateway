// SOME/IP routing daemon of the IVI (Android: vendor.ccg.someipd).
//
// Hosts the vsomeip routing manager: it owns the SOME/IP-SD socket and the
// vehicle network endpoints, and every other vsomeip application on the IVI
// (Vehicle HAL, diagnostics, apps through a HAL) connects to it locally.
// With --net-if it also keeps the vehicle network interface usable: link up and
// address (--net-address, for an interface no network manager owns) and the
// SOME/IP-SD multicast route that Android lacks (platform/linux/network_setup.hpp).
//
//   ccg_someipd [--app routingmanagerd] [--net-if IFACE [--net-address 192.168.10.30/24]
//               [--sd-prefix 224.0.0.0/4] [--sd-table 254] [--no-sd-route]]
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <vsomeip/vsomeip.hpp>

#include "network_setup.hpp"

#ifdef __ANDROID__
#include <android/log.h>
#endif

namespace {

void log(bool error, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
#ifdef __ANDROID__
    __android_log_vprint(error ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, "ccg_someipd", fmt, args);
#else
    std::fprintf(stderr, error ? "[someipd] error: " : "[someipd] ");
    std::vfprintf(stderr, fmt, args);
    std::fprintf(stderr, "\n");
#endif
    va_end(args);
}

struct Options {
    std::string appName = "routingmanagerd";
    std::string netInterface;
    std::string netAddress;
    bool sdRoute = true;
    std::string routePrefix = "224.0.0.0/4";
    std::uint32_t routeTable = 254;
};

}  // namespace

int main(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const bool hasValue = i + 1 < argc;
        if (arg == "--app" && hasValue) {
            opt.appName = argv[++i];
        } else if (arg == "--net-if" && hasValue) {
            opt.netInterface = argv[++i];
        } else if (arg == "--net-address" && hasValue) {
            opt.netAddress = argv[++i];
        } else if (arg == "--no-sd-route") {
            opt.sdRoute = false;
        } else if (arg == "--sd-prefix" && hasValue) {
            opt.routePrefix = argv[++i];
        } else if (arg == "--sd-table" && hasValue) {
            opt.routeTable = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        } else {
            std::fprintf(stderr,
                         "usage: %s [--app NAME] [--net-if IFACE [--net-address CIDR] "
                         "[--sd-prefix CIDR] [--sd-table N] [--no-sd-route]]\n",
                         argv[0]);
            return EXIT_FAILURE;
        }
    }

    // All threads (incl. the ones vsomeip creates) inherit the blocked mask;
    // termination signals are taken synchronously below.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    std::atomic<bool> running{true};
    std::optional<ccg::platform::NetworkSetup> network;
    std::thread routeThread;
    if (!opt.netInterface.empty()) {
        try {
            network.emplace(opt.netInterface);
            if (!opt.netAddress.empty()) network->setAddress(opt.netAddress);
            if (opt.sdRoute) network->setMulticastRoute(opt.routePrefix, opt.routeTable);
        } catch (const std::exception& e) {
            log(true, "%s", e.what());
            return EXIT_FAILURE;
        }
        const auto first = network->apply();
        log(first != ccg::platform::NetworkSetup::Result::Ok,
            "network %s: address %s, SD route %s (table %u): %s %s", opt.netInterface.c_str(),
            opt.netAddress.empty() ? "unmanaged" : opt.netAddress.c_str(),
            opt.sdRoute ? opt.routePrefix.c_str() : "off", opt.routeTable,
            ccg::platform::toString(first), network->lastError().c_str());
        routeThread = std::thread([&] { network->supervise(running); });
    }

    auto app = vsomeip::runtime::get()->create_application(opt.appName);
    if (!app || !app->init()) {
        log(true, "vsomeip application '%s' could not be initialised (VSOMEIP_CONFIGURATION?)",
            opt.appName.c_str());
        running = false;
        if (routeThread.joinable()) routeThread.join();
        return EXIT_FAILURE;
    }
    if (!app->is_routing()) {
        log(true, "'%s' is not configured as \"routing\" in the vsomeip configuration",
            opt.appName.c_str());
        running = false;
        if (routeThread.joinable()) routeThread.join();
        return EXIT_FAILURE;
    }

    std::thread signalThread([&] {
        int sig = 0;
        sigwait(&mask, &sig);
        log(false, "signal %d, stopping", sig);
        running = false;
        app->stop();
    });

    log(false, "routing manager '%s' started", opt.appName.c_str());
    app->start();  // returns after stop()

    if (running) {
        // start() returned without a signal: wake the signal thread.
        running = false;
        ::kill(::getpid(), SIGTERM);
    }
    signalThread.join();
    if (routeThread.joinable()) routeThread.join();
    if (network) log(false, "network setup applied %u times", network->applyCount());
    return EXIT_SUCCESS;
}
