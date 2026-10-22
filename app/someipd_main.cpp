// SOME/IP routing daemon of the IVI (Android: vendor.ccg.someipd).
//
// Hosts the vsomeip routing manager: it owns the SOME/IP-SD socket and the
// vehicle network endpoints, and every other vsomeip application on the IVI
// (Vehicle HAL, diagnostics, apps through a HAL) connects to it locally.
// Optionally keeps the SD multicast route on the vehicle network interface
// (see platform/linux/multicast_route.hpp).
//
//   ccg_someipd [--app routingmanagerd] [--sd-route IFACE [--sd-prefix 224.0.0.0/4]
//               [--sd-table 254]]
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

#include "multicast_route.hpp"

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
    std::string routeInterface;
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
        } else if (arg == "--sd-route" && hasValue) {
            opt.routeInterface = argv[++i];
        } else if (arg == "--sd-prefix" && hasValue) {
            opt.routePrefix = argv[++i];
        } else if (arg == "--sd-table" && hasValue) {
            opt.routeTable = static_cast<std::uint32_t>(std::stoul(argv[++i]));
        } else {
            std::fprintf(stderr,
                         "usage: %s [--app NAME] [--sd-route IFACE [--sd-prefix CIDR] "
                         "[--sd-table N]]\n",
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
    std::optional<ccg::platform::MulticastRoute> route;
    std::thread routeThread;
    if (!opt.routeInterface.empty()) {
        try {
            route.emplace(opt.routeInterface, opt.routePrefix, opt.routeTable);
        } catch (const std::exception& e) {
            log(true, "%s", e.what());
            return EXIT_FAILURE;
        }
        const auto first = route->install();
        log(first != ccg::platform::MulticastRoute::Result::Installed,
            "SD route %s dev %s table %u: %s %s", opt.routePrefix.c_str(),
            opt.routeInterface.c_str(), opt.routeTable, ccg::platform::toString(first),
            route->lastError().c_str());
        routeThread = std::thread([&] { route->supervise(running); });
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
    return EXIT_SUCCESS;
}
