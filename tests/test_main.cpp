#include <cstring>
#include <exception>

#include "test_framework.hpp"

int main(int argc, char** argv) {
    using namespace ccg::test;
    const char* filter = argc > 1 ? argv[1] : nullptr;
    int run = 0;
    int failedTests = 0;
    for (const auto& t : registry()) {
        if (filter && t.name.find(filter) == std::string::npos) {
            continue;
        }
        ++run;
        const int before = failureCount();
        try {
            t.fn();
        } catch (const AbortTest&) {
        } catch (const std::exception& e) {
            fail(__FILE__, __LINE__, std::string("unexpected exception: ") + e.what());
        }
        const bool ok = failureCount() == before;
        if (!ok) ++failedTests;
        std::cout << (ok ? "[ PASS ] " : "[ FAIL ] ") << t.name << "\n";
    }
    std::cout << "\n" << run - failedTests << "/" << run << " tests passed\n";
    return failedTests == 0 ? 0 : 1;
}
