#pragma once

// Minimal self-contained test harness (no external dependencies).

#include <cmath>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

namespace ccg::test {

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

inline int& failureCount() {
    static int count = 0;
    return count;
}

struct AbortTest {};

struct Registrar {
    Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

inline void fail(const char* file, int line, const std::string& message) {
    ++failureCount();
    std::cerr << "    " << file << ":" << line << ": " << message << "\n";
}

}  // namespace ccg::test

#define CCG_TEST_CONCAT_(a, b) a##b
#define CCG_TEST_CONCAT(a, b) CCG_TEST_CONCAT_(a, b)

#define TEST_CASE(name)                                                                  \
    static void CCG_TEST_CONCAT(ccgTestFn_, __LINE__)();                                 \
    static const ::ccg::test::Registrar CCG_TEST_CONCAT(ccgTestReg_, __LINE__)(          \
        name, &CCG_TEST_CONCAT(ccgTestFn_, __LINE__));                                   \
    static void CCG_TEST_CONCAT(ccgTestFn_, __LINE__)()

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) ::ccg::test::fail(__FILE__, __LINE__, "CHECK(" #cond ")"); \
    } while (0)

#define REQUIRE(cond)                                                       \
    do {                                                                    \
        if (!(cond)) {                                                      \
            ::ccg::test::fail(__FILE__, __LINE__, "REQUIRE(" #cond ")");    \
            throw ::ccg::test::AbortTest{};                                 \
        }                                                                   \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        const auto ccgA_ = (a);                                                            \
        const auto ccgB_ = (b);                                                            \
        if (!(ccgA_ == ccgB_)) {                                                           \
            ::ccg::test::fail(__FILE__, __LINE__,                                          \
                              "CHECK_EQ(" #a ", " #b "): " + std::to_string(ccgA_) +       \
                                  " != " + std::to_string(ccgB_));                         \
        }                                                                                  \
    } while (0)

#define CHECK_NEAR(a, b, eps)                                                              \
    do {                                                                                   \
        const double ccgA_ = static_cast<double>(a);                                       \
        const double ccgB_ = static_cast<double>(b);                                       \
        if (!(std::fabs(ccgA_ - ccgB_) <= (eps))) {                                        \
            ::ccg::test::fail(__FILE__, __LINE__,                                          \
                              "CHECK_NEAR(" #a ", " #b "): " + std::to_string(ccgA_) +     \
                                  " vs " + std::to_string(ccgB_));                         \
        }                                                                                  \
    } while (0)
