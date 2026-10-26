#include "security_journal.hpp"
#include "test_framework.hpp"
#include <fstream>

using namespace ccg;

TEST_CASE("IDPS journal: durable private bounded rotation survives reopen") {
    const auto path = "/tmp/ccg_journal_" + std::to_string(::getpid());
    ::unlink(path.c_str()); ::unlink((path + ".1").c_str());
    platform::SecurityJournal journal(path, 512);
    security::EventRecord e{1, security::EventId::SecOcMac, 3, 400, {}, {}};
    for (int i = 0; i < 10; ++i) { ++e.sequence; REQUIRE(journal.append(e)); }
    struct stat st{};
    REQUIRE(::stat(path.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == 0600); CHECK(st.st_size <= 512);
    REQUIRE(::stat((path + ".1").c_str(), &st) == 0); CHECK(st.st_size <= 512);
    platform::SecurityJournal reboot(path, 512); CHECK(reboot.append(e));
    std::ifstream in(path); std::string line; std::getline(in, line);
    CHECK(line.find("\"event\":1") != std::string::npos);
    CHECK(line.find("\"count\":400") != std::string::npos);
    ::unlink(path.c_str()); ::unlink((path + ".1").c_str());
}

TEST_CASE("IDPS journal: rejects symlink public file partial record and unavailable directory") {
    const auto path = "/tmp/ccg_journal_bad_" + std::to_string(::getpid());
    const auto victim = path + ".victim";
    ::unlink(path.c_str());
    { std::ofstream out(victim); out << "unchanged\n"; }
    REQUIRE(::symlink(victim.c_str(), path.c_str()) == 0);
    security::EventRecord e{1, security::EventId::SecOcMac, 0, 1, {}, {}};
    platform::SecurityJournal journal(path);
    CHECK(!journal.append(e));
    ::unlink(path.c_str());
    { std::ofstream out(path); out << "partial"; }
    REQUIRE(::chmod(path.c_str(), 0600) == 0); CHECK(!journal.append(e));
    { std::ofstream out(path); out << "complete\n"; }
    REQUIRE(::chmod(path.c_str(), 0644) == 0); CHECK(!journal.append(e));
    platform::SecurityJournal absent(path + "/missing/log"); CHECK(!absent.append(e));
    std::ifstream in(victim); std::string value; in >> value; CHECK(value == "unchanged");
    ::unlink(path.c_str()); ::unlink(victim.c_str());
}
