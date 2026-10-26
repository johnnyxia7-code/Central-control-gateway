#pragma once

#include "ccg/security/event_recorder.hpp"
#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <sstream>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ccg::platform {

// Bench persistence adapter. One writer per path in a private directory.
// Two bounded files, private permissions, no payloads/keys, synchronous durability.
// Vehicle integration must replace this with authenticated protected storage/SOC.
class SecurityJournal {
public:
    explicit SecurityJournal(std::string path, std::size_t maxBytes = 1024 * 1024)
        : path_(std::move(path)), maxBytes_(maxBytes), session_(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()) {}
    bool append(const security::EventRecord& e) {
        const auto ns = [](security::TimePoint t) {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()).count();
        };
        std::ostringstream out;
        out << "{\"session\":" << session_ << ",\"pid\":" << ::getpid()
            << ",\"sequence\":" << e.sequence << ",\"event\":" << static_cast<unsigned>(e.id)
            << ",\"source\":" << e.source << ",\"count\":" << e.count
            << ",\"first_monotonic_ns\":" << ns(e.first) << ",\"last_monotonic_ns\":" << ns(e.last) << "}\n";
        const auto line = out.str();
        if (line.size() > maxBytes_) return false;
        int fd = openFile();
        if (fd < 0) return false;
        struct stat st{};
        if (::fstat(fd, &st) != 0) { ::close(fd); return false; }
        if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > maxBytes_) { ::close(fd); return false; }
        char last = '\n';
        if (st.st_size && (::pread(fd, &last, 1, st.st_size - 1) != 1 || last != '\n')) {
            ::close(fd); return false; // torn journal needs explicit recovery, never append into a partial record
        }
        if (static_cast<std::uint64_t>(st.st_size) + line.size() > maxBytes_) {
            if (::close(fd) != 0) return false;
            if (::rename(path_.c_str(), (path_ + ".1").c_str()) != 0) return false;
            fd = openFile();
            if (fd < 0) return false;
            st.st_size = 0;
        }
        std::size_t done = 0;
        while (done < line.size()) {
            const auto n = ::write(fd, line.data() + done, line.size() - done);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            done += static_cast<std::size_t>(n);
        }
        if (done != line.size()) { // repair a partial write before a possible retry
            const bool repaired = ::ftruncate(fd, st.st_size) == 0 && ::fsync(fd) == 0;
            (void)repaired; // a failed repair is detected by the next open's trailing-newline check
        }
        bool ok = done == line.size() && ::fsync(fd) == 0;
        if (::close(fd) != 0) ok = false;
        const auto parent = std::filesystem::path(path_).parent_path();
        const int dir = ::open(parent.empty() ? "." : parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir < 0) return false;
        ok = (::fsync(dir) == 0) && ok;
        if (::close(dir) != 0) ok = false;
        return ok;
    }
private:
    int openFile() const {
        const int fd = ::open(path_.c_str(), O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
        if (fd < 0) return -1;
        struct stat st{};
        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != ::geteuid() ||
            st.st_nlink != 1 || (st.st_mode & 0077) != 0) {
            ::close(fd); return -1;
        }
        return fd;
    }
    std::string path_;
    std::size_t maxBytes_;
    std::int64_t session_;
};
} // namespace ccg::platform
