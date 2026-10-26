#pragma once

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ccg::platform {

// Caller owns a private, trusted directory. A unique exclusive temporary file
// prevents pre-created .tmp links from redirecting secret writes. Success means
// both the contents and directory entry have reached durable storage.
inline bool atomicPrivateFile(const std::string& path, const std::string& data) {
    std::string pattern = path + ".tmp.XXXXXX";
    std::vector<char> tmp(pattern.begin(), pattern.end());
    tmp.push_back('\0');
    const int fd = ::mkstemp(tmp.data());
    if (fd < 0) return false;
    bool ok = ::fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 && ::fchmod(fd, 0600) == 0;
    std::size_t done = 0;
    while (ok && done < data.size()) {
        const auto n = ::write(fd, data.data() + done, data.size() - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        done += static_cast<std::size_t>(n);
    }
    ok = ok && ::fsync(fd) == 0;
    if (::close(fd) != 0) ok = false;
    if (!ok || ::rename(tmp.data(), path.c_str()) != 0) {
        ::unlink(tmp.data());
        return false;
    }
    const auto parent = std::filesystem::path(path).parent_path();
    const int dir = ::open(parent.empty() ? "." : parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir < 0) return false;
    ok = ::fsync(dir) == 0;
    if (::close(dir) != 0) ok = false;
    return ok;
}
} // namespace ccg::platform
