#include "system_random.hpp"

#include <sys/random.h>

#include <cerrno>
#include <stdexcept>

namespace ccg::platform {

crypto::Block SystemRandom::randomKey() {
    crypto::Block key{};
    std::size_t done = 0;
    while (done < key.size()) {
        const ssize_t n = ::getrandom(key.data() + done, key.size() - done, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("getrandom failed");
        }
        done += static_cast<std::size_t>(n);
    }
    return key;
}

}  // namespace ccg::platform
