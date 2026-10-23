#pragma once

#include "ccg/keym/key_master.hpp"

// Key generation from the kernel CSPRNG (getrandom). On the target the HSM's
// TRNG generates the keys inside the HSM.
namespace ccg::platform {

class SystemRandom final : public keym::IRandom {
public:
    crypto::Block randomKey() override;  // throws std::runtime_error if the kernel fails
};

}  // namespace ccg::platform
