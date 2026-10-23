// Backend key server tool (bench): builds the SHE memory update messages
// M1..M3 for a key update of the gateway and checks the returned M4/M5.
//
//   ccg_key_tool --uid 000000000000004343470000000001 --slot 6 --auth-slot 1
//                --auth-key <32 hex> --key <32 hex> --counter 2 [--flags 03]
//                [--check <M4|M5 or the complete 71 01 F2 00 .. response>]
//
// Prints M1..M3 and the UDS request (31 01 F2 00 M1 M2 M3) to send to the
// gateway's diagnostic address, and the M4/M5 the gateway must answer.
// Flags (FID): 10 write protection, 08 boot, 04 debugger, 02 key usage (MAC
// key, required for SecOC keys), 01 wildcard UID forbidden. Default 03.
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "ccg/keym/she.hpp"

namespace {

using namespace ccg;
namespace she = ccg::keym::she;

std::vector<std::uint8_t> parseHex(std::string hex, std::size_t bytes, const char* what) {
    std::string clean;
    for (const char c : hex) {
        if (c != ' ' && c != ':') clean.push_back(c);
    }
    if (bytes != 0 && clean.size() != 2 * bytes) {
        throw std::invalid_argument(std::string(what) + ": expected " + std::to_string(bytes) + " bytes in hex");
    }
    if (clean.size() % 2 != 0) throw std::invalid_argument(std::string(what) + ": odd number of hex digits");
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i < clean.size(); i += 2) {
        std::size_t used = 0;
        const auto v = std::stoul(clean.substr(i, 2), &used, 16);
        if (used != 2) throw std::invalid_argument(std::string(what) + ": not hex");
        out.push_back(static_cast<std::uint8_t>(v));
    }
    return out;
}

template <typename Container>
std::string hex(const Container& c) {
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (const auto b : c) os << std::setw(2) << int{b};
    return os.str();
}

crypto::Block block(const std::string& text, const char* what) {
    const auto v = parseHex(text, 16, what);
    crypto::Block b;
    std::copy(v.begin(), v.end(), b.begin());
    return b;
}

}  // namespace

int main(int argc, char** argv) {
    she::Uid uid{};
    int slot = -1;
    int authSlot = -1;
    std::string authKeyText;
    std::string keyText;
    long long counter = -1;
    std::uint8_t flags = 0x03;
    std::string check;
    try {
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (i + 1 >= argc) throw std::invalid_argument("missing value for " + arg);
            const std::string value = argv[++i];
            if (arg == "--uid") {
                const auto v = parseHex(value, uid.size(), "--uid");
                std::copy(v.begin(), v.end(), uid.begin());
            } else if (arg == "--slot") {
                slot = std::stoi(value, nullptr, 0);
            } else if (arg == "--auth-slot") {
                authSlot = std::stoi(value, nullptr, 0);
            } else if (arg == "--auth-key") {
                authKeyText = value;
            } else if (arg == "--key") {
                keyText = value;
            } else if (arg == "--counter") {
                counter = std::stoll(value, nullptr, 0);
            } else if (arg == "--flags") {
                flags = parseHex(value, 1, "--flags")[0];
            } else if (arg == "--check") {
                check = value;
            } else {
                throw std::invalid_argument("unknown argument " + arg);
            }
        }
        if (slot < 1 || slot > 0xD || authSlot < 1 || authSlot > 0xD) {
            throw std::invalid_argument("--slot and --auth-slot must be 1 (MASTER_ECU_KEY) or 4..13 (KEY_1..KEY_10)");
        }
        if (counter < 1 || counter > she::kMaxCounter) throw std::invalid_argument("--counter must be 1..2^28-1");
        if (flags > 0x1F) throw std::invalid_argument("--flags is a 5-bit value");
        if (authKeyText.empty() || keyText.empty()) throw std::invalid_argument("--auth-key and --key are required");

        const auto authKey = block(authKeyText, "--auth-key");
        const auto newKey = block(keyText, "--key");
        const auto s = static_cast<std::uint8_t>(slot);
        const auto a = static_cast<std::uint8_t>(authSlot);
        const auto c = static_cast<std::uint32_t>(counter);
        const auto request = she::buildUpdate(uid, s, a, authKey, newKey, c, she::Flags::decode(flags));
        const auto proof = she::buildProof(uid, s, a, newKey, c);

        std::cout << "M1  " << hex(request.m1) << "\n"
                  << "M2  " << hex(request.m2) << "\n"
                  << "M3  " << hex(request.m3) << "\n"
                  << "UDS 3101f200" << hex(request.m1) << hex(request.m2) << hex(request.m3) << "\n"
                  << "expected M4  " << hex(proof.m4) << "\n"
                  << "expected M5  " << hex(proof.m5) << "\n";

        if (!check.empty()) {
            auto received = parseHex(check, 0, "--check");
            // Complete routine response: 71 01 F2 00 <SHE error code> M4 M5
            if (received.size() == 5 + 48 && received[0] == 0x71) {
                received.erase(received.begin(), received.begin() + 5);
            } else if (received.size() == 5 && received[0] == 0x71) {
                std::cout << "gateway refused the update: " << she::toString(static_cast<she::ErrorCode>(received[4]))
                          << "\n";
                return 2;
            }
            std::vector<std::uint8_t> expected(proof.m4.begin(), proof.m4.end());
            expected.insert(expected.end(), proof.m5.begin(), proof.m5.end());
            if (received != expected) {
                std::cout << "M4/M5 MISMATCH - key not confirmed\n";
                return 2;
            }
            std::cout << "M4/M5 verified - slot " << slot << " holds the new key (counter " << c << ")\n";
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\nusage: " << argv[0]
                  << " --uid HEX --slot N --auth-slot N --auth-key HEX --key HEX --counter N [--flags HEX]"
                     " [--check HEX]\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
