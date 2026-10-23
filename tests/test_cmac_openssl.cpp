// Cross-check of the software AES-CMAC against OpenSSL (only built when
// OpenSSL is available; the gateway itself does not depend on it).
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <random>
#include <vector>

#include "ccg/crypto/aes_cmac.hpp"
#include "test_framework.hpp"

using namespace ccg::crypto;

namespace {

Block opensslCmac(const Block& key, const std::uint8_t* data, std::size_t length) {
    Block out{};
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "CMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    char cipher[] = "AES-128-CBC";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher, 0),
                           OSSL_PARAM_construct_end()};
    std::size_t len = 0;
    EVP_MAC_init(ctx, key.data(), key.size(), params);
    EVP_MAC_update(ctx, data, length);
    EVP_MAC_final(ctx, out.data(), &len, out.size());
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return out;
}

}  // namespace

TEST_CASE("aes-cmac: matches OpenSSL for random keys and lengths 0..200") {
    std::mt19937 rng(1234);
    std::uniform_int_distribution<int> byte(0, 255);
    for (std::size_t length = 0; length <= 200; ++length) {
        Block key;
        for (auto& b : key) b = static_cast<std::uint8_t>(byte(rng));
        std::vector<std::uint8_t> data(length);
        for (auto& b : data) b = static_cast<std::uint8_t>(byte(rng));
        CHECK(Cmac(key).compute(data.data(), data.size()) == opensslCmac(key, data.data(), data.size()));
    }
}
