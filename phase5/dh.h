// Diffie-Hellman over the RFC 3526 2048-bit MODP group, from first principles.
// <openssl/dh.h> is not used; <openssl/bn.h> serves only as a big-integer type,
// with the modular exponentiation written by hand (see dh.cpp).

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace dh {

constexpr size_t MODULUS_BYTES = 256;   // 2048 bits
constexpr int    PRIV_BITS     = 256;   // ~128-bit security in a safe-prime group

// One side's ephemeral key pair. The private exponent is wiped on destruction.
class KeyPair {
public:
    KeyPair();
    ~KeyPair();
    KeyPair(const KeyPair&)            = delete;
    KeyPair& operator=(const KeyPair&) = delete;
    KeyPair(KeyPair&&) noexcept;                    // owns raw BIGNUMs
    KeyPair& operator=(KeyPair&&) noexcept;

    bool generate();                                // random x, then g^x mod p
    const std::vector<uint8_t>& public_value() const { return pub_; }

    // peer^x mod p, left-padded to MODULUS_BYTES so both sides serialise Z to
    // the same width. Rejects peer values in {0,1,p-1} that would fix the secret.
    bool compute_shared(const std::vector<uint8_t>& peer_pub,
                        std::vector<uint8_t>& secret) const;

private:
    struct Impl;
    Impl* p_;
    std::vector<uint8_t> pub_;
};

// Group parameters, for the report and for tests.
std::string prime_hex();
unsigned    generator();

// Exposed so the implementation can be tested directly against known values.
// result = base^exp mod mod, by square-and-multiply.
bool mod_exp_hex(const std::string& base_hex, const std::string& exp_hex,
                 const std::string& mod_hex, std::string& out_hex);

} // namespace dh
