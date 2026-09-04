// SHA-256 helpers and AES-256-GCM, built on OpenSSL's EVP primitives.

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {

constexpr size_t KEY_LEN   = 32;
constexpr size_t NONCE_LEN = 12;
constexpr size_t TAG_LEN   = 16;
constexpr size_t SALT_LEN  = 4;

using Key   = std::array<uint8_t, KEY_LEN>;
using Salt  = std::array<uint8_t, SALT_LEN>;
using Nonce = std::array<uint8_t, NONCE_LEN>;

std::vector<uint8_t> sha256(const std::vector<uint8_t>& in);

// SHA-256(label || parts...). The label keeps derivations from the same secret
// (key vs fingerprint) distinct.
std::vector<uint8_t> sha256_labelled(const std::string& label,
                                     const std::vector<std::vector<uint8_t>>& parts);

// nonce = salt(4) || seq(8, big-endian). Never derived twice for one key.
Nonce make_nonce(const Salt& salt, uint64_t seq);

// out = ciphertext || tag. `seq` is authenticated as additional data, so a
// record moved to a different position in the stream fails to verify.
bool seal(const Key& key, const Nonce& nonce, uint64_t seq,
          const uint8_t* plaintext, size_t pt_len,
          std::vector<uint8_t>& out);

// Returns false on any authentication failure; `plaintext` is left untouched.
bool open(const Key& key, const Nonce& nonce, uint64_t seq,
          const uint8_t* record, size_t rec_len,
          std::vector<uint8_t>& plaintext);

std::string hex(const uint8_t* p, size_t n);
bool random_bytes(uint8_t* out, size_t n);

} // namespace crypto
