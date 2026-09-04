#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>
#include <cstring>

namespace crypto {

namespace {

struct CipherCtx {
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    ~CipherCtx() { EVP_CIPHER_CTX_free(c); }
};

} // namespace

std::vector<uint8_t> sha256(const std::vector<uint8_t>& in)
{
    std::vector<uint8_t> out(32);
    unsigned len = 0;
    if (EVP_Digest(in.data(), in.size(), out.data(), &len, EVP_sha256(), nullptr) != 1)
        return {};
    out.resize(len);
    return out;
}

std::vector<uint8_t> sha256_labelled(const std::string& label,
                                     const std::vector<std::vector<uint8_t>>& parts)
{
    std::vector<uint8_t> buf(label.begin(), label.end());
    for (const auto& p : parts) buf.insert(buf.end(), p.begin(), p.end());
    return sha256(buf);
}

Nonce make_nonce(const Salt& salt, uint64_t seq)
{
    Nonce n{};
    std::memcpy(n.data(), salt.data(), SALT_LEN);
    for (int i = 0; i < 8; ++i)
        n[SALT_LEN + i] = static_cast<uint8_t>(seq >> (56 - 8 * i));
    return n;
}

bool seal(const Key& key, const Nonce& nonce, uint64_t seq,
          const uint8_t* plaintext, size_t pt_len,
          std::vector<uint8_t>& out)
{
    CipherCtx ctx;
    if (!ctx.c) return false;

    uint8_t aad[8];
    for (int i = 0; i < 8; ++i) aad[i] = static_cast<uint8_t>(seq >> (56 - 8 * i));

    out.assign(pt_len + TAG_LEN, 0);
    int len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx.c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx.c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1) return false;
    if (EVP_EncryptInit_ex(ctx.c, nullptr, nullptr, key.data(), nonce.data()) != 1) return false;
    if (EVP_EncryptUpdate(ctx.c, nullptr, &len, aad, sizeof aad) != 1) return false;
    if (pt_len > 0 &&
        EVP_EncryptUpdate(ctx.c, out.data(), &len, plaintext, static_cast<int>(pt_len)) != 1)
        return false;
    total = len;
    if (EVP_EncryptFinal_ex(ctx.c, out.data() + total, &len) != 1) return false;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx.c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, out.data() + total) != 1)
        return false;

    out.resize(static_cast<size_t>(total) + TAG_LEN);
    return true;
}

bool open(const Key& key, const Nonce& nonce, uint64_t seq,
          const uint8_t* record, size_t rec_len,
          std::vector<uint8_t>& plaintext)
{
    if (rec_len < TAG_LEN) return false;
    const size_t ct_len = rec_len - TAG_LEN;
    const uint8_t* tag  = record + ct_len;

    CipherCtx ctx;
    if (!ctx.c) return false;

    uint8_t aad[8];
    for (int i = 0; i < 8; ++i) aad[i] = static_cast<uint8_t>(seq >> (56 - 8 * i));

    std::vector<uint8_t> out(ct_len);
    int len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx.c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(ctx.c, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1) return false;
    if (EVP_DecryptInit_ex(ctx.c, nullptr, nullptr, key.data(), nonce.data()) != 1) return false;
    if (EVP_DecryptUpdate(ctx.c, nullptr, &len, aad, sizeof aad) != 1) return false;
    if (ct_len > 0 &&
        EVP_DecryptUpdate(ctx.c, out.data(), &len, record, static_cast<int>(ct_len)) != 1)
        return false;
    total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx.c, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                            const_cast<uint8_t*>(tag)) != 1)
        return false;

    // Returns <= 0 when the tag does not verify. Nothing is handed to the
    // caller in that case: a modified record is rejected, never processed.
    if (EVP_DecryptFinal_ex(ctx.c, out.data() + total, &len) <= 0) return false;
    total += len;

    out.resize(static_cast<size_t>(total));
    plaintext.swap(out);
    return true;
}

std::string hex(const uint8_t* p, size_t n)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 0x0f]; }
    return s;
}

bool random_bytes(uint8_t* out, size_t n)
{
    return RAND_bytes(out, static_cast<int>(n)) == 1;
}

} // namespace crypto
