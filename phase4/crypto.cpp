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

namespace {
const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
} // namespace

std::string b64_encode(const std::vector<uint8_t>& in)
{
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= in.size(); i += 3) {
        uint32_t n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out += B64[(n >> 18) & 63]; out += B64[(n >> 12) & 63];
        out += B64[(n >> 6) & 63];  out += B64[n & 63];
    }
    if (size_t rem = in.size() - i) {                 // 1 or 2 trailing bytes
        uint32_t n = in[i] << 16;
        if (rem == 2) n |= in[i + 1] << 8;
        out += B64[(n >> 18) & 63];
        out += B64[(n >> 12) & 63];
        out += (rem == 2) ? B64[(n >> 6) & 63] : '=';
        out += '=';
    }
    return out;
}

bool b64_decode(const std::string& in, std::vector<uint8_t>& out)
{
    out.clear();
    if (in.size() % 4 != 0) return false;
    for (size_t i = 0; i < in.size(); i += 4) {
        int a = b64val(in[i]), b = b64val(in[i + 1]);
        if (a < 0 || b < 0) return false;
        char c3 = in[i + 2], c4 = in[i + 3];
        out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        if (c3 != '=') {
            int c = b64val(c3);
            if (c < 0) return false;
            out.push_back(static_cast<uint8_t>((b << 4) | (c >> 2)));
            if (c4 != '=') {
                int d = b64val(c4);
                if (d < 0) return false;
                out.push_back(static_cast<uint8_t>((c << 6) | d));
            }
        } else if (c4 != '=') {
            return false;                             // '=' must be trailing
        }
    }
    return true;
}

} // namespace crypto
