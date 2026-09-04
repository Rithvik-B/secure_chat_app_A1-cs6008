#include "dh.h"

#include <openssl/bn.h>
#include <openssl/rand.h>

#include <cstring>

namespace dh {

namespace {

// RFC 3526 group 14: the standard published 2048-bit MODP prime. Not generated.
const char* P_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

constexpr unsigned G = 2;

// base^exp mod mod, by hand as square-and-multiply. The assignment forbids
// BN_mod_exp; BN_mod_mul is used only to multiply-and-reduce. Reducing at every
// step is essential -- base^exp unreduced would dwarf any representable integer.
// Not constant-time (branches on exponent bits), fine for ephemeral local keys.
bool mod_exp(BIGNUM* result, const BIGNUM* base, const BIGNUM* exp,
             const BIGNUM* mod, BN_CTX* ctx)
{
    if (BN_is_zero(mod)) return false;

    BIGNUM* acc = BN_new();
    BIGNUM* b   = BN_new();
    if (!acc || !b) { BN_free(acc); BN_free(b); return false; }

    bool ok = BN_one(acc) && BN_nnmod(b, base, mod, ctx);

    for (int i = BN_num_bits(exp) - 1; ok && i >= 0; --i) {
        ok = BN_mod_mul(acc, acc, acc, mod, ctx);              // square
        if (ok && BN_is_bit_set(exp, i))
            ok = BN_mod_mul(acc, acc, b, mod, ctx);            // multiply
    }

    if (ok) ok = (BN_copy(result, acc) != nullptr);

    BN_clear_free(acc);
    BN_clear_free(b);
    return ok;
}

} // namespace

struct KeyPair::Impl {
    BIGNUM* p    = nullptr;
    BIGNUM* g    = nullptr;
    BIGNUM* priv = nullptr;
    BN_CTX* ctx  = nullptr;

    ~Impl()
    {
        BN_free(p);
        BN_free(g);
        BN_clear_free(priv);      // wipe the exponent, do not just release it
        BN_CTX_free(ctx);
    }
};

KeyPair::KeyPair() : p_(new Impl) {}
KeyPair::~KeyPair() { delete p_; }

KeyPair::KeyPair(KeyPair&& o) noexcept : p_(o.p_), pub_(std::move(o.pub_))
{
    o.p_ = nullptr;
}

KeyPair& KeyPair::operator=(KeyPair&& o) noexcept
{
    if (this != &o) {
        delete p_;
        p_ = o.p_;
        pub_ = std::move(o.pub_);
        o.p_ = nullptr;
    }
    return *this;
}

bool KeyPair::generate()
{
    if (!p_) return false;
    p_->ctx = BN_CTX_new();
    p_->g   = BN_new();
    if (!p_->ctx || !p_->g) return false;
    if (!BN_hex2bn(&p_->p, P_HEX)) return false;
    if (!BN_set_word(p_->g, G)) return false;

    p_->priv = BN_new();
    if (!p_->priv) return false;
    // Top bit set so the exponent is always a full PRIV_BITS wide.
    if (!BN_rand(p_->priv, PRIV_BITS, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
        return false;

    BIGNUM* pub = BN_new();
    if (!pub) return false;
    if (!mod_exp(pub, p_->g, p_->priv, p_->p, p_->ctx)) { BN_free(pub); return false; }

    pub_.assign(MODULUS_BYTES, 0);
    int n = BN_bn2binpad(pub, pub_.data(), static_cast<int>(MODULUS_BYTES));
    BN_free(pub);
    return n == static_cast<int>(MODULUS_BYTES);
}

bool KeyPair::compute_shared(const std::vector<uint8_t>& peer_pub,
                             std::vector<uint8_t>& secret) const
{
    if (peer_pub.size() != MODULUS_BYTES) return false;
    if (!p_ || !p_->p || !p_->priv) return false;

    BIGNUM* y = BN_bin2bn(peer_pub.data(), static_cast<int>(peer_pub.size()), nullptr);
    if (!y) return false;

    // Reject degenerate peer values. y in {0, 1, p-1} would give a shared secret
    // the peer can choose; anything >= p is not a group element at all.
    BIGNUM* pm1 = BN_new();
    bool ok = pm1 && BN_copy(pm1, p_->p) && BN_sub_word(pm1, 1);
    if (ok) {
        ok = BN_cmp(y, BN_value_one()) > 0 && BN_cmp(y, pm1) < 0;
    }

    BIGNUM* z = ok ? BN_new() : nullptr;
    if (z) ok = mod_exp(z, y, p_->priv, p_->p, p_->ctx);

    if (ok) {
        secret.assign(MODULUS_BYTES, 0);
        ok = BN_bn2binpad(z, secret.data(), static_cast<int>(MODULUS_BYTES))
             == static_cast<int>(MODULUS_BYTES);
    }

    BN_free(y);
    BN_free(pm1);
    BN_clear_free(z);
    return ok;
}

std::string prime_hex() { return P_HEX; }
unsigned    generator() { return G; }

bool mod_exp_hex(const std::string& base_hex, const std::string& exp_hex,
                 const std::string& mod_hex, std::string& out_hex)
{
    BIGNUM *b = nullptr, *e = nullptr, *m = nullptr, *r = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    bool ok = r && ctx
           && BN_hex2bn(&b, base_hex.c_str())
           && BN_hex2bn(&e, exp_hex.c_str())
           && BN_hex2bn(&m, mod_hex.c_str())
           && mod_exp(r, b, e, m, ctx);

    if (ok) {
        char* s = BN_bn2hex(r);
        ok = (s != nullptr);
        if (ok) { out_hex = s; OPENSSL_free(s); }
    }

    BN_free(b); BN_free(e); BN_free(m); BN_free(r); BN_CTX_free(ctx);
    return ok;
}

} // namespace dh
