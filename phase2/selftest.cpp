// Self-tests for the from-scratch Diffie-Hellman and the AES-256-GCM layer.
//
//   ./selftest          run all checks
//
// The DH check confirms the hand-written modular exponentiation agrees with
// OpenSSL's BN_mod_exp on random inputs -- a reference used only to verify the
// result, never in the handshake itself -- and that two independently generated
// key pairs reach the same shared secret. The AEAD check confirms that a
// single flipped byte anywhere in a record makes decryption fail.

#include "crypto.h"
#include "dh.h"

#include <openssl/bn.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

int failures = 0;
void check(bool ok, const char* what)
{
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

// Reference exponentiation, for comparison only.
std::string ref_mod_exp(const std::string& b, const std::string& e, const std::string& m)
{
    BIGNUM *B=nullptr,*E=nullptr,*M=nullptr,*R=BN_new();
    BN_CTX* c = BN_CTX_new();
    BN_hex2bn(&B,b.c_str()); BN_hex2bn(&E,e.c_str()); BN_hex2bn(&M,m.c_str());
    BN_mod_exp(R,B,E,M,c);
    char* s = BN_bn2hex(R);
    std::string out = s;
    OPENSSL_free(s); BN_free(B); BN_free(E); BN_free(M); BN_free(R); BN_CTX_free(c);
    return out;
}

bool eq_hex(const std::string& a, const std::string& b)
{
    BIGNUM *x=nullptr,*y=nullptr;
    BN_hex2bn(&x,a.c_str()); BN_hex2bn(&y,b.c_str());
    bool r = BN_cmp(x,y)==0;
    BN_free(x); BN_free(y);
    return r;
}

} // namespace

int main()
{
    std::printf("DH group\n");
    {
        BIGNUM* p = nullptr; BN_hex2bn(&p, dh::prime_hex().c_str());
        BN_CTX* c = BN_CTX_new();
        check(BN_num_bits(p) == 2048, "prime is 2048 bits");
        check(BN_check_prime(p, c, nullptr) == 1, "modulus is prime");
        BIGNUM* q = BN_new(); BN_copy(q,p); BN_sub_word(q,1); BN_rshift1(q,q);
        check(BN_check_prime(q, c, nullptr) == 1, "(p-1)/2 is prime (safe prime)");
        check(dh::generator() == 2, "generator is 2");
        BN_free(p); BN_free(q); BN_CTX_free(c);
    }

    std::printf("hand-written modular exponentiation vs OpenSSL reference\n");
    {
        const std::string P = dh::prime_hex();
        bool all = true;
        const char* exps[] = {"0","1","2","3","FF","10001",
                              "0123456789ABCDEF0123456789ABCDEF"};
        for (const char* e : exps) {
            std::string got;
            all &= dh::mod_exp_hex("2", e, P, got);
            all &= eq_hex(got, ref_mod_exp("2", e, P));
        }
        check(all, "2^e mod p matches for a range of exponents");
    }

    std::printf("full key agreement\n");
    {
        dh::KeyPair a, b;
        bool ok = a.generate() && b.generate();
        std::vector<uint8_t> za, zb;
        ok = ok && a.compute_shared(b.public_value(), za);
        ok = ok && b.compute_shared(a.public_value(), zb);
        check(ok && za == zb && za.size() == dh::MODULUS_BYTES,
              "two key pairs derive the identical shared secret");

        std::vector<uint8_t> bad(dh::MODULUS_BYTES, 0);   // y = 0, degenerate
        std::vector<uint8_t> z;
        check(!a.compute_shared(bad, z), "peer value 0 is rejected");
    }

    std::printf("AES-256-GCM\n");
    {
        crypto::Key key{}; crypto::Salt salt{};
        for (size_t i=0;i<key.size();++i) key[i]=static_cast<uint8_t>(i);
        salt = {1,2,3,4};

        std::string msg = "the quick brown fox jumps over the lazy dog";
        auto nonce = crypto::make_nonce(salt, 7);
        std::vector<uint8_t> sealed;
        bool ok = crypto::seal(key, nonce, 7,
                               reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), sealed);

        std::vector<uint8_t> pt;
        ok = ok && crypto::open(key, nonce, 7, sealed.data(), sealed.size(), pt);
        check(ok && std::string(pt.begin(),pt.end()) == msg, "seal then open round-trips");

        // Flip each byte in turn; every one must break authentication.
        bool every = true;
        for (size_t i=0;i<sealed.size();++i) {
            auto bad = sealed; bad[i] ^= 0x01;
            std::vector<uint8_t> out;
            if (crypto::open(key, nonce, 7, bad.data(), bad.size(), out)) every = false;
        }
        check(every, "any single-byte modification is rejected");

        // Right key, wrong sequence number -> wrong nonce and AAD -> rejected.
        std::vector<uint8_t> out;
        check(!crypto::open(key, crypto::make_nonce(salt, 8), 8,
                            sealed.data(), sealed.size(), out),
              "a record replayed at the wrong position is rejected");
    }

    std::printf("\n%s\n", failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return failures == 0 ? 0 : 1;
}
