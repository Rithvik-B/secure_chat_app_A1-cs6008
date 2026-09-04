// Exercises pki::validate_cert against a CA, printing the result. Used by the
// PKI validation test to show each check (chain / validity / identity) rejecting
// the appropriate bad certificate.
//   certcheck --ca ca.pem --cert C.pem [--expect chatserver.local]

#include "pki.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

static std::vector<uint8_t> slurp(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

// A PEM certificate must be turned into DER for validate_cert; reuse OpenSSL.
#include <openssl/pem.h>
static std::vector<uint8_t> pem_to_der(const std::string& path, bool& ok)
{
    ok = false;
    auto pem = slurp(path);
    BIO* b = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    X509* c = PEM_read_bio_X509(b, nullptr, nullptr, nullptr);
    BIO_free(b);
    if (!c) return {};
    unsigned char* der = nullptr;
    int n = i2d_X509(c, &der);
    X509_free(c);
    if (n <= 0) return {};
    std::vector<uint8_t> out(der, der + n);
    OPENSSL_free(der);
    ok = true;
    return out;
}

int main(int argc, char** argv)
{
    std::string ca, cert, expect = "chatserver.local";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--ca"     && i + 1 < argc) ca = argv[++i];
        else if (a == "--cert"   && i + 1 < argc) cert = argv[++i];
        else if (a == "--expect" && i + 1 < argc) expect = argv[++i];
    }
    if (ca.empty() || cert.empty()) {
        std::fprintf(stderr, "usage: %s --ca F --cert F [--expect NAME]\n", argv[0]);
        return 2;
    }

    pki::TrustStore ts;
    std::string err;
    if (!pki::load_trust_store(ca, ts, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }

    bool ok;
    auto der = pem_to_der(cert, ok);
    if (!ok) { std::printf("REJECT  %-24s : cannot parse certificate\n", cert.c_str()); return 0; }

    X509* leaf = nullptr;
    std::string detail;
    auto r = pki::validate_cert(der, ts, expect, &leaf, detail);
    if (leaf) X509_free(leaf);

    std::printf("%-7s %-24s : %s\n",
                r == pki::CertResult::Ok ? "ACCEPT" : "REJECT",
                cert.c_str(), pki::result_str(r));
    return 0;
}
