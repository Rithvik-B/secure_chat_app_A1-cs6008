#include "pki.h"

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <cstdio>

namespace pki {

namespace {

std::vector<uint8_t> read_file(const std::string& path, bool& ok)
{
    ok = false;
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return {};
    std::vector<uint8_t> buf;
    uint8_t chunk[4096];
    size_t n;
    while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0)
        buf.insert(buf.end(), chunk, chunk + n);
    std::fclose(f);
    ok = true;
    return buf;
}

X509* parse_cert_der(const std::vector<uint8_t>& der)
{
    const unsigned char* p = der.data();
    return d2i_X509(nullptr, &p, static_cast<long>(der.size()));
}

} // namespace

ServerCreds::~ServerCreds() { EVP_PKEY_free(key); }
TrustStore::~TrustStore()   { X509_STORE_free(store); }

const char* result_str(CertResult r)
{
    switch (r) {
    case CertResult::Ok:             return "ok";
    case CertResult::BadEncoding:    return "certificate did not parse";
    case CertResult::ChainUntrusted: return "not signed by the trusted CA";
    case CertResult::Expired:        return "outside its validity period";
    case CertResult::WrongIdentity:  return "identity does not match expected server";
    }
    return "unknown";
}

bool load_server_creds(const std::string& cert_path, const std::string& key_path,
                       ServerCreds& out, std::string& err)
{
    bool ok;
    auto keybuf = read_file(key_path, ok);
    if (!ok) { err = "cannot read key file " + key_path; return false; }

    BIO* kb = BIO_new_mem_buf(keybuf.data(), static_cast<int>(keybuf.size()));
    out.key = PEM_read_bio_PrivateKey(kb, nullptr, nullptr, nullptr);
    BIO_free(kb);
    if (!out.key) { err = "cannot parse private key " + key_path; return false; }

    auto certbuf = read_file(cert_path, ok);
    if (!ok) { err = "cannot read cert file " + cert_path; return false; }

    BIO* cb = BIO_new_mem_buf(certbuf.data(), static_cast<int>(certbuf.size()));
    X509* cert = PEM_read_bio_X509(cb, nullptr, nullptr, nullptr);
    BIO_free(cb);
    if (!cert) { err = "cannot parse certificate " + cert_path; return false; }

    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    if (len <= 0) { X509_free(cert); err = "cannot DER-encode certificate"; return false; }
    out.cert_der.assign(der, der + len);
    OPENSSL_free(der);
    X509_free(cert);
    return true;
}

bool load_trust_store(const std::string& ca_path, TrustStore& out, std::string& err)
{
    out.store = X509_STORE_new();
    if (!out.store) { err = "cannot allocate trust store"; return false; }
    if (X509_STORE_load_locations(out.store, ca_path.c_str(), nullptr) != 1) {
        err = "cannot load CA file " + ca_path;
        return false;
    }
    return true;
}

CertResult validate_cert(const std::vector<uint8_t>& cert_der, const TrustStore& ts,
                         const std::string& expected_host, X509** out_leaf,
                         std::string& detail)
{
    *out_leaf = nullptr;
    X509* cert = parse_cert_der(cert_der);
    if (!cert) { detail = "d2i_X509 failed"; return CertResult::BadEncoding; }

    // 1. Chain: signed by the trusted CA. X509_verify_cert also checks the
    //    validity window, so an expired cert fails here -- separate that error
    //    out (check b) from a genuine untrusted-chain error (check a).
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    int verr = X509_V_OK;
    bool chain_ok = ctx && X509_STORE_CTX_init(ctx, ts.store, cert, nullptr) == 1
                        && X509_verify_cert(ctx) == 1;
    if (!chain_ok && ctx) {
        verr = X509_STORE_CTX_get_error(ctx);
        detail = X509_verify_cert_error_string(verr);
    }
    X509_STORE_CTX_free(ctx);
    if (!chain_ok) {
        X509_free(cert);
        if (verr == X509_V_ERR_CERT_HAS_EXPIRED || verr == X509_V_ERR_CERT_NOT_YET_VALID)
            return CertResult::Expired;
        return CertResult::ChainUntrusted;
    }

    // 2. Validity window (redundant with the chain check above, kept explicit).
    if (X509_cmp_current_time(X509_get0_notBefore(cert)) > 0 ||
        X509_cmp_current_time(X509_get0_notAfter(cert)) < 0) {
        detail = "notBefore/notAfter check failed";
        X509_free(cert);
        return CertResult::Expired;
    }

    // 3. Identity matches the expected server name (SAN or CN).
    if (X509_check_host(cert, expected_host.c_str(), expected_host.size(), 0, nullptr) != 1) {
        detail = "no SAN/CN matches " + expected_host;
        X509_free(cert);
        return CertResult::WrongIdentity;
    }

    *out_leaf = cert;
    detail = "chain, validity and identity all pass";
    return CertResult::Ok;
}

bool sign(EVP_PKEY* key, const std::vector<uint8_t>& data, std::vector<uint8_t>& sig)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1;

    size_t len = 0;
    ok = ok && EVP_DigestSign(ctx, nullptr, &len, data.data(), data.size()) == 1;
    if (ok) {
        sig.resize(len);
        ok = EVP_DigestSign(ctx, sig.data(), &len, data.data(), data.size()) == 1;
        if (ok) sig.resize(len);
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool verify_signature(X509* cert, const std::vector<uint8_t>& data,
                      const std::vector<uint8_t>& sig)
{
    EVP_PKEY* pub = X509_get_pubkey(cert);
    if (!pub) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = ctx && EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pub) == 1
                  && EVP_DigestVerify(ctx, sig.data(), sig.size(),
                                      data.data(), data.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pub);
    return ok;
}

} // namespace pki
