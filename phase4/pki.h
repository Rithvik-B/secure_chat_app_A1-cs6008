// X.509 certificate handling: loading credentials, validating a peer cert
// against a CA, and RSA-SHA256 sign/verify for proof of possession.
// Uses <openssl/x509.h> and <openssl/evp.h> as building blocks; never ssl.h.

#pragma once

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstdint>
#include <string>
#include <vector>

namespace pki {

// Server credentials: private key plus its certificate (DER, for the wire).
struct ServerCreds {
    EVP_PKEY*            key = nullptr;
    std::vector<uint8_t> cert_der;
    ~ServerCreds();
};
bool load_server_creds(const std::string& cert_path, const std::string& key_path,
                       ServerCreds& out, std::string& err);

// A trust store built from the CA root certificate (the client's anchor).
struct TrustStore {
    X509_STORE* store = nullptr;
    ~TrustStore();
};
bool load_trust_store(const std::string& ca_path, TrustStore& out, std::string& err);

// The five outcomes of certificate validation, checked in this order.
enum class CertResult { Ok, BadEncoding, ChainUntrusted, Expired, WrongIdentity };
const char* result_str(CertResult r);

// Validates a peer certificate (DER) against the store and expected host, in
// order (chain -> validity -> identity). On Ok, *out_leaf is the parsed cert,
// which the caller must X509_free.
CertResult validate_cert(const std::vector<uint8_t>& cert_der, const TrustStore& ts,
                         const std::string& expected_host, X509** out_leaf,
                         std::string& detail);

// RSA-SHA256 signature over `data` with the private key (proof of possession).
bool sign(EVP_PKEY* key, const std::vector<uint8_t>& data, std::vector<uint8_t>& sig);

// Verifies `sig` over `data` with the certificate's public key.
bool verify_signature(X509* cert, const std::vector<uint8_t>& data,
                      const std::vector<uint8_t>& sig);

} // namespace pki
