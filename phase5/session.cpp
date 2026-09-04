#include "session.h"
#include "proto.h"

#include <sys/socket.h>      // shutdown, SHUT_RDWR

#include <cstring>

namespace sec {

namespace {

void put_u16(std::vector<uint8_t>& v, uint16_t n)
{
    v.push_back(static_cast<uint8_t>(n >> 8));
    v.push_back(static_cast<uint8_t>(n & 0xff));
}

bool get_u16(const uint8_t* p, size_t n, size_t off, uint16_t& out)
{
    if (off + 2 > n) return false;
    out = static_cast<uint16_t>((p[off] << 8) | p[off + 1]);
    return true;
}

} // namespace

std::vector<uint8_t> transcript_hash(uint8_t version,
                                     const std::vector<uint8_t>& client_random,
                                     const std::vector<uint8_t>& cert_der,
                                     const std::vector<uint8_t>& server_pub,
                                     const std::vector<uint8_t>& client_pub)
{
    return crypto::sha256_labelled("", {{version}, client_random, cert_der,
                                        server_pub, client_pub});
}

std::vector<uint8_t> proof_transcript(uint8_t version,
                                      const std::vector<uint8_t>& client_random,
                                      const std::vector<uint8_t>& cert_der,
                                      const std::vector<uint8_t>& server_pub)
{
    std::vector<uint8_t> v{version};
    v.insert(v.end(), client_random.begin(), client_random.end());
    v.insert(v.end(), cert_der.begin(), cert_der.end());
    v.insert(v.end(), server_pub.begin(), server_pub.end());
    return v;
}

Keys derive_keys(const std::vector<uint8_t>& z, const std::vector<uint8_t>& th)
{
    Keys k;
    auto c2s  = crypto::sha256_labelled("CS6008-P2-KEY|c2s|",  {z, th});
    auto s2c  = crypto::sha256_labelled("CS6008-P2-KEY|s2c|",  {z, th});
    auto salt = crypto::sha256_labelled("CS6008-P2-SALT|",     {z, th});
    auto fp   = crypto::sha256_labelled("CS6008-P2-FP|",       {z, th});

    std::memcpy(k.c2s.data(),  c2s.data(),  crypto::KEY_LEN);
    std::memcpy(k.s2c.data(),  s2c.data(),  crypto::KEY_LEN);
    std::memcpy(k.salt.data(), salt.data(), crypto::SALT_LEN);
    k.fingerprint = crypto::hex(fp.data(), 8);
    return k;
}

// ------------------------------------------------------------------ Session

void Session::install(const Keys& k, Role r)
{
    keys_ = k;
    role_ = r;
    up_   = true;
    tx_ = rx_ = 0;
}

bool Session::seal(const std::string& plaintext, std::vector<uint8_t>& out)
{
    if (!up_) return false;
    const crypto::Key& k = (role_ == Role::Client) ? keys_.c2s : keys_.s2c;
    auto nonce = crypto::make_nonce(keys_.salt, tx_);
    if (!crypto::seal(k, nonce, tx_,
                      reinterpret_cast<const uint8_t*>(plaintext.data()),
                      plaintext.size(), out))
        return false;
    ++tx_;
    return true;
}

bool Session::open(const uint8_t* body, size_t n, std::string& plaintext)
{
    if (!up_) return false;
    const crypto::Key& k = (role_ == Role::Client) ? keys_.s2c : keys_.c2s;
    auto nonce = crypto::make_nonce(keys_.salt, rx_);
    std::vector<uint8_t> pt;
    if (!crypto::open(k, nonce, rx_, body, n, pt)) return false;
    ++rx_;
    plaintext.assign(pt.begin(), pt.end());
    return true;
}

// ---------------------------------------------------------------- encoding

std::vector<uint8_t> make_client_hello(uint8_t version,
                                       const std::vector<uint8_t>& client_random)
{
    std::vector<uint8_t> v{proto::HS_CLIENT_HELLO, version};
    v.insert(v.end(), client_random.begin(), client_random.end());
    return v;
}

std::vector<uint8_t> make_server_cert(const std::vector<uint8_t>& cert_der)
{
    std::vector<uint8_t> v{proto::HS_SERVER_CERT};
    put_u16(v, static_cast<uint16_t>(cert_der.size()));
    v.insert(v.end(), cert_der.begin(), cert_der.end());
    return v;
}

std::vector<uint8_t> make_server_kex(uint8_t version,
                                     const std::vector<uint8_t>& server_pub)
{
    std::vector<uint8_t> v{proto::HS_SERVER_KEX, version};
    put_u16(v, static_cast<uint16_t>(server_pub.size()));
    v.insert(v.end(), server_pub.begin(), server_pub.end());
    return v;
}

std::vector<uint8_t> make_server_proof(const std::vector<uint8_t>& sig)
{
    std::vector<uint8_t> v{proto::HS_SERVER_PROOF};
    put_u16(v, static_cast<uint16_t>(sig.size()));
    v.insert(v.end(), sig.begin(), sig.end());
    return v;
}

std::vector<uint8_t> make_client_kex(const std::vector<uint8_t>& client_pub)
{
    std::vector<uint8_t> v{proto::HS_CLIENT_KEX};
    put_u16(v, static_cast<uint16_t>(client_pub.size()));
    v.insert(v.end(), client_pub.begin(), client_pub.end());
    return v;
}

// ---------------------------------------------------------- ServerHandshake

void ServerHandshake::set_credentials(const std::vector<uint8_t>& cert_der, EVP_PKEY* key)
{
    cert_der_ = cert_der;
    key_      = key;
}

ServerHandshake::Status ServerHandshake::feed(const uint8_t* body, size_t n,
                                              std::vector<std::vector<uint8_t>>& replies,
                                              std::string& err)
{
    if (n < 1) { err = "empty handshake record"; return Status::Failed; }
    const uint8_t hstype = body[0];

    switch (step_) {
    case Step::AwaitClientHello: {
        if (hstype != proto::HS_CLIENT_HELLO) { err = "expected ClientHello"; return Status::Failed; }
        if (n != 2 + proto::CLIENT_RANDOM_LEN) { err = "bad ClientHello length"; return Status::Failed; }
        if (body[1] != proto::VERSION) { err = "version mismatch"; return Status::Failed; }
        if (cert_der_.empty() || !key_) { err = "server has no credentials"; return Status::Failed; }

        client_random_.assign(body + 2, body + n);
        if (!kp_.generate()) { err = "DH keygen failed"; return Status::Failed; }
        server_pub_ = kp_.public_value();

        // Sign version || client_random || cert || server_pub with the server
        // key. Only the holder of the private key can produce this signature.
        auto tosign = proof_transcript(proto::VERSION, client_random_, cert_der_, server_pub_);
        std::vector<uint8_t> sig;
        if (!pki::sign(key_, tosign, sig)) { err = "signing failed"; return Status::Failed; }

        // Cert first, then the DH value, then the proof over both.
        replies.push_back(make_server_cert(cert_der_));
        replies.push_back(make_server_kex(proto::VERSION, server_pub_));
        replies.push_back(make_server_proof(sig));
        step_ = Step::AwaitClientKex;
        return Status::NeedMore;
    }

    case Step::AwaitClientKex: {
        if (hstype != proto::HS_CLIENT_KEX) { err = "expected ClientKex"; return Status::Failed; }
        uint16_t len = 0;
        if (!get_u16(body, n, 1, len) || 3u + len != n || len != dh::MODULUS_BYTES) {
            err = "bad ClientKex length";
            return Status::Failed;
        }
        std::vector<uint8_t> client_pub(body + 3, body + n);

        std::vector<uint8_t> z;
        if (!kp_.compute_shared(client_pub, z)) {
            err = "invalid client public value";   // rejected before any key use
            return Status::Failed;
        }

        auto th = transcript_hash(proto::VERSION, client_random_, cert_der_, server_pub_, client_pub);
        keys_ = derive_keys(z, th);
        std::fill(z.begin(), z.end(), 0);

        step_ = Step::Complete;
        return Status::Done;
    }

    case Step::Complete:
    default:
        err = "unexpected handshake record after completion";
        return Status::Failed;
    }
}

// ------------------------------------------------------------ client side

namespace {

// Reads one handshake record of the expected sub-type. Surfaces a server alert
// verbatim so the caller can report why the server aborted.
bool recv_hs(int fd, uint8_t want_hstype, std::vector<uint8_t>& body, std::string& err)
{
    uint8_t type = 0;
    if (proto::recv_record(fd, type, body) != proto::Recv::Ok) {
        err = "connection closed during handshake";
        return false;
    }
    if (type == proto::REC_ALERT) { err = "server alert: " + proto::to_string(body); return false; }
    if (type != proto::REC_HANDSHAKE || body.empty() || body[0] != want_hstype) {
        err = "unexpected handshake record";
        return false;
    }
    return true;
}

// Aborts the handshake: sends an alert and closes without revealing anything
// further (no password, no DH value). §4.1.
bool abort_handshake(int fd, const std::string& reason, std::string& err)
{
    proto::send_record(fd, proto::REC_ALERT, reason.data(), reason.size());
    ::shutdown(fd, SHUT_RDWR);
    err = reason;
    return false;
}

} // namespace

bool client_handshake(int fd, uint8_t version, const pki::TrustStore& ts,
                      const std::string& expected_host, Session& out, std::string& err)
{
    std::vector<uint8_t> client_random(proto::CLIENT_RANDOM_LEN);
    if (!crypto::random_bytes(client_random.data(), client_random.size())) {
        err = "RNG failure";
        return false;
    }

    auto hello = make_client_hello(version, client_random);
    if (!proto::send_record(fd, proto::REC_HANDSHAKE, hello.data(), hello.size())) {
        err = "failed to send ClientHello";
        return false;
    }

    // ServerCert.
    std::vector<uint8_t> body;
    if (!recv_hs(fd, proto::HS_SERVER_CERT, body, err)) return false;
    uint16_t clen = 0;
    if (!get_u16(body.data(), body.size(), 1, clen) || 3u + clen != body.size()) {
        err = "bad ServerCert length"; return false;
    }
    std::vector<uint8_t> cert_der(body.begin() + 3, body.end());

    // ServerKex.
    if (!recv_hs(fd, proto::HS_SERVER_KEX, body, err)) return false;
    if (body.size() < 4 || body[1] != version) { err = "bad ServerKex"; return false; }
    uint16_t plen = static_cast<uint16_t>((body[2] << 8) | body[3]);
    if (plen != dh::MODULUS_BYTES || body.size() != 4u + plen) {
        err = "bad ServerKex length"; return false;
    }
    std::vector<uint8_t> server_pub(body.begin() + 4, body.end());

    // ServerProof.
    if (!recv_hs(fd, proto::HS_SERVER_PROOF, body, err)) return false;
    uint16_t slen = 0;
    if (!get_u16(body.data(), body.size(), 1, slen) || 3u + slen != body.size()) {
        err = "bad ServerProof length"; return false;
    }
    std::vector<uint8_t> sig(body.begin() + 3, body.end());

    // Validate before contributing anything. Any failure aborts here, before the
    // client's DH value or any application data is sent.
    X509* leaf = nullptr;
    std::string detail;
    auto res = pki::validate_cert(cert_der, ts, expected_host, &leaf, detail);
    if (res != pki::CertResult::Ok)
        return abort_handshake(fd, std::string("certificate rejected: ")
                                       + pki::result_str(res), err);

    auto tosign = proof_transcript(version, client_random, cert_der, server_pub);
    bool proof_ok = pki::verify_signature(leaf, tosign, sig);
    X509_free(leaf);
    if (!proof_ok)
        return abort_handshake(fd, "proof of possession failed: "
                                   "server does not hold the certificate's private key", err);

    // Validated: now contribute the client's DH value and finish.
    dh::KeyPair kp;
    if (!kp.generate()) { err = "DH keygen failed"; return false; }
    auto kex = make_client_kex(kp.public_value());
    if (!proto::send_record(fd, proto::REC_HANDSHAKE, kex.data(), kex.size())) {
        err = "failed to send ClientKex"; return false;
    }

    std::vector<uint8_t> z;
    if (!kp.compute_shared(server_pub, z)) { err = "invalid server public value"; return false; }

    auto th = transcript_hash(version, client_random, cert_der, server_pub, kp.public_value());
    Keys k = derive_keys(z, th);
    std::fill(z.begin(), z.end(), 0);

    out.install(k, Role::Client);
    return true;
}

} // namespace sec
