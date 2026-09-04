#include "session.h"
#include "proto.h"

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

std::vector<uint8_t> make_server_kex(uint8_t version,
                                     const std::vector<uint8_t>& server_pub)
{
    std::vector<uint8_t> v{proto::HS_SERVER_KEX, version};
    put_u16(v, static_cast<uint16_t>(server_pub.size()));
    v.insert(v.end(), server_pub.begin(), server_pub.end());
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

ServerHandshake::Status ServerHandshake::feed(const uint8_t* body, size_t n,
                                              std::vector<uint8_t>& reply,
                                              std::string& err)
{
    if (n < 1) { err = "empty handshake record"; return Status::Failed; }
    const uint8_t hstype = body[0];

    switch (step_) {
    case Step::AwaitClientHello: {
        if (hstype != proto::HS_CLIENT_HELLO) { err = "expected ClientHello"; return Status::Failed; }
        if (n != 2 + proto::CLIENT_RANDOM_LEN) { err = "bad ClientHello length"; return Status::Failed; }
        if (body[1] != proto::VERSION) { err = "version mismatch"; return Status::Failed; }

        client_random_.assign(body + 2, body + n);
        if (!kp_.generate()) { err = "DH keygen failed"; return Status::Failed; }
        server_pub_ = kp_.public_value();

        reply = make_server_kex(proto::VERSION, server_pub_);
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

        auto th = transcript_hash(proto::VERSION, client_random_, {}, server_pub_, client_pub);
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

bool client_handshake(int fd, uint8_t version, Session& out, std::string& err)
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

    uint8_t type = 0;
    std::vector<uint8_t> body;
    if (proto::recv_record(fd, type, body) != proto::Recv::Ok) {
        err = "connection closed during handshake";
        return false;
    }
    if (type == proto::REC_ALERT) {
        err = "server alert: " + proto::to_string(body);
        return false;
    }
    if (type != proto::REC_HANDSHAKE || body.size() < 4 ||
        body[0] != proto::HS_SERVER_KEX) {
        err = "expected ServerKex";
        return false;
    }
    if (body[1] != version) { err = "version mismatch"; return false; }

    const uint16_t plen = static_cast<uint16_t>((body[2] << 8) | body[3]);
    if (plen != dh::MODULUS_BYTES || body.size() != 4u + plen) {
        err = "bad ServerKex length";
        return false;
    }
    std::vector<uint8_t> server_pub(body.begin() + 4, body.end());

    // The client's public value is sent only now, after the server's message has
    // been accepted -- the ordering later phases depend on.
    dh::KeyPair kp;
    if (!kp.generate()) { err = "DH keygen failed"; return false; }

    auto kex = make_client_kex(kp.public_value());
    if (!proto::send_record(fd, proto::REC_HANDSHAKE, kex.data(), kex.size())) {
        err = "failed to send ClientKex";
        return false;
    }

    std::vector<uint8_t> z;
    if (!kp.compute_shared(server_pub, z)) {
        err = "invalid server public value";
        return false;
    }

    auto th = transcript_hash(version, client_random, {}, server_pub, kp.public_value());
    Keys k = derive_keys(z, th);
    std::fill(z.begin(), z.end(), 0);

    out.install(k, Role::Client);
    return true;
}

} // namespace sec
