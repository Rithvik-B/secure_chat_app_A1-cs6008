// Handshake and record-encryption state for one connection. Driven blocking by
// the client, as a state machine by the server, and twice over by the proxy.

#pragma once

#include "crypto.h"
#include "dh.h"
#include "pki.h"

#include <cstdint>
#include <string>
#include <vector>

namespace sec {

// Selects which directional key this side seals with vs opens with.
enum class Role { Client, Server };

struct Keys {
    crypto::Key  c2s{};
    crypto::Salt salt{};
    crypto::Key  s2c{};
    std::string  fingerprint;      // 16 hex chars, safe to print
};

// TH = SHA-256(version || client_random || cert_der || server_pub || client_pub);
// binds the whole handshake into the keys, including the certificate.
std::vector<uint8_t> transcript_hash(uint8_t version,
                                     const std::vector<uint8_t>& client_random,
                                     const std::vector<uint8_t>& cert_der,
                                     const std::vector<uint8_t>& server_pub,
                                     const std::vector<uint8_t>& client_pub);

// The bytes the server signs for proof of possession:
//   version || client_random || cert_der || server_pub
// It omits client_pub (unknown when the server signs), and the client_random
// makes a captured signature useless in any other session.
std::vector<uint8_t> proof_transcript(uint8_t version,
                                      const std::vector<uint8_t>& client_random,
                                      const std::vector<uint8_t>& cert_der,
                                      const std::vector<uint8_t>& server_pub);

// Per-direction keys (prevents reflection); fingerprint uses a distinct label
// from the keys, so it is safe to print.
Keys derive_keys(const std::vector<uint8_t>& shared_secret,
                 const std::vector<uint8_t>& th);

// Encrypts and decrypts application records once the handshake has completed.
class Session {
public:
    void install(const Keys& k, Role r);
    bool established() const { return up_; }
    const std::string& fingerprint() const { return keys_.fingerprint; }

    // Sequence numbers are implicit (each side counts its own records); any
    // drop/dup/reorder/injection desyncs the counters and the tag check fails.
    bool seal(const std::string& plaintext, std::vector<uint8_t>& out);
    bool open(const uint8_t* body, size_t n, std::string& plaintext);

private:
    Keys     keys_;
    Role     role_ = Role::Client;
    bool     up_   = false;
    uint64_t tx_   = 0;
    uint64_t rx_   = 0;
};

// ---------------------------------------------------------------- handshake

std::vector<uint8_t> make_client_hello(uint8_t version,
                                       const std::vector<uint8_t>& client_random);
std::vector<uint8_t> make_server_cert(const std::vector<uint8_t>& cert_der);
std::vector<uint8_t> make_server_kex(uint8_t version,
                                     const std::vector<uint8_t>& server_pub);
std::vector<uint8_t> make_server_proof(const std::vector<uint8_t>& sig);
std::vector<uint8_t> make_client_kex(const std::vector<uint8_t>& client_pub);

// Server side, driven one record at a time so the poll() loop never blocks.
// Presents `cert_der` and signs the handshake with `key` (proof of possession).
// The same class serves the real server and the MITM proxy; the proxy simply
// passes a certificate it cannot back with the matching key.
class ServerHandshake {
public:
    enum class Status { NeedMore, Done, Failed };

    void set_credentials(const std::vector<uint8_t>& cert_der, EVP_PKEY* key);

    // Consumes one handshake record body; appends any records to send back.
    Status feed(const uint8_t* body, size_t n,
                std::vector<std::vector<uint8_t>>& replies, std::string& err);

    const Keys& keys() const { return keys_; }

private:
    enum class Step { AwaitClientHello, AwaitClientKex, Complete } step_ = Step::AwaitClientHello;
    dh::KeyPair          kp_;
    std::vector<uint8_t> client_random_;
    std::vector<uint8_t> server_pub_;
    std::vector<uint8_t> cert_der_;
    EVP_PKEY*            key_ = nullptr;      // not owned
    Keys                 keys_;
};

// Client side, blocking. Validates the server's certificate against `ts` and
// `expected_host`, then its proof of possession, before contributing its own DH
// value. On any failure it sends an alert, closes, and returns false with the
// reason in `err` -- nothing further is revealed.
bool client_handshake(int fd, uint8_t version, const pki::TrustStore& ts,
                      const std::string& expected_host, Session& out, std::string& err);

} // namespace sec
