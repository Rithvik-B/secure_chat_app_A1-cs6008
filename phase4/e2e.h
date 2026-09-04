// End-to-end encryption between two clients (Phase 4). A second Diffie-Hellman
// runs directly between the clients, riding inside the MSG/FROM <text> field as
// base64. The server relays the tags opaquely and never sees the E2E key.
//
// Wire tags (fixed by the assignment, never renamed):
//   __E2E_INIT__<b64>  __E2E_ACK__<b64>  __E2E_MSG__<b64>

#pragma once

#include "crypto.h"
#include "dh.h"

#include <cstdint>
#include <map>
#include <string>

namespace e2e {

constexpr char TAG_INIT[] = "__E2E_INIT__";
constexpr char TAG_ACK[]  = "__E2E_ACK__";
constexpr char TAG_MSG[]  = "__E2E_MSG__";

// Manages one E2E session per peer username. All methods take my own username so
// the two ends agree, without negotiating, on who is "a" (lexicographically
// smaller) and who is "b" -- which fixes the two directional keys.
class Manager {
public:
    // Begin a handshake with `peer`. Returns the payload for MSG <peer> <payload>.
    bool start(const std::string& me, const std::string& peer,
               std::string& payload, std::string& err);

    // Handle an incoming __E2E_INIT__ from `peer`; fills `ack` to send back.
    bool on_init(const std::string& me, const std::string& peer,
                 const std::string& tag_payload, std::string& ack, std::string& err);

    // Handle an incoming __E2E_ACK__ from `peer`.
    bool on_ack(const std::string& me, const std::string& peer,
                const std::string& tag_payload, std::string& err);

    // Seal / open a chat message for an established peer.
    bool seal(const std::string& peer, const std::string& plaintext,
              std::string& payload, std::string& err);
    bool open(const std::string& peer, const std::string& tag_payload,
              std::string& plaintext, std::string& err);

    bool established(const std::string& peer) const;
    std::string fingerprint(const std::string& peer) const;

private:
    struct Peer {
        enum class State { Pending, Up } state = State::Pending;
        bool         am_a = false;      // I hold the a-side (smaller username)
        dh::KeyPair  kp;                // my ephemeral key pair
        uint32_t     epoch = 0;
        crypto::Key  k_a2b{}, k_b2a{};
        crypto::Salt salt{};
        std::string  fp;
        uint64_t     tx = 0, rx = 0;
    };
    std::map<std::string, Peer> peers_;

    // Derive both keys, salt and fingerprint from the shared secret and epoch.
    static void derive(Peer& p, const std::vector<uint8_t>& z);
};

} // namespace e2e
