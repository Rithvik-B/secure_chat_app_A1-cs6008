// End-to-end encryption between two clients, with periodic rekeying for forward
// secrecy (Phases 4-5). A second Diffie-Hellman runs directly between the
// clients, riding inside the MSG/FROM <text> field as base64. Every 60 s the key
// is renegotiated into a new epoch, independent of the old one, which is then
// discarded -- so a compromised key exposes only a bounded window of traffic.
//
// Wire tags (fixed, never renamed): __E2E_INIT__  __E2E_ACK__  __E2E_MSG__

#pragma once

#include "crypto.h"
#include "dh.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace e2e {

constexpr char TAG_INIT[] = "__E2E_INIT__";
constexpr char TAG_ACK[]  = "__E2E_ACK__";
constexpr char TAG_MSG[]  = "__E2E_MSG__";

// Rotation timing. Mutable so a test (or a --rekey flag) can shorten them; the
// assignment default is 60/75/10.
extern int REKEY_SEC;      // initiator rotates after this long on an epoch
extern int FALLBACK_SEC;   // responder rotates if the initiator has gone silent
extern int GRACE_SEC;      // how long the previous epoch key lingers for decrypt

using Clock = std::chrono::steady_clock;

// A message the client should relay: MSG <peer> <payload>.
struct Action { std::string peer, payload; };

class Manager {
public:
    // Begin the initial handshake with `peer` (epoch 0). Fills the INIT payload.
    bool start(const std::string& me, const std::string& peer,
               std::string& payload, std::string& err);

    // Handle an incoming __E2E_INIT__ (initial handshake or a rotation). Fills
    // `ack` to send back, and `note` with a human line to print/log (empty when
    // the INIT is ignored by the collision tie-break).
    bool on_init(const std::string& me, const std::string& peer,
                 const std::string& tag_payload,
                 std::string& ack, std::string& note, std::string& err);

    // Handle an incoming __E2E_ACK__ (completes a handshake or rotation).
    bool on_ack(const std::string& me, const std::string& peer,
                const std::string& tag_payload, std::string& note, std::string& err);

    bool seal(const std::string& peer, const std::string& plaintext,
              std::string& payload, std::string& err);
    bool open(const std::string& peer, const std::string& tag_payload,
              std::string& plaintext, std::string& err);

    // Called periodically by the client's timer thread. Emits rotation INITs
    // that are due and expires stale grace windows.
    void tick(const std::string& me, std::vector<Action>& out,
              std::vector<std::string>& notes);

    bool established(const std::string& peer) const;
    std::string fingerprint(const std::string& peer) const;

private:
    struct Epoch {
        uint32_t     n = 0;
        crypto::Key  k_a2b{}, k_b2a{};
        crypto::Salt salt{};
        std::string  fp;
        uint64_t     tx = 0, rx = 0;
    };
    struct Peer {
        enum class State { Pending, Up } state = State::Pending;
        bool        am_a = false;              // I hold the a-side (smaller name)
        Epoch       cur;                       // active epoch
        bool        have_prev = false;         // previous epoch, decrypt-only
        Epoch       prev;
        Clock::time_point grace_until{};
        Clock::time_point epoch_start{};       // when `cur` became active
        bool        rotating = false;          // sent INIT for next_epoch, awaiting ACK
        uint32_t    next_epoch = 0;
        dh::KeyPair next_kp;                   // ephemeral for the pending rotation
        Clock::time_point rot_sent{};          // when our rotation INIT went out
    };
    std::map<std::string, Peer> peers_;

    static Epoch derive(uint32_t epoch, const std::vector<uint8_t>& z);
    static std::string rekey_note(const std::string& peer, const Epoch& e);
};

} // namespace e2e
