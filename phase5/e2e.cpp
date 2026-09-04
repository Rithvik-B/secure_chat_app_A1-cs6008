#include "e2e.h"
#include "proto.h"

#include <algorithm>
#include <cstring>

namespace e2e {

int REKEY_SEC    = 60;
int FALLBACK_SEC = 75;
int GRACE_SEC    = 10;

namespace {

std::vector<uint8_t> epoch_bytes(uint32_t e)
{
    return { uint8_t(e >> 24), uint8_t(e >> 16), uint8_t(e >> 8), uint8_t(e) };
}
std::vector<uint8_t> str_bytes(const char* s) { return { s, s + std::strlen(s) }; }

// __E2E_INIT__ / __E2E_ACK__ payload: [version][epoch:4][dh_pub_len:2][dh_pub]
std::string encode_kex(uint32_t epoch, const std::vector<uint8_t>& pub)
{
    std::vector<uint8_t> v{proto::VERSION};
    auto eb = epoch_bytes(epoch);
    v.insert(v.end(), eb.begin(), eb.end());
    v.push_back(uint8_t(pub.size() >> 8));
    v.push_back(uint8_t(pub.size()));
    v.insert(v.end(), pub.begin(), pub.end());
    return crypto::b64_encode(v);
}
bool decode_kex(const std::string& b64, uint32_t& epoch, std::vector<uint8_t>& pub)
{
    std::vector<uint8_t> v;
    if (!crypto::b64_decode(b64, v) || v.size() < 7 || v[0] != proto::VERSION) return false;
    epoch = (v[1] << 24) | (v[2] << 16) | (v[3] << 8) | v[4];
    uint16_t plen = (v[5] << 8) | v[6];
    if (v.size() != 7u + plen || plen != dh::MODULUS_BYTES) return false;
    pub.assign(v.begin() + 7, v.end());
    return true;
}

} // namespace

Manager::Epoch Manager::derive(uint32_t epoch, const std::vector<uint8_t>& z)
{
    Epoch e;
    e.n = epoch;
    auto eb = epoch_bytes(epoch);
    auto a2b  = crypto::sha256_labelled("CS6008-P4-KEY|",  {eb, str_bytes("|a2b|"), z});
    auto b2a  = crypto::sha256_labelled("CS6008-P4-KEY|",  {eb, str_bytes("|b2a|"), z});
    auto salt = crypto::sha256_labelled("CS6008-P4-SALT|", {eb, z});
    auto fp   = crypto::sha256_labelled("CS6008-P4-FP|",   {eb, z});
    std::memcpy(e.k_a2b.data(), a2b.data(), crypto::KEY_LEN);
    std::memcpy(e.k_b2a.data(), b2a.data(), crypto::KEY_LEN);
    std::memcpy(e.salt.data(), salt.data(), crypto::SALT_LEN);
    e.fp = crypto::hex(fp.data(), 8);
    return e;
}

std::string Manager::rekey_note(const std::string& peer, const Epoch& e)
{
    if (e.n == 0)
        return "* end-to-end session established with " + peer + ", fingerprint " + e.fp;
    return "E2E rekey -> epoch " + std::to_string(e.n) + " with " + peer +
           "  fingerprint " + e.fp;
}

bool Manager::start(const std::string& me, const std::string& peer,
                    std::string& payload, std::string& err)
{
    if (me == peer) { err = "cannot E2E with yourself"; return false; }
    Peer p;
    p.am_a = (me < peer);
    if (!p.next_kp.generate()) { err = "DH keygen failed"; return false; }
    p.rotating   = true;
    p.next_epoch = 0;
    p.rot_sent   = Clock::now();
    payload = std::string(TAG_INIT) + encode_kex(0, p.next_kp.public_value());
    peers_[peer] = std::move(p);
    return true;
}

bool Manager::on_init(const std::string& me, const std::string& peer,
                      const std::string& tag_payload,
                      std::string& ack, std::string& note, std::string& err)
{
    uint32_t epoch;
    std::vector<uint8_t> their_pub;
    if (!decode_kex(tag_payload, epoch, their_pub)) { err = "bad E2E init"; return false; }

    auto it = peers_.find(peer);
    const bool am_a = (me < peer);

    // Collision: I have also sent an INIT for this same epoch. The peer with the
    // smaller username wins; the loser abandons its own INIT and responds here.
    if (it != peers_.end() && it->second.rotating && it->second.next_epoch == epoch) {
        if (am_a) { note.clear(); ack.clear(); return true; }   // I win: ignore theirs
        it->second.rotating = false;                            // I lose: drop my INIT
    }

    // Fresh key pair for my side of this (possibly new) epoch.
    dh::KeyPair kp;
    if (!kp.generate()) { err = "DH keygen failed"; return false; }
    std::vector<uint8_t> z;
    if (!kp.compute_shared(their_pub, z)) { err = "invalid E2E public value"; return false; }
    Epoch e = derive(epoch, z);
    std::fill(z.begin(), z.end(), 0);

    if (it == peers_.end()) {                          // initial handshake (epoch 0)
        Peer p;
        p.am_a = am_a;
        p.cur = e;
        p.state = Peer::State::Up;
        p.epoch_start = Clock::now();
        peers_[peer] = std::move(p);
    } else {                                           // rotation: retire cur -> grace
        Peer& p = it->second;
        p.prev = p.cur;
        p.have_prev = true;
        p.grace_until = Clock::now() + std::chrono::seconds(GRACE_SEC);
        p.cur = e;
        p.state = Peer::State::Up;
        p.epoch_start = Clock::now();
        p.rotating = false;
    }
    ack  = std::string(TAG_ACK) + encode_kex(epoch, kp.public_value());
    note = rekey_note(peer, e);
    return true;
}

bool Manager::on_ack(const std::string& me, const std::string& peer,
                     const std::string& tag_payload, std::string& note, std::string& err)
{
    (void)me;
    auto it = peers_.find(peer);
    if (it == peers_.end() || !it->second.rotating) { err = "unexpected E2E ack"; return false; }
    Peer& p = it->second;

    uint32_t epoch;
    std::vector<uint8_t> their_pub;
    if (!decode_kex(tag_payload, epoch, their_pub) || epoch != p.next_epoch) {
        err = "bad E2E ack"; return false;
    }
    std::vector<uint8_t> z;
    if (!p.next_kp.compute_shared(their_pub, z)) { err = "invalid E2E public value"; return false; }
    Epoch e = derive(epoch, z);
    std::fill(z.begin(), z.end(), 0);

    if (p.state == Peer::State::Up) {                  // rotation: retire cur -> grace
        p.prev = p.cur;
        p.have_prev = true;
        p.grace_until = Clock::now() + std::chrono::seconds(GRACE_SEC);
    }
    p.cur = e;
    p.state = Peer::State::Up;
    p.epoch_start = Clock::now();
    p.rotating = false;
    note = rekey_note(peer, e);
    return true;
}

bool Manager::seal(const std::string& peer, const std::string& plaintext,
                   std::string& payload, std::string& err)
{
    auto it = peers_.find(peer);
    if (it == peers_.end() || it->second.state != Peer::State::Up) {
        err = "no E2E session"; return false;
    }
    Epoch& e = it->second.cur;
    const crypto::Key& k = it->second.am_a ? e.k_a2b : e.k_b2a;
    auto nonce = crypto::make_nonce(e.salt, e.tx);
    std::vector<uint8_t> ct;
    if (!crypto::seal(k, nonce, e.tx,
                      reinterpret_cast<const uint8_t*>(plaintext.data()),
                      plaintext.size(), ct)) { err = "E2E seal failed"; return false; }
    ++e.tx;
    std::vector<uint8_t> v = epoch_bytes(e.n);
    v.insert(v.end(), ct.begin(), ct.end());
    payload = std::string(TAG_MSG) + crypto::b64_encode(v);
    return true;
}

bool Manager::open(const std::string& peer, const std::string& tag_payload,
                   std::string& plaintext, std::string& err)
{
    auto it = peers_.find(peer);
    if (it == peers_.end() || it->second.state != Peer::State::Up) {
        err = "no E2E session"; return false;
    }
    Peer& p = it->second;
    std::vector<uint8_t> v;
    if (!crypto::b64_decode(tag_payload, v) || v.size() < 4 + crypto::TAG_LEN) {
        err = "bad E2E message"; return false;
    }
    uint32_t epoch = (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];

    // Choose the key by epoch: the current one, or the previous one while its
    // grace window is open (for messages in flight across a rotation).
    Epoch* e = nullptr;
    if (epoch == p.cur.n) {
        e = &p.cur;
    } else if (p.have_prev && epoch == p.prev.n && Clock::now() < p.grace_until) {
        e = &p.prev;
    } else {
        err = "unknown or expired E2E epoch"; return false;
    }

    const crypto::Key& k = p.am_a ? e->k_b2a : e->k_a2b;
    auto nonce = crypto::make_nonce(e->salt, e->rx);
    std::vector<uint8_t> pt;
    if (!crypto::open(k, nonce, e->rx, v.data() + 4, v.size() - 4, pt)) {
        err = "E2E authentication failed"; return false;
    }
    ++e->rx;
    plaintext.assign(pt.begin(), pt.end());
    return true;
}

void Manager::tick(const std::string& me, std::vector<Action>& out,
                   std::vector<std::string>& notes)
{
    (void)me; (void)notes;
    auto now = Clock::now();
    for (auto& [peer, p] : peers_) {
        if (p.state != Peer::State::Up || p.rotating) {
            // Expire a grace window even mid-rotation.
            if (p.have_prev && now >= p.grace_until) p.have_prev = false;
            continue;
        }
        if (p.have_prev && now >= p.grace_until) p.have_prev = false;

        // The a-side rotates after REKEY_SEC; the b-side only after FALLBACK_SEC,
        // i.e. only if the a-side has fallen silent.
        int due = p.am_a ? REKEY_SEC : FALLBACK_SEC;
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - p.epoch_start).count();
        if (age < due) continue;

        if (!p.next_kp.generate()) continue;
        p.rotating   = true;
        p.next_epoch = p.cur.n + 1;
        p.rot_sent   = now;
        out.push_back({peer, std::string(TAG_INIT) + encode_kex(p.next_epoch, p.next_kp.public_value())});
    }
}

bool Manager::established(const std::string& peer) const
{
    auto it = peers_.find(peer);
    return it != peers_.end() && it->second.state == Peer::State::Up;
}

std::string Manager::fingerprint(const std::string& peer) const
{
    auto it = peers_.find(peer);
    return it == peers_.end() ? std::string() : it->second.cur.fp;
}

} // namespace e2e
