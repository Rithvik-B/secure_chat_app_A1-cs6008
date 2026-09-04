#include "e2e.h"
#include "proto.h"

#include <algorithm>
#include <cstring>

namespace e2e {

namespace {

std::vector<uint8_t> epoch_bytes(uint32_t e)
{
    return { uint8_t(e >> 24), uint8_t(e >> 16), uint8_t(e >> 8), uint8_t(e) };
}

std::vector<uint8_t> str_bytes(const char* s)
{
    return { s, s + std::strlen(s) };
}

// __E2E_INIT__ / __E2E_ACK__ payload: [version][epoch:4][dh_pub_len:2][dh_pub]
std::string encode_kex(uint32_t epoch, const std::vector<uint8_t>& pub)
{
    std::vector<uint8_t> v;
    v.push_back(proto::VERSION);
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
    if (!crypto::b64_decode(b64, v) || v.size() < 7) return false;
    if (v[0] != proto::VERSION) return false;
    epoch = (v[1] << 24) | (v[2] << 16) | (v[3] << 8) | v[4];
    uint16_t plen = (v[5] << 8) | v[6];
    if (v.size() != 7u + plen || plen != dh::MODULUS_BYTES) return false;
    pub.assign(v.begin() + 7, v.end());
    return true;
}

} // namespace

void Manager::derive(Peer& p, const std::vector<uint8_t>& z)
{
    auto eb = epoch_bytes(p.epoch);
    auto a2b  = crypto::sha256_labelled("CS6008-P4-KEY|",  {eb, str_bytes("|a2b|"), z});
    auto b2a  = crypto::sha256_labelled("CS6008-P4-KEY|",  {eb, str_bytes("|b2a|"), z});
    auto salt = crypto::sha256_labelled("CS6008-P4-SALT|", {eb, z});
    auto fp   = crypto::sha256_labelled("CS6008-P4-FP|",   {eb, z});
    std::memcpy(p.k_a2b.data(), a2b.data(), crypto::KEY_LEN);
    std::memcpy(p.k_b2a.data(), b2a.data(), crypto::KEY_LEN);
    std::memcpy(p.salt.data(), salt.data(), crypto::SALT_LEN);
    p.fp = crypto::hex(fp.data(), 8);
}

bool Manager::start(const std::string& me, const std::string& peer,
                    std::string& payload, std::string& err)
{
    if (me == peer) { err = "cannot E2E with yourself"; return false; }
    Peer p;
    p.am_a  = (me < peer);
    p.epoch = 0;
    if (!p.kp.generate()) { err = "DH keygen failed"; return false; }
    payload = std::string(TAG_INIT) + encode_kex(p.epoch, p.kp.public_value());
    peers_[peer] = std::move(p);       // replaces any previous session
    return true;
}

bool Manager::on_init(const std::string& me, const std::string& peer,
                      const std::string& tag_payload, std::string& ack, std::string& err)
{
    uint32_t epoch;
    std::vector<uint8_t> their_pub;
    if (!decode_kex(tag_payload, epoch, their_pub)) { err = "bad E2E init"; return false; }

    Peer p;
    p.am_a  = (me < peer);
    p.epoch = epoch;
    if (!p.kp.generate()) { err = "DH keygen failed"; return false; }

    std::vector<uint8_t> z;
    if (!p.kp.compute_shared(their_pub, z)) { err = "invalid E2E public value"; return false; }
    derive(p, z);
    std::fill(z.begin(), z.end(), 0);

    ack = std::string(TAG_ACK) + encode_kex(p.epoch, p.kp.public_value());
    p.state = Peer::State::Up;
    peers_[peer] = std::move(p);
    return true;
}

bool Manager::on_ack(const std::string& me, const std::string& peer,
                     const std::string& tag_payload, std::string& err)
{
    (void)me;
    auto it = peers_.find(peer);
    if (it == peers_.end() || it->second.state != Peer::State::Pending) {
        err = "unexpected E2E ack"; return false;
    }
    uint32_t epoch;
    std::vector<uint8_t> their_pub;
    if (!decode_kex(tag_payload, epoch, their_pub) || epoch != it->second.epoch) {
        err = "bad E2E ack"; return false;
    }
    std::vector<uint8_t> z;
    if (!it->second.kp.compute_shared(their_pub, z)) { err = "invalid E2E public value"; return false; }
    derive(it->second, z);
    std::fill(z.begin(), z.end(), 0);
    it->second.state = Peer::State::Up;
    return true;
}

bool Manager::seal(const std::string& peer, const std::string& plaintext,
                   std::string& payload, std::string& err)
{
    auto it = peers_.find(peer);
    if (it == peers_.end() || it->second.state != Peer::State::Up) {
        err = "no E2E session"; return false;
    }
    Peer& p = it->second;
    const crypto::Key& k = p.am_a ? p.k_a2b : p.k_b2a;   // seal on my sending direction
    auto nonce = crypto::make_nonce(p.salt, p.tx);
    std::vector<uint8_t> ct;
    if (!crypto::seal(k, nonce, p.tx,
                      reinterpret_cast<const uint8_t*>(plaintext.data()),
                      plaintext.size(), ct)) { err = "E2E seal failed"; return false; }
    ++p.tx;

    // payload = epoch(4) || ciphertext || tag
    std::vector<uint8_t> v = epoch_bytes(p.epoch);
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
    if (epoch != p.epoch) { err = "unknown E2E epoch"; return false; }

    const crypto::Key& k = p.am_a ? p.k_b2a : p.k_a2b;   // open on my receiving direction
    auto nonce = crypto::make_nonce(p.salt, p.rx);
    std::vector<uint8_t> pt;
    if (!crypto::open(k, nonce, p.rx, v.data() + 4, v.size() - 4, pt)) {
        err = "E2E authentication failed"; return false;
    }
    ++p.rx;
    plaintext.assign(pt.begin(), pt.end());
    return true;
}

bool Manager::established(const std::string& peer) const
{
    auto it = peers_.find(peer);
    return it != peers_.end() && it->second.state == Peer::State::Up;
}

std::string Manager::fingerprint(const std::string& peer) const
{
    auto it = peers_.find(peer);
    return it == peers_.end() ? std::string() : it->second.fp;
}

} // namespace e2e
