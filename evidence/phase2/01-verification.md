# Phase 2 Verification — Confidentiality, MITM, Tamper Detection

Evidence for assignment §3.2 (verification) and §3.3 (MITM attack). All runs are on the lab VMs:
server on `vm1-server` (10.10.0.10), `alice` on `vm2-client1` (10.10.0.11), `bob` on `vm3-client2`
(10.10.0.12), Mallory's proxy on `vm4-mallory` (10.10.0.13).

Three self-contained demos, each collected from one run:

| Demo | Files | Interleaved transcript |
|---|---|---|
| Encrypted chat | `chat-alice.log`, `chat-bob.log`, `chat-server.log`, `chat.pcap` | `chat-transcript.md` |
| MITM attack | `mitm-alice.log`, `mitm-bob.log`, `mitm-server.log`, `mitm-mallory.log` | `mitm-transcript.md` |
| Tamper | `tamper-alice.log`, `tamper-server.log`, `tamper-mallory.log` | `tamper-transcript.md` |

Each `*-transcript.md` interleaves every party in timestamp order, so one file tells the whole story.
Client logs echo what each user typed (`you -> bob: ...`) as well as what they received (`bob> ...`).

---

## 1. Requirements → evidence

| §3 requirement | Evidence | Result |
|---|---|---|
| DH implemented from scratch, standard published group, modexp by hand | `selftest.txt`; `phase2/dh.cpp` | ✓ RFC 3526 group 14, hand-written square-and-multiply |
| AES key derived from the DH secret via a hash, not used raw | `docs/protocol.md` §L2; Q&A below | ✓ SHA-256(label ‖ Z ‖ transcript) |
| Authenticated encryption (AES-GCM) on all traffic incl. login | `chat-transcript.md`; `chat.pcap` | ✓ login travels encrypted (nothing readable pre-first-message) |
| Both ends print matching fingerprints; raw secret never printed | `chat-transcript.md` §2 | ✓ alice & server both `f5b73958…`; only the fingerprint is printed |
| Wireshark shows chat content no longer readable | `wireshark-*.png`, `chat-follow-stream.txt` | ✓ zero plaintext; ciphertext at the same offsets Phase 1 was readable |
| Tampering with a ciphertext byte is rejected, not silently accepted | `tamper-transcript.md`, `tamper-server.log` | ✓ record dropped with an auth failure, connection closed |
| MITM with two independent DH exchanges reads all traffic | `mitm-mallory.log`, `mitm-transcript.md` | ✓ every message captured in plaintext |
| Explanation: detectable evidence of the MITM, and why a user misses it | Q&A below | ✓ answered |

---

## 2. Confidentiality and matching fingerprints (§3.2)

From `chat-transcript.md`, each client's fingerprint equals the one the server logged for its
connection, and the two clients differ (independent exchanges):

```
alice(C1) | key exchange complete, shared-secret fingerprint f5b73958da76b903
SERVER    | KEX 10.10.0.11:39236 session established, fingerprint=f5b73958da76b903   <- matches alice
bob(C2)   | key exchange complete, shared-secret fingerprint ef643199d65ce813
SERVER    | KEX 10.10.0.12:42666 session established, fingerprint=ef643199d65ce813   <- matches bob
```

The fingerprint is `SHA-256("CS6008-P2-FP|" ‖ Z ‖ TH)[0..7]` — a different label from the encryption
keys, so it can be printed safely; the raw secret `Z` and the keys are never printed.

**On the wire** (`chat.pcap`): every chat word from the session (`alice`, `bob`, `MSG`, `FROM`,
`LOGIN`, `wireshark`, `ciphertext`, …) was searched across all frames and found in **zero**. The only
readable structure is the two Diffie-Hellman handshakes (public values, meant to be public).

- `wireshark-packet-ciphertext.png` — frame 16 (a chat record); the bytes pane is AES-GCM ciphertext
  with an unreadable ASCII column, where the Phase 1 capture showed `MSG bob hey bob, are you there?`.
- `wireshark-follow-tcp-stream.png` — Follow → TCP Stream: the whole conversation is unreadable, in
  direct contrast to the Phase 1 Follow-stream screenshot where every line was legible.
- `chat-packet16-hexdump.txt`, `chat-follow-stream.txt` — the same, as text.

---

## 3. MITM attack succeeds (§3.3)

`alice` was pointed at Mallory (`./client 10.10.0.13 alice`); `bob` used the real server. From
`mitm-mallory.log`:

```
two sessions established -- victim-side fp=cfbb2a3efc76a443  server-side fp=6d7bdab001012959
[C->S] LOGIN alice
[S->C] OK alice
[C->S] MSG bob this channel feels private to us
[S->C] FROM bob agreed, looks perfectly secure
[C->S] MSG bob mallory is reading every word
```

Mallory read and logged **every** message — login, both chat messages, the reply — in full
plaintext, while alice's client reported a normal, completed key exchange.

---

## 4. Tampering is detected (§3.2)

Mallory re-run with `--tamper` flips one byte of the first chat record. From `tamper-transcript.md`:

```
MALLORY | [C->S] LOGIN alice
MALLORY | [S->C] OK alice
alice   | you -> bob: this record will be corrupted in flight
MALLORY | [C->S] MSG bob this record will be corrupted in flight
MALLORY | [C->S] TAMPERED one byte of the next record
SERVER  | DROP alice : AES-GCM authentication failed, record rejected
SERVER  | CLOSE alice (peer closed)
alice   | * server closed the connection
```

The login (untampered) is accepted; the corrupted chat record fails its GCM tag and is rejected
outright — the connection closes rather than delivering corrupted text. A single flipped byte is a
hard failure, never silent corruption.

---

## 5. Required explanations (assignment questions)

**Why hash the DH shared secret instead of using it directly as the AES key? (§3.1)**
The raw secret `Z = g^{ab} mod p` is a 2048-bit element of a mathematical group, not a uniform
256-bit string. Its size is wrong (AES-256 needs exactly 32 bytes) and its bits are not uniformly
distributed — some values are structurally more likely, and there are known relationships between the
bits of a modular-exponentiation result. Using it raw would key AES with biased, non-uniform material.
A cryptographic hash (SHA-256) fixes both problems at once: it outputs exactly 32 bytes, and it maps
the biased input to an output indistinguishable from random, giving no usable structure to an attacker.
Hashing also lets us fold in a label and the handshake transcript, so one secret safely yields several
independent values (two directional keys, a salt, a printable fingerprint) that cannot be confused
with or derived from one another.

**What observable evidence would have let the victim detect the MITM, and why would an ordinary user
miss it? (§3.3)**
The evidence is the fingerprints. With Mallory in the middle there are two independent secrets:
alice computed `cfbb2a3efc76a443` (her session with Mallory) and the real server computed
`6d7bdab001012959` (its session with Mallory). Had alice and bob compared their fingerprints over an
independent channel — read them aloud on a phone call, say — the values would not have matched, and
the mismatch exposes that neither is talking directly to the other. An ordinary user misses this
because unauthenticated Diffie-Hellman gives *no automatic signal*: both endpoints see a normal,
completed handshake and a working encrypted session. Nothing on screen looks wrong; the only tell is a
manual, out-of-band comparison that users never actually perform. This is exactly the gap Phase 3
closes — the server proves its identity with a certificate, so a middle party cannot substitute a key
of its own without being caught automatically.

---

## 6. Changed since Phase 1

- **Added** a Diffie-Hellman handshake before any application data (`dh.*`, `session.*`), and
  **AES-256-GCM** on every record after it (`crypto.*`). The username/login now travels encrypted.
- **Added** the MITM proxy (`mitm.cpp`) and a crypto self-test (`selftest.cpp`).
- **Unchanged**: the record framing, the `LOGIN`/`MSG`/`WHO` grammar, and the server's routing — the
  server still forwards `<text>` verbatim, it just decrypts inbound and re-encrypts outbound.
- **Client** now echoes its own outgoing messages locally, so a terminal transcript is self-contained.

---

## 7. Reproducing

```bash
./scripts/deploy.sh phase2 s c1 c2 m

# encrypted chat + capture (write pcap to /tmp; dumpcap drops privileges under /home)
#   server:  ./server --log chat-server.log
#   c1:      sudo tshark -i enp0s8 -f 'tcp port 5555' -w /tmp/chat.pcap &  ./client 10.10.0.10 alice
#   c2:      ./client 10.10.0.10 bob

# MITM:  mallory: ./mitm --listen 10.10.0.13 --server 10.10.0.10 --log mitm-mallory.log [--tamper]
#        victim:  ./client 10.10.0.13 alice          (pointed at Mallory)

# self-test:  make test     (on any VM)
```
