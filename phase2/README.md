# Phase 2 — Client–Server Confidentiality via Diffie–Hellman

Phase 1's chat, now encrypted. Each client runs a Diffie–Hellman key exchange with the server when it
connects, derives an AES-256-GCM key from the shared secret, and all traffic after the handshake —
the login included — is encrypted. A man-in-the-middle proxy (`mitm`) demonstrates that unauthenticated
DH agrees a key with *whoever answers*, which is the weakness Phase 3 will close.

## Build

```
make            # builds server, client, mitm, selftest
make test       # runs the self-test
```

Needs g++ (C++17), pthreads, and `libcrypto` (OpenSSL). `<openssl/ssl.h>` and `<openssl/dh.h>` are
**not** used: the DH exchange and its modular exponentiation are written from scratch in `dh.cpp`.

## Run

Same as Phase 1. Key agreement happens automatically before login; each client prints its
shared-secret fingerprint.

```
./server                          # on vm1-server (10.10.0.10)
./client 10.10.0.10 alice         # on vm2-client1
./client 10.10.0.10 bob           # on vm3-client2
```

## What's new since Phase 1

| File | Purpose |
|---|---|
| `dh.{h,cpp}` | RFC 3526 group-14 Diffie–Hellman; hand-written square-and-multiply modexp |
| `crypto.{h,cpp}` | SHA-256 and AES-256-GCM over OpenSSL EVP primitives |
| `session.{h,cpp}` | handshake driver and per-direction record encryption |
| `mitm.cpp` | man-in-the-middle proxy for the §3.3 attack |
| `selftest.cpp` | checks the group, the modexp, key agreement, and AEAD |

`proto.{h,cpp}` and the server/client structure are carried over from Phase 1. The record framing and
the `LOGIN`/`MSG`/`WHO` grammar are unchanged; only the record *body* is now ciphertext.

## The handshake

```
C → S   HS_CLIENT_HELLO {version, 32-byte random}
S → C   HS_SERVER_KEX   {version, g^b mod p}
C → S   HS_CLIENT_KEX   {g^a mod p}
        each side computes Z = peer^own mod p, hashes it into keys, prints a fingerprint
```

Full specification, including key derivation, in [`../docs/protocol.md`](../docs/protocol.md).

Design points worth noting:

- **DH from first principles.** RFC 3526 group 14 (2048-bit safe prime, `g=2`). `g^x mod p` is
  square-and-multiply, reducing mod `p` at every step; `BN_mod_exp` is never called. OpenSSL's bignum
  type is used only as an arithmetic primitive.
- **The shared secret is hashed, not used raw.** `Z` is a biased group element; SHA-256 gives a
  uniform 256-bit key of the right size. Separate keys per direction prevent a message being reflected
  back at its sender.
- **Fingerprint.** Derived under a different hash label from the keys, so it is safe to print. Both
  ends compute the same one — the matching-fingerprint check of §3.2.
- **Nonce.** `salt(4) ‖ seq(8)`, with `seq` an implicit per-direction counter. Never repeats under one
  key, which GCM requires.
- **Server structure.** The handshake is a state machine fed one record at a time inside the existing
  non-blocking `poll()` loop, so a stalled client cannot freeze the whole server.

## The MITM proxy

```
victim ──DH──> mitm ──DH──> real server
```

`mitm` runs two independent handshakes — server-side toward the victim, client-side toward the real
server — so it holds both keys and reads everything. The victim is pointed at it manually (permitted
by §3.3): `./client 10.10.0.13 alice` instead of `10.10.0.10`.

```
./mitm --listen 10.10.0.13 --server 10.10.0.10 --log mallory.log
./mitm ... --tamper          # also corrupt one forwarded chat record, to show it rejected
```

The proxy's two fingerprints differ from each other and from what the real endpoints would have
agreed. That mismatch is the only observable sign of the attack — and the thing Phase 3 makes
un-forgeable.

## Changed since Phase 1

- **Added** a Diffie-Hellman handshake before any data (`dh.*`, `session.*`) and AES-256-GCM on every
  record after it (`crypto.*`); the login now travels encrypted.
- **Added** the MITM proxy (`mitm.cpp`) and the self-test (`selftest.cpp`).
- **Unchanged**: record framing, the `LOGIN`/`MSG`/`WHO` grammar, and the server's routing.
- **Client** now echoes its own outgoing messages (`you -> bob: ...`) so a terminal log is
  self-contained.

## Verification

Evidence in [`../evidence/phase2/`](../evidence/phase2/), three self-contained demos plus the
self-test. Each demo has an interleaved `*-transcript.md` that tells the whole story in one file. Full
write-up and the required explanations (why hash the secret; what would expose the MITM and why a user
misses it) are in [`01-verification.md`](../evidence/phase2/01-verification.md).

| Demo | Key files |
|---|---|
| Encrypted chat | `chat-transcript.md`, `chat.pcap`, `wireshark-*.png` (ciphertext where Phase 1 showed text) |
| MITM | `mitm-transcript.md`, `mitm-mallory.log` (captured plaintext + two differing fingerprints) |
| Tamper | `tamper-transcript.md` (flipped byte rejected with an auth failure) |
| Self-test | `selftest.txt` (safe prime; modexp matches OpenSSL; key agreement; 1-byte change breaks GCM) |

Capture as in Phase 1: `sudo tshark -i enp0s8 -f 'tcp port 5555' -w /tmp/x.pcap`, then copy off `/tmp`.
