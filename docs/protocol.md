# Secure Chat Protocol

Wire protocol for the CS6008 secure chat application.

This document describes the protocol **as currently implemented**. It grows with each phase; right
now it covers Phases 1 through 4.

| Phase | Status | Adds |
|---|---|---|
| 1 | implemented | Record framing, application grammar, username routing |
| 2 | implemented | Diffie-Hellman key exchange, AES-256-GCM record encryption |
| 3 | implemented | Server authentication: certificate + proof of possession |
| 4 | implemented | End-to-end encryption between clients (server-blind) |
| 5 | not started | Key rotation |

---

## Layering

```
┌──────────────────────────────────────────────────────────┐
│ L5  End-to-end (Phase 4)  __E2E_* inside <text>, C1<->C2  │
├──────────────────────────────────────────────────────────┤
│ L4  Application grammar   LOGIN / MSG / WHO / QUIT        │
│                           OK / ERR / FROM / USERS / INFO  │
├──────────────────────────────────────────────────────────┤
│ L3  Record encryption     AES-256-GCM  (Phase 2)          │
├──────────────────────────────────────────────────────────┤
│ L2  Handshake             Diffie-Hellman + certificate    │
├──────────────────────────────────────────────────────────┤
│ L1  Record framing        [len:4][type:1][body]           │
├──────────────────────────────────────────────────────────┤
│     TCP — reliable, ordered byte stream                   │
└──────────────────────────────────────────────────────────┘
```

L1 knows nothing about chat and L4 knows nothing about how bytes are delimited or encrypted. Phase 2
inserted L2 and L3 between them without changing either: the application grammar and the framing are
exactly as they were in Phase 1. L3 sits *below* the grammar, so `LOGIN`, `MSG`, `WHO` and their
replies are all encrypted — the username never travels in the clear.

---

# L1 — Record framing

Every record, in both directions:

```
 0        1        2        3        4        5                     5+N
 ├────────┴────────┴────────┴────────┼────────┼──────────────────────┤
 │      length = 1 + N  (uint32 BE)  │  type  │   body — N bytes     │
 └───────────────────────────────────┴────────┴──────────────────────┘
```

- `length` counts the type byte plus the body — everything after the length field itself.
- Big-endian, via `htonl()` / `ntohl()`.

| `type` | Name | Meaning |
|---|---|---|
| `0x01` | `REC_HANDSHAKE` | key-exchange message, always plaintext |
| `0x02` | `REC_APPDATA` | application data — AES-256-GCM once the handshake completes |
| `0x03` | `REC_ALERT` | abort reason, plaintext by necessity |

Whether a `REC_APPDATA` body is plaintext or ciphertext is decided by connection state, not by the
record: before the handshake finishes there is no key, so the body is plaintext; after it, every body
is a GCM record. Alerts are plaintext because they are sent only while tearing a session down, often
before any key exists.

### Limits

```
MAX_RECORD    = 16384      // bytes after the length prefix
MAX_PLAINTEXT = 8192       // application payload
```

A declared length outside `1 .. MAX_RECORD` **aborts the connection before any allocation**. A length
field trusted blindly is a one-packet denial of service: a peer claiming `0xFFFFFFFF` would otherwise
trigger a 4 GB allocation.

### Reading a record

TCP is a byte stream with no message boundaries. A single `send()` may arrive split across several
`recv()` calls, or concatenated with its neighbours. So:

1. read exactly 4 bytes → `ntohl` → `length`
2. reject if `length < 1` or `length > MAX_RECORD`
3. read exactly `length` bytes → first byte is `type`, the rest is `body`

Each step loops until satisfied. **A message is complete when, and only when, the declared number of
bytes has arrived.** Symmetrically, `send()` may transmit fewer bytes than requested, so writing also
loops.

`recv()` returning `0` is an orderly peer shutdown, not an error; `-1` is an error, check `errno`.

### Why a length prefix rather than a delimiter

Delimiting messages with `\n` would be simpler, and adequate for Phase 1 where every payload is
printable text.

It was rejected because the body will not stay printable. Once payloads carry encrypted data they
are uniformly distributed binary, so roughly one byte in 256 equals `0x0A` — a newline-framed reader
would split messages at random positions. Working around that means either base64-encoding every
record (33% overhead, and framing is still needed on top) or an escaping scheme whose bugs would be
protocol-breaking.

Length prefixing is binary-safe, so the framing written now does not have to be revisited. Verified
rather than assumed: a payload containing all 256 byte values, including `0x00`, `0x0A` and `0xFF`,
round-trips byte-exactly.

---

# L2 — Handshake (Phases 2–3)

Runs immediately after TCP connect, before any application data. It agrees a shared secret with
Diffie-Hellman (Phase 2) and, in Phase 3, authenticates the server with a certificate and a proof of
possession before the client commits anything.

A handshake record (`REC_HANDSHAKE`) carries a one-byte sub-type followed by its payload. Variable
fields are `uint16` big-endian length-prefixed.

| Sub-type | Name | Direction | Body | Phase |
|---|---|---|---|---|
| `0x01` | `HS_CLIENT_HELLO` | C → S | `[version:1][client_random:32]` | 2 |
| `0x03` | `HS_SERVER_CERT` | S → C | `[cert_len:2][cert_der]` | 3 |
| `0x02` | `HS_SERVER_KEX` | S → C | `[version:1][dh_pub_len:2][dh_pub]` | 2 |
| `0x04` | `HS_SERVER_PROOF` | S → C | `[sig_len:2][sig]` | 3 |
| `0x05` | `HS_CLIENT_KEX` | C → S | `[dh_pub_len:2][dh_pub]` | 2 |


```
                Phase 2                          Phase 3
C → S   HS_CLIENT_HELLO {ver, random}    HS_CLIENT_HELLO {ver, random}
S → C   HS_SERVER_KEX   {ver, B}         HS_SERVER_CERT  {cert}
                                         HS_SERVER_KEX   {ver, B}
                                         HS_SERVER_PROOF {sig}
                                         ── client validates, or alert + close ──
C → S   HS_CLIENT_KEX   {A}              HS_CLIENT_KEX   {A}
```

Phase 3 is purely additive: two new server messages inserted into the same sequence. Both sides then
compute `Z = peer_pub^own_priv mod p`, derive keys, and print a fingerprint.

`HS_CLIENT_HELLO` **carries no DH value** — only a 32-byte random nonce. The client contributes its
public value in `HS_CLIENT_KEX`, *after* it has received and (in Phase 3) validated the server's
messages, so a client that rejects the certificate has revealed nothing but 32 random bytes and can
abort cleanly. The nonce is also what the server signs, which makes a captured signature useless in
any later session.

## Server authentication (Phase 3)

### Certificate and proof of possession

The server sends its X.509 certificate (`HS_SERVER_CERT`), then, after its DH value, a signature
(`HS_SERVER_PROOF`):

```
sig = RSA-SHA256_sign( server_key,  version || client_random || cert_der || server_pub )
```

A certificate only asserts that a CA vouched a public key belongs to `chatserver.local`; it is a
public file that anyone can copy. The signature is what proves the peer actually *holds* the matching
private key — only that key can produce a signature the certificate's public key verifies. Signing a
value that includes `client_random` binds the proof to this session, so it cannot be replayed.

### Client validation — fail closed, in order

The client checks, and aborts at the first failure (sending a `REC_ALERT` and nothing else — no DH
value, no login):

1. **Chain** — the certificate verifies against the trusted CA (`X509_verify_cert`).
2. **Validity** — the current time is within the certificate's window.
3. **Identity** — a SAN/CN matches the expected name (`X509_check_host`, `chatserver.local`).
4. **Proof of possession** — the signature verifies against the certificate's public key over the
   recomputed transcript.

This defeats the Phase 2 MITM two ways: a self-signed certificate fails step 1, and a *stolen* real
certificate (whose private key the attacker lacks) fails step 4.

### The Diffie-Hellman group

RFC 3526 group 14: a standard, published 2048-bit MODP group with generator `g = 2`. The modulus is a
safe prime (both `p` and `(p-1)/2` are prime), verified in the self-test. The private exponent is 256
random bits.

The modular exponentiation `g^x mod p` is **implemented by hand**, as square-and-multiply, reducing
modulo `p` at every step. Computing `g^x` first and reducing afterwards is impossible: with a
2048-bit modulus and a 256-bit exponent the intermediate would have more digits than there are atoms
in the observable universe. OpenSSL's big-integer type is used only as an arithmetic primitive
(`BN_mod_mul`); `BN_mod_exp` and the whole DH API are avoided.

A received peer value is rejected unless `1 < y < p-1`. Without that check a peer could send `0`, `1`
or `p-1` and force the shared secret to a value it chooses.

### Key derivation

Let `Z` be the shared secret, big-endian, **left-padded to 256 bytes**. The padding matters: a `Z`
that happens to have a leading zero byte would otherwise serialise one byte shorter on one side than
the other, and the two ends would derive different keys roughly one time in 256.

```
TH    = SHA-256( version || client_random || cert_der || server_pub || client_pub )

K_c2s = SHA-256( "CS6008-P2-KEY|c2s|" || Z || TH )   // client -> server
K_s2c = SHA-256( "CS6008-P2-KEY|s2c|" || Z || TH )   // server -> client
salt  = SHA-256( "CS6008-P2-SALT|"    || Z || TH )[0..3]
FP    = SHA-256( "CS6008-P2-FP|"      || Z || TH )[0..7]   // printable fingerprint
```

- **`Z` is never used directly as a key.** It is a biased element of a large group, not a uniform
  256-bit string; a cryptographic hash both fixes the size and removes the bias. This is why the DH
  secret is hashed rather than truncated.
- **Separate keys per direction** stop a record the server sent from being replayed back at it as
  though the client had sent it.
- **The transcript hash `TH` is folded in**, so that tampering with any handshake field makes the two
  sides derive different keys — the very first encrypted record then fails its tag and the connection
  dies, rather than proceeding on mismatched keys.
- **The fingerprint uses a different label** from the keys, so it can be printed for the
  matching-fingerprint check without revealing anything about the keys. Both ends print `FP`; a real
  session sees them match. `Z` and the keys themselves are never printed.

---

# L3 — Record encryption (Phase 2)

Once the handshake completes, every `REC_APPDATA` body is:

```
 0                              N            N+16
 ├──────────────────────────────┼─────────────┤
 │        ciphertext            │  tag (16)   │
 └──────────────────────────────┴─────────────┘
```

AES-256-GCM. Note what is **not** on the wire: no IV and no sequence number.

```
seq    : uint64, starts at 0, a separate counter per direction
nonce  : salt(4) || seq(8, big-endian)   = 12 bytes
AAD    : seq(8, big-endian)
key    : K_c2s or K_s2c, by direction
```

Each side counts its own records, so the sequence number is implicit — nothing is transmitted. TCP
delivers records in order, so the two counters stay in lockstep. If a record is dropped, duplicated,
reordered or injected, the counters diverge, the GCM tag fails, and the connection aborts. That
failure *is* the tamper detection: a single flipped byte makes decryption fail rather than produce
corrupted plaintext, and the corrupted record is never processed.

**A nonce is never reused under one key.** GCM nonce reuse leaks the XOR of two plaintexts and lets an
attacker forge tags; a monotonic counter makes reuse structurally impossible, where a random 96-bit
nonce would eventually collide.

---

# L4 — Application grammar

The body of an application record — the GCM *plaintext* from Phase 2 on — is a single UTF-8 line: a verb, then space-separated arguments.
No trailing newline — the record boundary is the message boundary.

### Client → Server

| Message | Meaning |
|---|---|
| `LOGIN <username>` | Register a username. First message on the connection. |
| `MSG <to> <text>` | Deliver `<text>` to `<to>`. `<text>` is everything after the second space. |
| `WHO` | Request the list of online users. |
| `QUIT` | Disconnect cleanly. |

### Server → Client

| Message | Meaning |
|---|---|
| `OK <username>` | Registration accepted. |
| `ERR <reason>` | Request rejected; human-readable reason. |
| `FROM <sender> <text>` | A relayed message. |
| `USERS <name> <name> ...` | Response to `WHO`, sorted. May be empty. |
| `INFO <text>` | Notice, e.g. `INFO bob joined`. |

`LOGIN` carries identity for routing, not authentication — there is no password. The assignment
never requires user authentication, and its reference to protecting a login exchange is explicitly
conditional ("if applicable").

### Usernames

1–32 characters, `[A-Za-z0-9_]`, unique across connected clients. Excluding spaces keeps the
space-delimited grammar unambiguous: a username can never be mistaken for part of a message.

### Connection state machine

```
   TCP connect
        │
        ▼
  ┌────────────────┐   LOGIN <user>    ┌──────────────┐
  │ UNAUTHENTICATED│──────────────────►│  REGISTERED  │
  │                │◄───── OK ─────────│              │
  └───────┬────────┘                   └──────┬───────┘
          │                                   │
    anything else                       MSG / WHO (loop)
          │                                   │
          ▼                                   ▼
     ERR + close                     QUIT, or peer closed
                                              │
                                              ▼
                                           CLOSED
```

A duplicate or malformed username gets an `ERR` and the connection closes.

### Routing

The server keeps a `username → socket` map. On `MSG <to> <text>`:

1. Resolve `<to>`.
2. Found → send `FROM <sender> <text>` to that socket, and log the relay.
3. Not found → log it as undeliverable and reply `ERR no such user: <to>`.

Because routing is a map lookup rather than a hard-wired pairing, the design supports an arbitrary
number of simultaneous clients; the two required by Phase 1 are simply the case demonstrated.
Broadcast is used only for join and leave notices.

### The opacity rule

**The server parses exactly two tokens of a `MSG`: the verb and the recipient. The message text is
copied byte-for-byte and never inspected, validated or modified.**

This is a deliberate constraint rather than an accident of implementation. Keeping the relay ignorant
of message content means the routing logic never has to change when the content changes — the server
forwards bytes addressed to a username, and nothing more.

### Relay logging

The server logs every message it handles, with the full text:

```
[2026-09-04T00:54:56Z] RELAY   alice -> bob   : "hey bob, are you there?"
[2026-09-04T00:55:02Z] UNDELIV alice -> carol : "nobody home"
```

`RELAY` is written only after the recipient resolves, so the line means the message was actually
delivered. This log is the Phase 1 evidence that the server can read the entire content of every
message passing through it — and, from Phase 4, the evidence that it no longer can.

---

# L5 — End-to-end encryption (Phase 4)

Phases 2–3 secure the client-server link, but the server still reads every message. Phase 4 adds a
second encryption layer *between the two clients* that the server cannot read. It lives entirely
inside the `<text>` field of `MSG` / `FROM`, so **the server's routing is unchanged** — it forwards
the field verbatim, exactly as before, and never learns the layer exists. The whole feature is in the
client; `server.cpp` is byte-for-byte identical to Phase 3.

### Wire tags

Carried as the `<text>` of an ordinary `MSG` / `FROM`, base64 because `<text>` is a text field:

```
__E2E_INIT__<b64>   __E2E_ACK__<b64>   __E2E_MSG__<b64>
```

`__E2E_INIT__` / `__E2E_ACK__` decode to `[version:1][epoch:4][dh_pub_len:2][dh_pub]`;
`__E2E_MSG__` decodes to `[epoch:4][ciphertext][tag:16]`. The `epoch` field is present from Phase 4
(always 0 here) so that Phase 5 rekeying needs no format change.

### Handshake

```
alice types /e2e bob
alice → server → bob    MSG bob   __E2E_INIT__<b64(ver, epoch 0, A)>
bob   → server → alice  MSG alice __E2E_ACK__ <b64(ver, epoch 0, B)>
both derive Z_e2e = peer^own mod p, derive keys, print a fingerprint
```

A second Diffie-Hellman, over the same MODP-2048 group, run directly between the clients. The server
relays two `MSG`s and understands neither.

### Key derivation

"a" is the lexicographically smaller username, "b" the larger, so both sides agree on directions
without negotiating:

```
K_a2b  = SHA-256("CS6008-P4-KEY|"  || epoch(4) || "|a2b|" || Z_e2e)
K_b2a  = SHA-256("CS6008-P4-KEY|"  || epoch(4) || "|b2a|" || Z_e2e)
salt   = SHA-256("CS6008-P4-SALT|" || epoch(4) || Z_e2e)[0..3]
FP_e2e = SHA-256("CS6008-P4-FP|"   || epoch(4) || Z_e2e)[0..7]
```

Records use AES-256-GCM with the same implicit-counter nonce as L3, keyed per (epoch, direction).
Both clients print `FP_e2e`, which match — the §5.2 evidence.

### Two layers

A `__E2E_MSG__` is encrypted with the C1↔C2 key, *then* the whole `MSG bob __E2E_MSG__...` line is
encrypted again by the client-server link (L3) on the way to the server. So the server, which can
decrypt the outer layer, sees only the opaque `__E2E_MSG__` base64; a wire sniffer sees neither layer.

### Dispatch rule

On `FROM sender <text>` the client branches on the tag prefix:

| Prefix | Action |
|---|---|
| `__E2E_INIT__` / `__E2E_ACK__` | complete the handshake — **never** shown as chat |
| `__E2E_MSG__` | decrypt with the epoch key, show as `sender [e2e]> ...` |
| anything else | plain chat |

Two rules keep this unambiguous (§1.4 property 2): outgoing text starting with `__E2E` is refused, so
a user cannot forge a tag; and a *plain* message from a peer with an active E2E session is flagged as
a downgrade rather than shown as normal chat.

---

# Client command interface

The commands are the user interface, kept deliberately separate from the wire protocol.

| User types | Client action | Sent on the wire |
|---|---|---|
| `@bob hello` | select `bob`, send | `MSG bob hello` |
| `@bob` | select `bob` | — |
| `/chat bob` | select `bob` | — (local state only) |
| `/who` | request user list | `WHO` |
| `/quit` | disconnect and exit | `QUIT` |
| anything else | send to selected partner | `MSG <partner> <text>` |

The last row follows the specification literally: input matching no recognised command tag is treated
as a plain chat message to the currently selected user, so a mistyped `/quti` is transmitted as chat
text rather than rejected.

---

# Implementation

| Layer | Where |
|---|---|
| L1 framing, blocking I/O, incremental reader | `phase1/proto.h`, `phase1/proto.cpp` |
| L2 grammar, routing, relay logging | `phase1/server.cpp` |
| Command interface | `phase1/client.cpp` |

**Server** — single-threaded `poll()` over non-blocking sockets. Each connection owns a
`RecordReader` buffering partial inbound records, and an outbound byte queue flushed on `POLLOUT`.
Neither a half-delivered record nor a peer that has stopped reading can stall the other clients. The
outbound queue is capped at 1 MiB; a peer that exceeds it is dropped.

**Client** — blocking socket with two threads, because it must wait on the socket and the keyboard at
once: the main thread reads stdin, a reader thread reads the socket. Each blocks on its own source.
Stdout is mutex-guarded so an arriving message cannot interleave inside a line.

**Both** ignore `SIGPIPE`, so writing to a departed peer returns an error instead of killing the
process.

`WHO` output is sorted; the underlying map's iteration order varies between runs, which would make
captured evidence hard to compare.

### Error handling

| Condition | Response |
|---|---|
| `length` outside `1 .. MAX_RECORD` | close immediately, no allocation |
| Unknown record type | close |
| Payload above `MAX_PLAINTEXT` | close |
| Application message before `LOGIN` | `ERR must LOGIN first`, close |
| Invalid or duplicate username | `ERR`, close |
| Unknown recipient | `ERR no such user: <to>`, connection stays open |

### Verification

Framing was tested against: a record delivered one byte at a time; three records glued into a single
write; an 8 KB record reassembled from arbitrary chunk boundaries; a payload containing all 256 byte
values. Hostile input — a forged `0xFFFFFFFF` length, application data before `LOGIN`, a duplicate
username, an unexpected record type — is rejected and the connection closed in each case.

Evidence in [`../evidence/phase1/`](../evidence/phase1/).

---

# Constants

```c
#define PROTO_VERSION      0x04
#define CHAT_PORT          5555

#define MAX_RECORD         16384
#define MAX_PLAINTEXT      8192
#define MAX_USERNAME       32

#define REC_HANDSHAKE      0x01
#define REC_APPDATA        0x02
#define REC_ALERT          0x03

#define HS_CLIENT_HELLO    0x01
#define HS_SERVER_KEX      0x02
#define HS_SERVER_CERT     0x03
#define HS_SERVER_PROOF    0x04
#define HS_CLIENT_KEX      0x05
#define CLIENT_RANDOM_LEN  32

// crypto
#define DH_MODULUS_BYTES   256   // RFC 3526 group 14, 2048-bit
#define AES_KEY_LEN        32
#define GCM_NONCE_LEN      12
#define GCM_TAG_LEN        16
```
