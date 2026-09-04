# Phase 5 Verification — Forward Secrecy via Key Rotation

Evidence for assignment §6. Server on `vm1-server` (10.10.0.10), `alice` on `vm2-client1`, `bob` on
`vm3-client2`.

One demo, collected from one run:

| Files | Headline | Transcript |
|---|---|---|
| `rekey-alice.log`, `rekey-bob.log`, `rekey-server.log`, `selftest.txt` | `fingerprint-timeline.md` | `e2e-rekey-transcript.md` |

The rotation interval was set to **20 s** via `--rekey 20` so that two rotations complete inside a
short captured session. The code's default is **60 s**, as the assignment specifies; the behaviour is
identical, only the timer changes.

## 1. Requirements → evidence

| §6 requirement | Evidence | Result |
|---|---|---|
| E2E key renegotiated on a fixed timer while the session is active | `e2e-rekey-transcript.md` | ✓ every ~20 s |
| Each new key independent of the old; old key discarded | design §4; `selftest.txt` | ✓ fresh DH, no derivation from old |
| Simultaneous-rekey collisions handled without divergence | design §3; `selftest.txt` | ✓ deterministic tie-break |
| Chat uninterrupted across rotation | `e2e-rekey-transcript.md` | ✓ messages before/across/after all delivered |
| ≥2 rotations logged with timestamps + fingerprints, changing and matching | `fingerprint-timeline.md` | ✓ epoch 0→1→2 |
| A message sent immediately after a rotation is decrypted by the recipient | `e2e-rekey-transcript.md` | ✓ |
| Explanation of what forward secrecy adds over Phase 4 | §5 below | ✓ |

## 2. Fingerprint timeline (§6.2)

From `fingerprint-timeline.md`, both clients logged each epoch's fingerprint with a timestamp:

```
epoch time (alice)  alice fingerprint   time (bob)    bob fingerprint     match
0     07:22:40      edadeade4196261a    07:22:40      edadeade4196261a    yes
1     07:23:01      d5b9d6fbd2bad80f    07:23:01      d5b9d6fbd2bad80f    yes
2     07:23:21      0ab850ced4712d7f    07:23:21      0ab850ced4712d7f    yes
```

Two rotations. The fingerprint **changes** at each one (a fresh, independent key), and the two clients
always **agree** on the current fingerprint after a rotation completes.

## 3. Chat is not disrupted (§6.1)

From `e2e-rekey-transcript.md`, messages sent before, across, and after rotations are all delivered
and decrypted:

```
07:22:43  alice -> bob [e2e]: epoch 0: forward secrecy demo         bob | alice [e2e]> ...   (epoch 0)
07:23:01  E2E rekey -> epoch 1  ...                                                          (rotation)
07:23:01  alice -> bob [e2e]: after the first rotation              bob | alice [e2e]> ...   (epoch 1)
07:23:03  bob   -> alice [e2e]: replying across a rekey             alice | bob [e2e]> ...   (epoch 1)
07:23:21  E2E rekey -> epoch 2  ...                                                          (rotation)
07:23:21  alice -> bob [e2e]: after the second rotation             bob | alice [e2e]> ...   (epoch 2)
```

The message at 07:23:21 is sent in the same second as the second rotation and is decrypted correctly.
Every `__E2E_MSG__` carries its epoch (visible in the server log, e.g. the `__E2E_INIT__` payloads
begin `BQAAAAAB`, `BQAAAAEB`, `BQAAAAIB` for epochs 0, 1, 2), so the recipient always knows which key
to use, and the previous epoch's key lingers for a short grace window to decrypt anything in flight.
The server's relay log stays opaque (`__E2E_MSG__`) throughout.

## 4. How rotation works — collision avoidance (§6.1)

- **Who rotates.** Only the *initiator* — the peer with the lexicographically smaller username —
  starts a rotation, at the 60 s mark. Usernames are unique (the server enforces it), so both sides
  compute the same initiator with no negotiation.
- **Fallback.** The other peer holds a 75 s timer and initiates only if the initiator has gone silent,
  so a crashed initiator does not freeze rotation.
- **Tie-break.** If both somehow send `__E2E_INIT__` for the same epoch at once, the smaller username
  wins; the loser abandons its own INIT and answers with an ACK. This is deterministic, so the two
  sides can never settle on different keys — confirmed by the self-test's "both sides agree on the
  fingerprint after each rotation".
- **Independence.** Each epoch's key comes from a brand-new ephemeral Diffie-Hellman; it is never
  derived from the previous key. The old key is retained only for a ~10 s grace window (decrypt-only)
  and then wiped.

## 5. Required explanation — what forward secrecy buys over Phase 4

In Phase 4, a single end-to-end key protects the entire session. If an attacker records the encrypted
traffic and *later* obtains that one key — by stealing it from a device after the fact, or through a
future cryptographic break — they can decrypt **every message ever sent** in that session, past and
future.

Phase 5 rotates the key every 60 s, each epoch keyed by a fresh ephemeral Diffie-Hellman and the old
key wiped. Compromising one epoch's key now reveals **only that ~60 s window**. It does not reveal
earlier or later epochs: each epoch's secret came from ephemeral private exponents that were discarded
after the exchange, so they cannot be reconstructed from the compromised key, and the shared secrets
are independent. That is forward secrecy — the guarantee that compromising a key *now* does not
retroactively expose traffic protected by keys that have already been discarded. Phase 4 alone gives
no such guarantee; one key leak there is total.

## 6. Self-test

`selftest.txt` adds a key-rotation section: two rotations produce three epochs, the fingerprint changes
on every rotation and both sides agree, an in-flight previous-epoch message still decrypts within the
grace window, and a message sent right after a rotation decrypts.

## 7. Changed since Phase 4

- **Added** epoch state and a rotation timer to the E2E manager (`e2e.{h,cpp}`): the initiator rotates
  every 60 s, a fresh DH per epoch, a grace window for the retiring key, and the deterministic
  collision tie-break. The client gained a rotation-timer thread and a `--rekey` override.
- **No wire-format change** — the `epoch` field was already present from Phase 4.
- **Unchanged**: `server.cpp` (still identical to Phase 3), the record framing, the outer handshake and
  encryption, and the E2E message format.

## 8. Reproducing

```bash
./scripts/deploy.sh phase5 s c1 c2
# server:  ./server --cert pki/out/server-cert.pem --key pki/out/server-key.pem
# alice:   ./client 10.10.0.10 alice --ca certs/ca-cert.pem            # 60 s rotation (default)
# bob:     ./client 10.10.0.10 bob   --ca certs/ca-cert.pem
#   type "/e2e bob" on alice, then chat; watch the "E2E rekey -> epoch N" lines.
#   add --rekey 20 to both clients to see rotations sooner.
```
