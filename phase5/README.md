# Phase 5 — Forward Secrecy via Key Rotation

Phase 4 kept one end-to-end key for the whole session, so an attacker who later obtained that key could
read every message ever exchanged. Phase 5 renegotiates the E2E key every 60 s: each new key comes
from a fresh Diffie-Hellman, independent of the last, and the old key is discarded — so a compromised
key exposes only a bounded window of traffic. There is **no wire-format change**; the `epoch` field was
already present in Phase 4, and `server.cpp` is still identical to Phase 3.

## Build and run

```
make            # server, client, mitm, selftest, certcheck
make test       # self-test (now includes a key-rotation section)

./server --cert pki/out/server-cert.pem --key pki/out/server-key.pem
./client 10.10.0.10 alice --ca certs/ca-cert.pem              # 60 s rotation (default)
./client 10.10.0.10 alice --ca certs/ca-cert.pem --rekey 20   # rotate every 20 s (for demos)
```

After `/e2e bob`, the clients rotate on the timer, each printing
`E2E rekey -> epoch N  fingerprint ...` on both ends.

## What's new since Phase 4

| Change | |
|---|---|
| `e2e.{h,cpp}` | epoch state, a `tick()` rotation driver, a grace window, the collision tie-break |
| `client.cpp` | a third thread (`rotation_timer`), the `--rekey` interval override |

- Only the **initiator** (lexicographically smaller username) rotates, at 60 s; the peer holds a 75 s
  fallback if the initiator goes silent; a same-epoch collision is broken deterministically in favour
  of the smaller username. So the two sides can never end up on different keys.
- Each epoch's key is a fresh ephemeral DH, **never** derived from the old one. The retiring key
  lingers ~10 s (decrypt-only) so messages in flight across a rotation still decrypt, then is wiped.
- Every `__E2E_MSG__` carries its epoch, so the recipient always knows which key to use.

Unchanged: the wire format, the `__E2E_*` message format, `server.cpp` (identical to Phase 3), the
outer handshake and encryption, and the application grammar.

## What forward secrecy buys

In Phase 4 one key protects everything: leaking it later decrypts the whole session. In Phase 5,
compromising one epoch's key reveals only that ~60 s window — earlier and later epochs used independent
secrets whose ephemeral private values are gone, so they cannot be reconstructed. That is the guarantee
forward secrecy adds: a key compromised *now* does not retroactively expose already-discarded traffic.

## Verification

Evidence in [`../evidence/phase5/`](../evidence/phase5/); full write-up, including the required
forward-secrecy explanation, in
[`01-verification.md`](../evidence/phase5/01-verification.md).

| Item | Shows |
|---|---|
| `fingerprint-timeline.md` | epoch 0→1→2, fingerprint changing each rotation and matching on both sides |
| `e2e-rekey-transcript.md` | full flow; messages before/across/after each rotation all delivered |
| `selftest.txt` | rotations change + agree on fingerprints; grace-window and post-rotation decrypt |
