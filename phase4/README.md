# Phase 4 — End-to-End Encryption Between Clients

Phases 2–3 secure the client–server link, but the server still reads every message it relays. Phase 4
adds a second encryption layer directly between the two clients that the server cannot read. It lives
inside the `<text>` field of `MSG`/`FROM`, so the server's routing is unchanged — and, as proof,
`server.cpp` is **byte-for-byte identical to Phase 3**.

## Build and run

```
make                                   # server, client, mitm, selftest, certcheck
make test                              # self-test (now includes base64 + E2E)

# same as Phase 3
./server --cert pki/out/server-cert.pem --key pki/out/server-key.pem
./client 10.10.0.10 alice --ca certs/ca-cert.pem
```

## Using end-to-end

```
@bob hello          # plain — the server relays and can read it
/e2e bob            # establish an end-to-end session with bob
@bob secret         # now E2E-encrypted; the server sees only __E2E_MSG__<base64>
```

Both clients print a matching end-to-end fingerprint; E2E messages show as `you -> bob [e2e]:` and
`bob [e2e]>`.

## What's new since Phase 3

| File | Purpose |
|---|---|
| `e2e.{h,cpp}` | per-peer E2E session: a second DH, key derivation, seal/open |
| `crypto` | added base64 (E2E payloads ride as text inside `<text>`) |
| `client.cpp` | `/e2e` command, tag dispatch, downgrade + escaping rules |

Changed:

- The **client** runs a second Diffie-Hellman directly with a peer (same MODP-2048 group), keyed
  independently of the server, and encrypts chat to that peer *inside* the existing server link.
- Incoming `FROM` is dispatched on the `__E2E_*` tag prefix; handshake tags are never shown as chat,
  a chat tag is decrypted, everything else is plain.
- The reader thread now also sends (E2E acks), so sends are mutex-serialised.

Unchanged: `server.cpp` (identical to Phase 3), record framing, the outer handshake and encryption,
the `LOGIN`/`MSG`/`WHO` grammar, routing, the DH group and modular exponentiation.

## How the two layers stack

```
plaintext --[C1<->C2 key]--> __E2E_MSG__<b64>  --[client<->server key]--> on the wire
```

An E2E message is encrypted twice. The server can decrypt the outer layer (it logs the base64), but
not the inner one; a wire sniffer sees neither, not even the tag. Only the two clients hold the inner
key.

## Robustness (§1.4 property 2)

- **Escaping** — outgoing text starting with `__E2E` is refused, so a user cannot forge a tag.
- **Downgrade warning** — a plain message from a peer with an active E2E session is flagged, not shown
  as normal chat, so a relay could not silently strip the inner layer.

## Verification

Evidence in [`../evidence/phase4/`](../evidence/phase4/); full write-up in
[`01-verification.md`](../evidence/phase4/01-verification.md).

| Item | Shows |
|---|---|
| `e2e-transcript.md` | full flow: matching E2E fingerprints, server log opaque after `/e2e` |
| `server-view.txt` | the §5.2 contrast — readable before, `__E2E_MSG__` after |
| `wireshark-wire-is-opaque.png` | the wire carries only ciphertext (double-encrypted) |
| `selftest.txt` | base64 round-trips; E2E fingerprints match; messages decrypt; outsider cannot |
