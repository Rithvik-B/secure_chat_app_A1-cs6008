# Phase 4 Verification — End-to-End Encryption Between Clients

Evidence for assignment §5. Server on `vm1-server` (10.10.0.10), `alice` on `vm2-client1`, `bob` on
`vm3-client2`. No Mallory is needed in this phase.

One demo, collected from one run:

| Files | Transcript |
|---|---|
| `e2e-alice.log`, `e2e-bob.log`, `e2e-server.log`, `e2e.pcap`, `server-view.txt` | `e2e-transcript.md` |

## 1. Requirements → evidence

| §5 requirement | Evidence | Result |
|---|---|---|
| C1↔C2 shared secret, independent of and not derivable by the server | `e2e-transcript.md`; server relays only tags | ✓ separate DH between the clients |
| Triggered by `/e2e username`, using `__E2E_INIT__/ACK/MSG` tags | `e2e-transcript.md` | ✓ |
| Server routing unchanged; it forwards opaque data | `server.cpp` identical to Phase 3 (below) | ✓ |
| Server sees only opaque data for E2E chat; contrast a pre-E2E message | `server-view.txt`, `e2e-server.log` | ✓ readable before, `__E2E_MSG__` after |
| Independent fingerprints on both clients match | `e2e-transcript.md` | ✓ both `1cf3a11922709169` |
| A C1 message is correctly decrypted and displayed by C2 | `e2e-transcript.md` | ✓ `alice [e2e]> ...` on bob |
| E2E is an inner layer, inside the Phase 3 client-server link | §4 below | ✓ double-encrypted on the wire |
| Handshake tags never shown as chat; chat never treated as handshake | `client.cpp` dispatch; transcript | ✓ |

## 2. The server does not change — §1.4 property (1)

`phase4/server.cpp` is **byte-for-byte identical** to `phase3/server.cpp`:

```
$ diff phase3/server.cpp phase4/server.cpp   # (no output — identical)
```

The entire E2E feature lives in the client (`e2e.{h,cpp}` and `client.cpp`). The server's routing
forwards the `<text>` field verbatim, exactly as in every earlier phase, and never learns the E2E
tags exist. A visible consequence: the Phase 4 server's start banner still reads `START phase3 ...`,
because it is the same binary — which is itself the proof that the relay was not modified.

## 3. Matching fingerprints, server relays opaque data — §5.2

From `e2e-transcript.md`, `alice` and `bob` each print an end-to-end fingerprint after `/e2e`, and the
two match — independent of the separate fingerprints of their client-server sessions:

```
alice(C1) | server session fingerprint 26ea5ff5cc3fe482
bob(C2)   | server session fingerprint 2138f6c188fe1851
alice(C1) | end-to-end session established with bob,   fingerprint 1cf3a11922709169
bob(C2)   | end-to-end session established with alice, fingerprint 1cf3a11922709169   <- matches
bob(C2)   | alice [e2e]> now the server sees only ciphertext for our messages         <- decrypted
```

The server relay log (`server-view.txt`) shows the required before/after contrast:

```
before /e2e:  RELAY alice -> bob : "this line is only server-encrypted, the server can read it"
after  /e2e:  RELAY alice -> bob : "__E2E_MSG__AAAAAKHfPIs0SpKJ+y00bwVM0bvJSfJSx5ODMs9Jz/+OlY4..."
              RELAY bob -> alice : "__E2E_MSG__AAAAABzPq0NJ7MlWhESN38oqxLmQsHkIiZUYMenSFbUZhE3..."
```

The server can read the outer client-server layer — it logged the first message in full — yet after
`/e2e` it sees only opaque base64 for chat content. Only `alice` and `bob` hold the inner key.

## 4. Inner layer, inside the Phase 3 link — §5.1

An E2E message is encrypted twice: with the C1↔C2 key (inner), then with the client-server key (outer)
when `send_line` transmits it. So even a passive wire sniffer sees nothing --- not even the
`__E2E_MSG__` tag, which is inside the outer ciphertext. Searching `e2e.pcap` for every keyword found
them all zero except `chatserver.local`, which appears once (the certificate in the handshake):

```
__E2E_ : 0    E2E_MSG : 0    MSG : 0    FROM : 0    "server-encrypted" : 0    chatserver : 1 (frame 6, the cert)
```

`wireshark-wire-is-opaque.png` shows the Follow → TCP Stream: the certificate is readable in the
handshake, everything after is ciphertext. So the E2E content is hidden from the wire *and* from the
relay; only the two endpoints can read it.

## 5. Dispatch, and its robustness rules — §1.4 property (2)

The client checks the tag prefix of each incoming `FROM sender <text>`:

| Prefix | Action |
|---|---|
| `__E2E_INIT__` / `__E2E_ACK__` | complete the handshake; **never** shown as chat |
| `__E2E_MSG__` | decrypt and show as `sender [e2e]> ...` |
| anything else | shown as plain chat |

Two defensive rules (in `client.cpp`), confirmed by the self-test and code:

- **Escaping.** A user who types text starting with `__E2E` is refused (`messages starting with __E2E
  are reserved`), so a user cannot forge a protocol tag.
- **Downgrade warning.** If a *plain* message arrives from a peer with an active E2E session, it is
  flagged (`WARNING: unencrypted message ... while E2E is active`) rather than shown as normal chat,
  so a relay that stripped the inner layer could not do so silently.

## 6. Self-test

`selftest.txt` adds base64 round-trips (every length 0..256) and an end-to-end session test:
independently-computed fingerprints match, messages decrypt both ways, and a third party without the
session cannot open a message.

## 7. Threat model note

Phase 4 protects message content from the relay: an honest-but-curious server that faithfully forwards
cannot derive the E2E key or read the messages. It does not, on its own, authenticate the two clients
to each other, so a *malicious* server could attempt to man-in-the-middle the E2E handshake — the same
class of attack Phase 3 addressed for the client-server link. The assignment scopes Phase 4 to
server-blindness (§5.1: "independent of, and never derivable by, the server, while still using the
server purely as a message relay"), which is what the evidence above demonstrates.

## 8. Changed since Phase 3

- **Added** `e2e.{h,cpp}` and base64 helpers in `crypto`; the `/e2e` command and the tag dispatch in
  the client.
- **Client** now runs a second DH directly with a peer and encrypts chat to that peer inside the
  existing server link; the reader thread also sends (E2E acks), so sends are mutex-serialised.
- **Unchanged**: `server.cpp` (identical to Phase 3), the record framing, the outer handshake and
  encryption, and the application grammar.

## 9. Reproducing

```bash
./scripts/deploy.sh phase4 s c1 c2
# server:  ./server --cert pki/out/server-cert.pem --key pki/out/server-key.pem
# alice:   ./client 10.10.0.10 alice --ca certs/ca-cert.pem
#            @bob hello           (plain — server can read)
#            /e2e bob             (establish end-to-end)
#            @bob secret          (E2E — server sees only __E2E_MSG__)
# bob:     ./client 10.10.0.10 bob --ca certs/ca-cert.pem
```
