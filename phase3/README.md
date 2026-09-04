# Phase 3 — Server Authentication via PKI

Phase 2 encrypted the channel but agreed a key with *whoever answered*, which is why the
man-in-the-middle succeeded. Phase 3 authenticates the server: before the key exchange, the server
sends a CA-signed certificate and proves it holds the matching private key. The client validates both
and aborts if anything is wrong. The same MITM proxy now fails.

## Build and set up the PKI

```
make                                   # server, client, mitm, selftest, certcheck

cd pki
./make-ca.sh                           # CA key + self-signed root
./make-server-cert.sh                  # server key + CSR, CA-signed cert (SAN chatserver.local, 10.10.0.10)
./make-attack-certs.sh                 # certs used only to test that validation rejects them
```

Distribute: `ca-cert.pem` to every client; the server keeps `server-cert.pem` + `server-key.pem`.

## Run

```
# server (vm1-server, the CA host)
./server --cert pki/out/server-cert.pem --key pki/out/server-key.pem

# clients (vm2 / vm3)
./client 10.10.0.10 alice --ca certs/ca-cert.pem --expect chatserver.local
```

The client prints `server certificate verified (chatserver.local)` once validation passes.

## What's new since Phase 2

| File | Purpose |
|---|---|
| `pki/*.sh` | OpenSSL scripts: CA, server certificate, test certs |
| `pki.{h,cpp}` | load credentials, validate a peer cert, RSA-SHA256 sign/verify |
| `certcheck.cpp` | runs the client validation logic over a cert, for the validation test |

Changed:

- **Handshake** gains `HS_SERVER_CERT` and `HS_SERVER_PROOF`. The server signs
  `version ‖ client_random ‖ cert ‖ server_pub` with its private key.
- **Client** validates chain → validity → identity → proof of possession, and sends its DH value only
  after all pass; on any failure it sends an alert and closes, revealing nothing.
- **Server** takes `--cert` / `--key`.
- **MITM** takes `--present-cert` / `--present-key` (and `--ca` for its upstream leg).

Unchanged: record framing, AES-256-GCM, the `LOGIN`/`MSG`/`WHO` grammar, routing, the DH group and the
hand-written modular exponentiation.

## Certificate vs. proof of possession

A certificate is a public file: it says a CA vouched that a key belongs to `chatserver.local`, but
anyone can copy it. The **proof of possession** — a signature over this session's transcript, verified
against the certificate's public key — proves the peer actually holds the private key *now*. The
certificate answers "whose key is this?"; the signature answers "does this peer hold it?". Both are
needed, which is why an attacker holding only the certificate file (§4.2) is still rejected.

## The MITM re-run

```
# self-signed cert (fails the chain check):
./mitm --listen 10.10.0.13 --server 10.10.0.10 --ca certs/ca-cert.pem \
       --present-cert certs/mallory-cert.pem --present-key certs/mallory-key.pem

# stolen real cert, no private key (fails proof of possession):
./mitm ... --present-cert certs/server-cert.pem --present-key certs/mallory-own-key.pem
```

Point the victim at `10.10.0.13`; either way the client aborts before sending anything.

## Verification

Evidence in [`../evidence/phase3/`](../evidence/phase3/); full write-up, including the required
certificate-vs-proof explanation, in
[`01-verification.md`](../evidence/phase3/01-verification.md).

| Demo | Key files |
|---|---|
| Legit flow | `chat-transcript.md`, `chat.pcap`, `wireshark-certificate-in-handshake.png` |
| MITM self-signed | `mitm-selfsigned-transcript.md` (rejected: chain) |
| MITM stolen cert | `mitm-stolen-transcript.md` (rejected: proof of possession) |
| Validation branches | `cert-validation.txt` (each bad cert rejected by its own check) |
