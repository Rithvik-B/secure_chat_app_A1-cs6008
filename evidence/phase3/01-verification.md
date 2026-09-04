# Phase 3 Verification — Server Authentication via PKI

Evidence for assignment §4. Same lab: server on `vm1-server` (10.10.0.10), clients on `vm2-client1`
/ `vm3-client2`, Mallory on `vm4-mallory` (10.10.0.13). The CA is hosted on the server VM (§1.2.1).

Demos, each collected from one run:

| Demo | Files | Transcript |
|---|---|---|
| Legit authenticated chat | `chat-alice.log`, `chat-bob.log`, `chat-server.log`, `chat.pcap` | `chat-transcript.md` |
| MITM, self-signed cert | `mitm-selfsigned-*.log` | `mitm-selfsigned-transcript.md` |
| MITM, stolen cert no key | `mitm-stolen-*.log` | `mitm-stolen-transcript.md` |
| Certificate validation | `cert-validation.txt` | — |

---

## 1. The PKI

Created with OpenSSL on the server VM (`phase3/pki/*.sh`): a CA (private key + self-signed root),
then a server key and CSR that the CA signs into `server-cert.pem`. `cert-validation.txt` shows the
certificate summary:

```
issuer=C=IN, O=CS6008 Secure Chat, CN=CS6008 Root CA
subject=C=IN, O=CS6008 Secure Chat, CN=chatserver.local
X509v3 Subject Alternative Name: DNS:chatserver.local, IP Address:10.10.0.10
```

`openssl verify` independently confirms the chain: `server-cert.pem: OK`. The public `ca-cert.pem` and
`server-cert.pem` are included here as artifacts.

## 2. Requirements → evidence

| §4 requirement | Evidence | Result |
|---|---|---|
| CA (key + self-signed root), server key+CSR, CA-signed cert | `pki/*.sh`, `cert-validation.txt` | ✓ |
| Server sends its certificate before the DH exchange | `wireshark-certificate-in-handshake.png` | ✓ cert is frame 6 of the handshake |
| Client validates chain against its trusted CA | `cert-validation.txt`; `mitm-selfsigned-transcript.md` | ✓ self-signed rejected |
| Client validates the validity period | `cert-validation.txt` | ✓ expired cert rejected |
| Client validates the expected identity | `cert-validation.txt` | ✓ wrong-name cert rejected |
| On failure: abort, send no password / no DH / nothing further | `mitm-*-transcript.md` | ✓ client aborts before ClientKex |
| Server proves possession of the private key | protocol §L2; `mitm-stolen-transcript.md` | ✓ signs the transcript |
| Full legitimate flow works | `chat-transcript.md` | ✓ validated, DH completes, chat flows |
| Same MITM re-run now fails | `mitm-selfsigned-transcript.md` | ✓ chain check fails |
| Attacker with real cert file but not the key is rejected | `mitm-stolen-transcript.md` | ✓ PoP fails |

## 3. Legitimate flow (§4.2)

From `chat-transcript.md`, each client validates the certificate and only then proceeds:

```
alice(C1) | server certificate verified (chatserver.local); key exchange complete, fingerprint 6069079c...
bob(C2)   | server certificate verified (chatserver.local); key exchange complete, fingerprint ...
```

The chat then runs encrypted exactly as in Phase 2. On the wire
(`wireshark-certificate-in-handshake.png`) the certificate is visible in the clear in the handshake —
which is correct, a certificate is public — with `CS6008 Secure Chat`, `CS6008 Root CA` and
`chatserver.local` readable in frame 6. No chat word appears anywhere in `chat.pcap`; the content
stays encrypted. `wireshark-follow-tcp-stream.png` shows the same: readable certificate, then
ciphertext.

## 4. Certificate validation, each check (§4.1)

`cert-validation.txt` runs the client's own validation logic (`pki::validate_cert`, via the
`certcheck` tool) over every certificate variant. Each bad certificate is rejected by exactly the
check that should catch it:

```
ACCEPT  server-cert.pem    : ok
REJECT  mallory-cert.pem   : not signed by the trusted CA        <- check (a) chain
REJECT  expired-cert.pem   : outside its validity period         <- check (b) validity
REJECT  wrongname-cert.pem : identity does not match expected server  <- check (c) identity
```

## 5. MITM re-run — now defeated (§4.2)

**Self-signed certificate.** Mallory cannot get a CA-signed certificate, so she presents a self-signed
one with the correct name. `mitm-selfsigned-transcript.md`:

```
MALLORY   | victim connected from 10.10.0.11:53338
MALLORY   | victim rejected the presented certificate -- attack failed
alice(C1) | handshake aborted: certificate rejected: not signed by the trusted CA
```

The client aborts at the chain check, **before** sending its DH value or any message. Contrast Phase 2,
where this exact proxy read every message.

**Stolen certificate, no private key (§4.2).** Mallory copies the real `server-cert.pem` (a public
file) but does not have its private key, so she signs the proof with a key of her own.
`mitm-stolen-transcript.md`:

```
alice(C1) | handshake aborted: proof of possession failed: server does not hold the certificate's private key
MALLORY   | victim rejected the presented certificate -- attack failed
```

The certificate passes chain, validity and identity — but the proof of possession fails, because the
signature does not verify against the certificate's public key. The client aborts.

## 6. Required explanation — certificate vs. proof of possession

A certificate proves only that a CA once vouched that a public key belongs to `chatserver.local`. It
is a public file; anyone can copy it. What a certificate does **not** prove is that the party
presenting it right now actually holds the corresponding private key. That gap is the "stolen
certificate" attack of §4.2.

Proof of possession closes it. The server signs, with its private key, a value built from *this*
handshake — `version ‖ client_random ‖ cert ‖ server_dh_pub` — and the client verifies the signature
against the public key inside the certificate. Only the holder of the private key can produce a
signature that verifies. The 32-byte `client_random` makes the signed value unique to this session, so
a signature captured from a real session cannot be replayed into another. Together: the certificate
says *who* the key belongs to; the signature proves the peer *holds* that key, now.

## 7. Changed since Phase 2

- **Added** a PKI (`phase3/pki/`), a `pki.{h,cpp}` module, and two handshake messages:
  `HS_SERVER_CERT` and `HS_SERVER_PROOF`.
- The **client** now validates the certificate (chain → validity → identity) and the proof of
  possession before contributing its DH value, aborting on any failure.
- The **server** loads a certificate and key (`--cert`, `--key`) and signs the handshake.
- The **MITM proxy** now presents a certificate and signs with a key; in Phase 3 neither a self-signed
  cert nor a stolen cert (whose key it lacks) passes validation.
- **Unchanged**: record framing, AES-256-GCM, application grammar, routing, the DH group and modexp.

## 8. Reproducing

```bash
# generate the PKI (on the server VM, the CA host)
cd phase3/pki && ./make-ca.sh && ./make-server-cert.sh && ./make-attack-certs.sh

# distribute: ca-cert.pem -> clients; server-cert.pem (as "stolen") -> mallory

# legit:  server:  ./server --cert pki/out/server-cert.pem --key pki/out/server-key.pem
#         client:  ./client 10.10.0.10 alice --ca certs/ca-cert.pem --expect chatserver.local

# MITM self-signed:  ./mitm --listen 10.10.0.13 --server 10.10.0.10 --ca certs/ca-cert.pem \
#                          --present-cert certs/mallory-cert.pem --present-key certs/mallory-key.pem
# MITM stolen cert:  ./mitm ... --present-cert certs/server-cert.pem --present-key certs/mallory-own-key.pem
#   then point the victim at 10.10.0.13; it aborts either way.

# validation branches:  ./certcheck --ca pki/out/ca-cert.pem --cert <any cert>
```
