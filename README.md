# Building a Secure Chat Application

**CS6008 — Network Security.** A one-to-one chat application over TCP sockets, progressively hardened
across five phases. Each phase adds one security property and demonstrates, with evidence, that it
actually holds — including attacking the previous phase to show what the new one defeats.

Written in C++17 over POSIX sockets, using OpenSSL only for low-level primitives (`bn.h`, `evp.h`,
`x509.h`). No TLS library, and Diffie–Hellman is implemented from scratch — `<openssl/ssl.h>` and
`<openssl/dh.h>` are never used.

## The five phases

| Phase | Adds | Attack / proof |
|---|---|---|
| **1** | Plaintext chat: framing, `@user`/`/chat`/`/who`/`/quit`, server relay | Wireshark reads the whole conversation |
| **2** | Diffie–Hellman + AES-256-GCM (DH from scratch, hand-written modexp) | MITM proxy reads everything; tamper rejected |
| **3** | PKI: CA, server certificate, proof of possession | Same MITM now **fails** — bad chain, or stolen cert without the key |
| **4** | End-to-end encryption between clients (`/e2e`), server relays opaque data | Server sees only `__E2E_MSG__`; `server.cpp` unchanged from Phase 3 |
| **5** | Key rotation every 60 s for forward secrecy | A leaked key exposes only one ~60 s window |

Each `phaseN/` is standalone and copies the previous phase forward, so it builds and runs on its own.
The protocol is layered (framing → handshake → record encryption → grammar → end-to-end) so that each
phase *extends* the design rather than rewriting it — see [`docs/protocol.md`](docs/protocol.md).

## Network topology

Four VirtualBox VMs on an isolated internal network (`secure-chat`, `10.10.0.0/24`). A second NAT
adapter on each VM carries internet + host SSH only; all chat traffic and captures happen on
`secure-chat`.

```
                         HOST (no interface on secure-chat)
                                     │
              ┌──────────────────────┴───────────────────────┐
        Adapter 1: NAT (per VM)               Adapter 2: Internal Network "secure-chat"
        internet, apt, host SSH               10.10.0.0/24, no DHCP/router/DNS
                                     │
        ┌───────────────┬───────────┼───────────────┬───────────────┐
   10.10.0.10      10.10.0.11              10.10.0.12          10.10.0.13
   vm1-server      vm2-client1             vm3-client2         vm4-mallory
      (S)              (C1)                    (C2)             (M, MITM)
```

Chat port **5555**. Server certificate identity **`chatserver.local`** (SAN `IP:10.10.0.10`). Mallory
(Phases 2–3) sits between a client and the server. Full detail in
[`evidence/phase0/`](evidence/phase0/).

## Repository layout

```
phase1 .. phase5/   source for each phase (server, client, mitm, selftest, pki/) + README
docs/               protocol.md (the wire protocol), ai-prompts.md (AI-usage appendix)
evidence/phaseN/    per-phase verification doc, transcripts, pcaps, Wireshark screenshots
report/             main.tex -> report.pdf  (the written report)
scripts/            vm.sh, connect.sh, deploy.sh  (drive the lab VMs)
infra/              lab-setup notes and the working design reference (not part of the graded code)
```

## Build and run

Build (on each VM — the guest toolchain differs from the host):

```
cd phaseN && make          # server, client, and (phase 2+) mitm, selftest, certcheck
make test                  # phase 2+: run the crypto self-test
```

Phase 3+ needs a PKI (generate on the server VM, distribute `ca-cert.pem` to clients):

```
cd phase3/pki && ./make-ca.sh && ./make-server-cert.sh && ./make-attack-certs.sh
```

Run a session — server on `vm1-server`, clients on `vm2`/`vm3`:

```
# server
./server                                                         # phase 1-2
./server --cert pki/out/server-cert.pem --key pki/out/server-key.pem   # phase 3+

# client
./client 10.10.0.10 alice                                        # phase 1-2
./client 10.10.0.10 alice --ca certs/ca-cert.pem                 # phase 3+
#   phase 4-5: type "/e2e bob" to start end-to-end; the key rotates every 60 s
```

Deploying from the host uses `./scripts/deploy.sh phaseN s c1 c2 m` (rsync + build on the VMs) and
`./scripts/connect.sh <s|c1|c2|m>` for a shell. Packet capture runs inside a VM
(`sudo tshark -i enp0s8 -f 'tcp port 5555' -w /tmp/x.pcap`), then the pcap is copied to the host for
Wireshark.

## Verification

Each phase's evidence lives in `evidence/phaseN/`, with an `01-verification.md` mapping every
assignment requirement to the file that proves it. The consolidated write-up, with the required
explanations and Wireshark screenshots, is in [`report/report.pdf`](report/report.pdf).
