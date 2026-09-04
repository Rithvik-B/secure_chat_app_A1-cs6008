# Phase 3 — MITM with a stolen certificate, no private key (transcript)

Assignment section 4.2: Mallory has a copy of the real server-cert.pem (a public file) but not its private key. The certificate passes chain, validity and identity, but she cannot produce the proof of possession, so the client rejects her at the signature check and aborts.

Interleaved from the per-party logs in this directory, ordered by timestamp (UTC).

```
06:39:33  SERVER    | START phase3 DH + AES-256-GCM relay, authenticated (PKI) on 0.0.0.0:5555 (log: mitm-stolen-server.log)
06:39:35  MALLORY   | MITM proxy up on 10.10.0.13:5555 -> 10.10.0.10:5555
06:39:37  alice(C1) | handshake aborted: proof of possession failed: server does not hold the certificate's private key
06:39:37  MALLORY   | victim connected from 10.10.0.11:37636
06:39:37  MALLORY   | victim rejected the presented certificate -- attack failed
06:39:56  SERVER    | STOP  shutting down
```
