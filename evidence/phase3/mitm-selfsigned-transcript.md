# Phase 3 — MITM with a self-signed certificate (transcript)

The same MITM that succeeded in Phase 2, re-run. Mallory cannot obtain a CA-signed certificate, so she presents a self-signed one with the right name. The victim's chain check fails and the client aborts BEFORE sending its DH value or any message. Contrast Phase 2, where this attack read every message.

Interleaved from the per-party logs in this directory, ordered by timestamp (UTC).

```
06:39:11  SERVER    | START phase3 DH + AES-256-GCM relay, authenticated (PKI) on 0.0.0.0:5555 (log: mitm-selfsigned-server.log)
06:39:12  MALLORY   | MITM proxy up on 10.10.0.13:5555 -> 10.10.0.10:5555
06:39:14  MALLORY   | victim connected from 10.10.0.11:53338
06:39:14  MALLORY   | victim rejected the presented certificate -- attack failed
06:39:15  alice(C1) | handshake aborted: certificate rejected: not signed by the trusted CA
06:39:33  SERVER    | STOP  shutting down
```
