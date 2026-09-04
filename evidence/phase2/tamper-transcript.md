# Phase 2 — Tamper detection (transcript)

Mallory forwards with `--tamper`, flipping one byte of the first chat record. The login (untampered) is accepted; the corrupted chat record fails its AES-GCM tag and the server rejects it and closes the connection — corrupted output is never produced.

Interleaved from the per-party logs in this directory, ordered by timestamp (UTC).

```
05:58:35  SERVER    | START phase2 DH + AES-256-GCM relay on 0.0.0.0:5555 (log: tamper-server.log)
05:58:36  MALLORY   | MITM proxy up on 10.10.0.13:5555 -> 10.10.0.10:5555  [tamper armed]
05:58:39  alice(C1) | key exchange complete, shared-secret fingerprint 04e3daf12049c5a7
05:58:39  alice(C1) | connected to 10.10.0.13:5555 as alice
05:58:39  SERVER    | CONN  10.10.0.12:41698
05:58:39  SERVER    | KEX   10.10.0.12:41698 session established, fingerprint=b68011127c7038cc
05:58:39  SERVER    | LOGIN bob from 10.10.0.12:41698
05:58:39  SERVER    | CONN  10.10.0.13:37774
05:58:39  SERVER    | KEX   10.10.0.13:37774 session established, fingerprint=85e910a7d2c52435
05:58:39  SERVER    | LOGIN alice from 10.10.0.13:37774
05:58:39  MALLORY   | victim connected from 10.10.0.11:49542
05:58:39  MALLORY   | two sessions established -- victim-side fp=04e3daf12049c5a7  server-side fp=85e910a7d2c52435
05:58:39  MALLORY   | [C->S] LOGIN alice
05:58:39  MALLORY   | [S->C] OK alice
05:58:41  alice(C1) | you -> bob: this record will be corrupted in flight
05:58:41  alice(C1) | * server closed the connection
05:58:41  SERVER    | DROP  alice : AES-GCM authentication failed, record rejected
05:58:41  SERVER    | CLOSE alice (peer closed)
05:58:41  MALLORY   | [C->S] MSG bob this record will be corrupted in flight
05:58:41  MALLORY   | [C->S] TAMPERED one byte of the next record
05:58:41  MALLORY   | victim disconnected
05:58:47  SERVER    | QUIT  bob
05:58:47  SERVER    | CLOSE bob (quit)
05:59:10  SERVER    | STOP  shutting down
```
