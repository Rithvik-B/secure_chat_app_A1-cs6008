# Phase 2 — Encrypted chat session (transcript)

A normal client–server–client session with Phase 2 encryption. `alice` (C1) and `bob` (C2) both hold their own DH session with the server; each client's fingerprint matches the one the server logged for it. `you -> ...` lines are what that user typed; `name>` lines are what they received.

Interleaved from the per-party logs in this directory, ordered by timestamp (UTC).

```
05:56:07  SERVER    | START phase2 DH + AES-256-GCM relay on 0.0.0.0:5555 (log: chat-server.log)
05:56:13  alice(C1) | key exchange complete, shared-secret fingerprint f5b73958da76b903
05:56:13  alice(C1) | connected to 10.10.0.10:5555 as alice
05:56:13  bob(C2)   | key exchange complete, shared-secret fingerprint ef643199d65ce813
05:56:13  bob(C2)   | connected to 10.10.0.10:5555 as bob
05:56:13  bob(C2)   | * alice joined
05:56:13  SERVER    | CONN  10.10.0.12:42666
05:56:13  SERVER    | KEX   10.10.0.12:42666 session established, fingerprint=ef643199d65ce813
05:56:13  SERVER    | LOGIN bob from 10.10.0.12:42666
05:56:13  SERVER    | CONN  10.10.0.11:39236
05:56:13  SERVER    | KEX   10.10.0.11:39236 session established, fingerprint=f5b73958da76b903
05:56:13  SERVER    | LOGIN alice from 10.10.0.11:39236
05:56:15  alice(C1) | * online: alice bob
05:56:15  SERVER    | WHO   alice -> [alice bob]
05:56:17  alice(C1) | you -> bob: hi bob, this is the phase 2 encrypted channel
05:56:17  bob(C2)   | alice> hi bob, this is the phase 2 encrypted channel
05:56:17  SERVER    | RELAY alice -> bob : "hi bob, this is the phase 2 encrypted channel"
05:56:19  alice(C1) | bob> got it, all encrypted end to end with the server
05:56:19  bob(C2)   | you -> alice: got it, all encrypted end to end with the server
05:56:19  SERVER    | RELAY bob -> alice : "got it, all encrypted end to end with the server"
05:56:21  alice(C1) | you -> bob: wireshark should see only ciphertext now
05:56:21  bob(C2)   | alice> wireshark should see only ciphertext now
05:56:21  SERVER    | RELAY alice -> bob : "wireshark should see only ciphertext now"
05:56:24  alice(C1) | * bob left
05:56:24  bob(C2)   | * bye
05:56:24  SERVER    | QUIT  bob
05:56:24  SERVER    | CLOSE bob (quit)
05:56:25  alice(C1) | * bye
05:56:25  SERVER    | QUIT  alice
05:56:25  SERVER    | CLOSE alice (quit)
05:56:52  SERVER    | STOP  shutting down
```
