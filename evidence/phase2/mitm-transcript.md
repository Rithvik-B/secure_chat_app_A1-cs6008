# Phase 2 — MITM attack (transcript)

`alice` (C1) was pointed at Mallory (10.10.0.13) instead of the server; `bob` (C2) talks to the real server. Mallory runs two independent DH exchanges and logs every message in plaintext (the `[C->S]` / `[S->C]` lines) while alice believes the channel is secure. Note the two Mallory fingerprints differ from each other — neither is what alice and bob would have agreed directly.

Interleaved from the per-party logs in this directory, ordered by timestamp (UTC).

```
05:57:37  SERVER    | START phase2 DH + AES-256-GCM relay on 0.0.0.0:5555 (log: mitm-server.log)
05:57:39  MALLORY   | MITM proxy up on 10.10.0.13:5555 -> 10.10.0.10:5555
05:57:41  alice(C1) | key exchange complete, shared-secret fingerprint cfbb2a3efc76a443
05:57:41  alice(C1) | connected to 10.10.0.13:5555 as alice
05:57:41  bob(C2)   | key exchange complete, shared-secret fingerprint ac8c4dd18a4e310e
05:57:41  bob(C2)   | connected to 10.10.0.10:5555 as bob
05:57:41  bob(C2)   | * alice joined
05:57:41  SERVER    | CONN  10.10.0.12:58210
05:57:41  SERVER    | KEX   10.10.0.12:58210 session established, fingerprint=ac8c4dd18a4e310e
05:57:41  SERVER    | LOGIN bob from 10.10.0.12:58210
05:57:41  SERVER    | CONN  10.10.0.13:57834
05:57:41  SERVER    | KEX   10.10.0.13:57834 session established, fingerprint=6d7bdab001012959
05:57:41  SERVER    | LOGIN alice from 10.10.0.13:57834
05:57:41  MALLORY   | victim connected from 10.10.0.11:36722
05:57:41  MALLORY   | two sessions established -- victim-side fp=cfbb2a3efc76a443  server-side fp=6d7bdab001012959
05:57:41  MALLORY   | [C->S] LOGIN alice
05:57:41  MALLORY   | [S->C] OK alice
05:57:43  alice(C1) | you -> bob: this channel feels private to us
05:57:43  bob(C2)   | alice> this channel feels private to us
05:57:43  SERVER    | RELAY alice -> bob : "this channel feels private to us"
05:57:43  MALLORY   | [C->S] MSG bob this channel feels private to us
05:57:47  alice(C1) | bob> agreed, looks perfectly secure
05:57:47  alice(C1) | you -> bob: mallory is reading every word
05:57:47  bob(C2)   | you -> alice: agreed, looks perfectly secure
05:57:47  bob(C2)   | alice> mallory is reading every word
05:57:47  SERVER    | RELAY bob -> alice : "agreed, looks perfectly secure"
05:57:47  SERVER    | RELAY alice -> bob : "mallory is reading every word"
05:57:47  MALLORY   | [S->C] FROM bob agreed, looks perfectly secure
05:57:47  MALLORY   | [C->S] MSG bob mallory is reading every word
05:57:51  alice(C1) | * bye
05:57:51  bob(C2)   | * alice left
05:57:51  SERVER    | QUIT  alice
05:57:51  SERVER    | CLOSE alice (quit)
05:57:51  MALLORY   | [C->S] QUIT
05:57:51  MALLORY   | victim disconnected
05:57:52  bob(C2)   | * bye
05:57:52  SERVER    | QUIT  bob
05:57:52  SERVER    | CLOSE bob (quit)
05:58:17  SERVER    | STOP  shutting down
```
