# Phase 4 — End-to-end encryption (transcript)

The first message is only server-encrypted, so the server logs it in the clear. After `/e2e bob`, both clients derive the same end-to-end fingerprint (`1cf3a119...`), independent of their separate server-session fingerprints, and every message after is `__E2E_MSG__` --- the server's RELAY log shows only opaque base64 (truncated here). `you -> bob [e2e]:` and `bob [e2e]>` mark E2E messages.

Interleaved from the per-party logs, ordered by timestamp (UTC).

```
07:03:43  SERVER    | START phase3 DH + AES-256-GCM relay, authenticated (PKI) on 0.0.0.0:5555 (log: e2e-server.log)
07:03:49  alice(C1) | server certificate verified (chatserver.local); key exchange complete, fingerprint 26ea5ff5cc3fe482
07:03:49  alice(C1) | connected to 10.10.0.10:5555 as alice
07:03:49  bob(C2)   | server certificate verified (chatserver.local); key exchange complete, fingerprint 2138f6c188fe1851
07:03:49  bob(C2)   | connected to 10.10.0.10:5555 as bob
07:03:49  bob(C2)   | * alice joined
07:03:49  SERVER    | CONN  10.10.0.12:57790
07:03:49  SERVER    | KEX   10.10.0.12:57790 session established, fingerprint=2138f6c188fe1851
07:03:49  SERVER    | LOGIN bob from 10.10.0.12:57790
07:03:49  SERVER    | CONN  10.10.0.11:47842
07:03:49  SERVER    | KEX   10.10.0.11:47842 session established, fingerprint=26ea5ff5cc3fe482
07:03:49  SERVER    | LOGIN alice from 10.10.0.11:47842
07:03:51  alice(C1) | you -> bob: this line is only server-encrypted, the server can read it
07:03:51  bob(C2)   | alice> this line is only server-encrypted, the server can read it
07:03:51  SERVER    | RELAY alice -> bob : "this line is only server-encrypted, the server can read it"
07:03:55  alice(C1) | * requesting end-to-end session with bob ...
07:03:55  alice(C1) | * end-to-end session established with bob, fingerprint 1cf3a11922709169
07:03:55  bob(C2)   | * end-to-end session established with alice (they requested it), fingerprint 1cf3a11922709169
07:03:55  SERVER    | RELAY alice -> bob : "__E2E_INIT__BAAAAAABAA1/hzqBYUaCvn0b4MPeLy56TesbOu9cKPWuFhfIwpBHRBR6c1..."
07:03:55  SERVER    | RELAY bob -> alice : "__E2E_ACK__BAAAAAABABH/Oa5OqfPOQsBG3UmHML2FOFheoAl7vxHi46Sputs7/0hqpPq..."
07:03:58  alice(C1) | you -> bob [e2e]: now the server sees only ciphertext for our messages
07:03:58  bob(C2)   | alice [e2e]> now the server sees only ciphertext for our messages
07:03:58  SERVER    | RELAY alice -> bob : "__E2E_MSG__AAAAAKHfPIs0SpKJ+y00bwVM0bvJSfJSx5ODMs9Jz/+OlY4ghjtfcZg2Ocl..."
07:04:01  alice(C1) | bob [e2e]> confirmed, decrypting locally with our shared key
07:04:01  bob(C2)   | you -> alice [e2e]: confirmed, decrypting locally with our shared key
07:04:01  SERVER    | RELAY bob -> alice : "__E2E_MSG__AAAAABzPq0NJ7MlWhESN38oqxLmQsHkIiZUYMenSFbUZhE3KsGbjEgfk2f5..."
07:04:02  alice(C1) | you -> bob [e2e]: end to end, even the relay is blind
07:04:02  bob(C2)   | alice [e2e]> end to end, even the relay is blind
07:04:02  SERVER    | RELAY alice -> bob : "__E2E_MSG__AAAAAOSdL5bHk6Wg/oFaXZQI0P2TY0h4ObI8nKDDMrdnqTP8FjoGT85ejd0..."
07:04:06  alice(C1) | * bob left
07:04:06  alice(C1) | * bye
07:04:06  bob(C2)   | * bye
07:04:06  SERVER    | QUIT  bob
07:04:06  SERVER    | CLOSE bob (quit)
07:04:06  SERVER    | QUIT  alice
07:04:06  SERVER    | CLOSE alice (quit)
07:04:33  SERVER    | STOP  shutting down
```
