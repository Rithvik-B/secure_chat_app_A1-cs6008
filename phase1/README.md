# Phase 1 — Baseline Chat Application (No Security)

A TCP chat server relaying messages between two clients in **plaintext**. The point of this phase is
that the traffic is readable: the server logs every message in full, and Wireshark's Follow → TCP
Stream shows the conversation as text.

## Build

```
make
```

Produces `server` and `client`. Requires g++ with C++17 and pthreads; no external libraries.

## Run

On the server VM (`vm1-server`, 10.10.0.10):

```
./server
```

Options: `--bind ADDR` (default `0.0.0.0`), `--port N` (default `5555`), `--log FILE` (default
`server.log`). The log is written to both stdout and the file.

On the client VMs:

```
./client 10.10.0.10 alice        # on vm2-client1
./client 10.10.0.10 bob          # on vm3-client2
```

Usage: `./client <server-ip> <username> [port]`. Usernames are 1–32 characters,
letters/digits/underscore, and must be unique across connected clients.

## Commands

| Command | Effect |
|---|---|
| `@username message` | Send `message` to `username`, and select them as the current partner |
| `@username` | Select `username` as partner without sending |
| `/chat username` | Select `username` as partner. Sends nothing over the network |
| `/who` | List currently online users |
| `/quit` | Disconnect cleanly and exit |
| anything else | Sent as a chat message to the currently selected partner |

That last row is deliberate. Assignment §1.3: *"Any input that does not match one of the recognized
command tags below should be treated as a plain chat message to whichever user is currently
selected."* So a mistyped `/quti` is transmitted as chat text rather than rejected.

Output prefixes: `alice> text` is an incoming message, `* text` a notice, `!! text` an error.

## Protocol

Full specification in [`../docs/protocol.md`](../docs/protocol.md). Summary of what Phase 1 uses:

### Framing — how a message is known to be complete

Every record on the wire is length-prefixed:

```
[ length : uint32 big-endian ][ type : uint8 ][ body : length-1 bytes ]
```

The receiver reads exactly 4 bytes, decodes the length, then reads exactly that many more. TCP is a
byte stream with no message boundaries — a single `send()` may arrive split across several `recv()`s
or glued to its neighbours — so the length prefix is what defines a message.

A delimiter such as `\n` would have been simpler, and adequate while every payload is printable
text. It was rejected because the body will not stay printable: once payloads carry encrypted data
they are uniformly distributed binary, so roughly 1 byte in 256 equals `0x0A` and a newline-framed
reader would split messages at random. Length prefixing is binary-safe, so the framing does not have
to be revisited later.

Declared lengths above 16384 are rejected before any allocation, so a peer cannot trigger a huge
allocation with a forged length field.

`type` is `0x02` (application data). `0x01` and `0x03` are reserved, so adding record kinds later
needs no version bump or parser change.

### Message grammar

Client → server: `LOGIN <user>`, `MSG <to> <text>`, `WHO`, `QUIT`
Server → client: `OK <user>`, `ERR <reason>`, `FROM <sender> <text>`, `USERS <names…>`, `INFO <text>`

`LOGIN` registers a username for routing only — there is no password. The assignment never requires
user authentication, and its reference to protecting a login exchange is explicitly conditional
("if applicable").

### Routing, and more than two clients

The server keeps a `username → socket` map, so routing is a lookup and the design already handles
more than the two clients Phase 1 requires. `WHO` returns the list sorted, so captured evidence is
comparable between runs. On `MSG <to> <text>` it looks up `<to>`, forwards
`FROM <sender> <text>`, and replies `ERR no such user: <to>` if absent. Broadcast is only used for
join/leave notices.

**The server parses exactly two tokens of a `MSG`: the verb and the recipient.** `<text>` is copied
byte-for-byte and never inspected, so the relay stays independent of whatever the clients put in it.

## Architecture

**Server** — single-threaded, `poll()`-driven, sockets non-blocking. Each connection owns an inbound
`RecordReader` (which buffers partial records) and an outbound byte queue flushed on `POLLOUT`. No
client can stall the server by sending half a record or by refusing to read.

**Client** — two threads: the main thread reads stdin, a reader thread blocks on the socket. The
socket stays blocking because each thread blocks on its own source. Terminal output is serialised
behind a mutex.

Both processes ignore `SIGPIPE`, so a peer disappearing yields an error return rather than killing
the process.

## Verification

Server log (`server.log`) records every relayed message with full content:

```
[2026-09-04T00:54:56Z] RELAY   alice -> bob   : "hey bob, are you there?"
[2026-09-04T00:55:02Z] UNDELIV alice -> carol : "nobody home"
```

`RELAY` is written only after the recipient resolves, so it means the message was delivered.
Undeliverable messages get their own tag, still with the full text.

Packet capture runs inside a VM — the host has no interface on `secure-chat` and cannot see this
traffic:

```
sudo tshark -i enp0s8 -f 'tcp port 5555' -w /tmp/cap.pcap
```

Write captures to `/tmp`, not to a home directory: `dumpcap` drops privileges even under `sudo`, and
Ubuntu's AppArmor profile also blocks `tshark -r` from reading files under `/home`.

Copy the `.pcap` to the host, open in Wireshark, right-click a packet → Follow → TCP Stream. The
conversation appears as readable text.

Evidence for this phase is in [`../evidence/phase1/`](../evidence/phase1/):

| File | Contents |
|---|---|
| `server.pcap` | Capture on the server VM, both client connections |
| `c1.pcap`, `c2.pcap` | Captures on each client VM |
| `server.log` | Relay log with full message content |
| `wireshark-packet-list.png` | Packet view with plaintext in the bytes pane |
| `wireshark-follow-tcp-stream.png` | Follow → TCP Stream, whole conversation |
