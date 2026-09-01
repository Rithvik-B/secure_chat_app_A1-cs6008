# Phase 0 Evidence — Connectivity Verification

Evidence that the lab network described in `01-network-and-vm-configuration.md` is functioning, and
that it satisfies the assignment's prerequisite:

---

## 1. Method

Each check was run from the host via `scripts/connect.sh <role>`, which SSHes to the VM over its
loopback-bound NAT port-forward. Roles: `s` = vm1-server, `c1` = vm2-client1, `c2` = vm3-client2,
`m` = vm4-mallory.

| # | Check | Command | Purpose |
|---|---|---|---|
| 1 | Interface addressing | `ip -br addr` | Both adapters up with the intended addresses |
| 2 | Routing | `ip route` | Correct interface selected per destination |
| 3 | Layer-2 adjacency | `ip neigh` | ARP resolves every peer on `secure-chat` |
| 4 | Reachability | `ping -c1 -W1` ×16 | Every VM reaches every VM |
| 5 | Listening sockets | `ss -lntp` | Chat port 5555 is free |
| 6 | Toolchain | version queries | Build and capture tooling present |

---

## 2. Interface addressing

### `enp0s8` after `netplan apply` — all four VMs

```
=== s  -> 10.10.0.10
enp0s8           UP             10.10.0.10/24 fe80::a00:27ff:fe11:80e/64
=== c1 -> 10.10.0.11
enp0s8           UP             10.10.0.11/24 fe80::a00:27ff:fe2a:3c7b/64
=== c2 -> 10.10.0.12
enp0s8           UP             10.10.0.12/24 fe80::a00:27ff:fe32:22c2/64
=== m  -> 10.10.0.13
enp0s8           UP             10.10.0.13/24 fe80::a00:27ff:fe26:9451/64
```

All four hold their intended static address on the `secure-chat` adapter.

Before configuration, `enp0s8` on every VM had **only** an `fe80::` link-local address and no IPv4 —
the expected state on a VirtualBox Internal Network, which has no DHCP server.

### Full listing — vm1-server (representative)

```
server@vm1-server:~$ ip -br addr
lo               UNKNOWN        127.0.0.1/8 ::1/128
enp0s3           UP             10.0.2.15/24 metric 100 fd17:625c:f037:2:a00:27ff:fe26:4f0d/64 fe80::a00:27ff:fe26:4f0d/64
enp0s8           UP             10.10.0.10/24 fe80::a00:27ff:fe11:80e/64

server@vm1-server:~$ ip -br link
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
enp0s3           UP             08:00:27:26:4f:0d <BROADCAST,MULTICAST,UP,LOWER_UP>
enp0s8           UP             08:00:27:11:08:0e <BROADCAST,MULTICAST,UP,LOWER_UP>
```

Two simultaneous IPv4 addresses on one host — `10.0.2.15` (NAT) and `10.10.0.10` (secure-chat) —
which is normal and is resolved per-packet by the routing table, not by the application.

MACs match the VirtualBox adapter configuration in `01-network-and-vm-configuration.md` §4 exactly.

---

## 3. Routing — vm1-server

```
server@vm1-server:~$ ip route
default via 10.0.2.2 dev enp0s3 proto dhcp src 10.0.2.15 metric 100
10.0.2.0/24 dev enp0s3 proto kernel scope link src 10.0.2.15 metric 100
10.0.2.2 dev enp0s3 proto dhcp scope link src 10.0.2.15 metric 100
10.0.2.3 dev enp0s3 proto dhcp scope link src 10.0.2.15 metric 100
10.10.0.0/24 dev enp0s8 proto kernel scope link src 10.10.0.10
```

Confirms the intended separation:

- `10.10.0.0/24 dev enp0s8` — all chat traffic goes out the assignment network directly, no router
  involved. Installed automatically (`proto kernel`) by assigning the address.
- `default via 10.0.2.2 dev enp0s3` — everything else goes out NAT. This is the **only** default
  route, which is exactly the intent of omitting `gateway4` from `99-secure-chat.yaml`.

Selection is by longest-prefix match: `10.10.0.11` matches the `/24` (24 bits) and `default` (0 bits),
so the `/24` wins and `enp0s3` is never involved.

---

## 4. Layer-2 adjacency — vm1-server

```
server@vm1-server:~$ ip neigh
10.10.0.11 dev enp0s8 lladdr 08:00:27:2a:3c:7b STALE
10.10.0.12 dev enp0s8 lladdr 08:00:27:32:22:c2 STALE
10.10.0.13 dev enp0s8 lladdr 08:00:27:26:94:51 STALE
10.0.2.2 dev enp0s3 lladdr 52:54:00:12:35:00 REACHABLE
10.0.2.3 dev enp0s3 lladdr 52:54:00:12:35:00 STALE
fd17:625c:f037:2::3 dev enp0s3 lladdr 52:54:00:12:35:00 router STALE
fd17:625c:f037:2::2 dev enp0s3 lladdr 52:54:00:12:35:00 router STALE
fe80::2 dev enp0s3 lladdr 52:54:00:12:35:00 router STALE
```

**Cross-check** — resolved MACs against the VirtualBox adapter configuration:

| Peer | ARP-resolved MAC | VirtualBox Adapter 2 MAC | Match |
|---|---|---|---|
| `10.10.0.11` (C1) | `08:00:27:2a:3c:7b` | `08:00:27:2A:3C:7B` | ✓ |
| `10.10.0.12` (C2) | `08:00:27:32:22:c2` | `08:00:27:32:22:C2` | ✓ |
| `10.10.0.13` (M) | `08:00:27:26:94:51` | `08:00:27:26:94:51` | ✓ |

The server has genuine layer-2 adjacency to all three peers on the internal switch, and each address
maps to the correct virtual machine.

Two observations:

- **`STALE` is not a fault.** It means the mapping is held but has not been confirmed in ~30 s; such
  entries are still used immediately. The `secure-chat` entries are stale simply because the pings had
  finished. `10.0.2.2` is `REACHABLE` because the SSH session was actively flowing over `enp0s3` at
  the time — TCP ACKs count as upper-layer confirmation.
- **`10.0.2.2` and `10.0.2.3` share one MAC** (`52:54:00:12:35:00`): the gateway and the DNS resolver
  are the same VirtualBox NAT engine answering to two addresses.

---

## 5. Reachability — full 4×4 ping matrix

```
=== from s ===
10.10.0.10   OK
10.10.0.11   OK
10.10.0.12   OK
10.10.0.13   OK
=== from c1 ===
10.10.0.10   OK
10.10.0.11   OK
10.10.0.12   OK
10.10.0.13   OK
=== from c2 ===
10.10.0.10   OK
10.10.0.11   OK
10.10.0.12   OK
10.10.0.13   OK
=== from m ===
10.10.0.10   OK
10.10.0.11   OK
10.10.0.12   OK
10.10.0.13   OK
```

**Result: 16/16 OK.** Every VM reaches every other VM (and itself) on `secure-chat`.

Sample with timing, vm1-server → vm2-client1:

```
server@vm1-server:~$ ping -c1 -W1 10.10.0.11
PING 10.10.0.11 (10.10.0.11) 56(84) bytes of data.
64 bytes from 10.10.0.11: icmp_seq=1 ttl=64 time=0.295 ms

--- 10.10.0.11 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.295/0.295/0.295/0.000 ms
```

`ttl=64` unchanged from the default confirms **zero router hops** — the peer is directly on-link, as
intended for a single switched segment.

---

## 6. Listening sockets — vm1-server

```
server@vm1-server:~$ ss -lntp
State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port
LISTEN  0       4096     127.0.0.53%lo:53           0.0.0.0:*
LISTEN  0       4096        127.0.0.54:53           0.0.0.0:*
LISTEN  0       4096           0.0.0.0:22           0.0.0.0:*
LISTEN  0       4096              [::]:22              [::]:*
```

- `:22` — sshd, on all interfaces. Reached from the host through the NAT port-forward.
- `127.0.0.53:53`, `127.0.0.54:53` — `systemd-resolved` local DNS stub, loopback only.
- **Port 5555 is free**, as required for the chat server.

Note that sshd reports `systemctl is-active ssh` as `inactive` on these guests. That is not a fault:
Ubuntu ships sshd socket-activated, so `ssh.socket` holds the port and `ssh.service` is spawned per
connection. The correct unit to check is `ssh.socket`.

---

## 7. Toolchain — identical on all four VMs

```
g++ (Ubuntu 15.2.0-16ubuntu1) 15.2.0
OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)
Version: 3.5.5-1ubuntu3.5
TShark (Wireshark) 4.6.4.
/usr/sbin/ip
/usr/bin/ss
/usr/bin/ping
/usr/bin/rsync
/usr/bin/make
```

Sufficient for every phase: a C++ compiler, OpenSSL headers and `libcrypto` (`bn.h`, `evp.h`,
`x509.h`), packet capture, and file transfer.

---

## 8. Conclusion

| Requirement | Status |
|---|---|
| Four VMs on one virtual network (§1.2.1) | ✓ `secure-chat`, 10.10.0.0/24 |
| Separate Mallory VM, distinct from server and clients (§1.2.1) | ✓ vm4-mallory, 10.10.0.13 |
| Connectivity verified with ping before running the application | ✓ 16/16 |
| Build toolchain available on each VM | ✓ g++ 15.2.0, OpenSSL 3.5.5 |
| Packet capture available on the assignment network | ✓ TShark 4.6.4, capture on `enp0s8` |
| Chat port free | ✓ 5555 unused |

The environment is ready for Phase 1.

### Reproducing these checks

```bash
./scripts/vm.sh up

for r in s c1 c2 m; do
  echo "=== $r ==="
  ./scripts/connect.sh $r 'hostname; ip -br addr; echo; ip route; echo; ip neigh'
done

for r in s c1 c2 m; do
  echo "=== from $r ==="
  ./scripts/connect.sh $r 'for ip in 10.10.0.10 10.10.0.11 10.10.0.12 10.10.0.13; do
      printf "%-12s " $ip; ping -c1 -W1 $ip >/dev/null 2>&1 && echo OK || echo FAIL; done'
done
```
