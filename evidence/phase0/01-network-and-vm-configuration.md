# Phase 0 Evidence — Network and VM Configuration

Reference record of the lab environment: what the machines are, how they are wired, and what
addresses they hold. Companion to `02-connectivity-verification.md`, which shows this configuration
actually working.

---

## 1. Host environment

| Item | Value |
|---|---|
| OS | Ubuntu 24.04.4 LTS |
| Kernel | 7.0.0-30-generic |
| VirtualBox | 7.2.16r174877 (Oracle repository build) |
| VM storage | `/home/rithvik/VirtualBox VMs/` |
| Host toolchain | g++ 13.3.0, GNU Make 4.3, OpenSSL 3.0.13 |

The host is **not** attached to the assignment network. It has no interface on the `secure-chat`
Internal Network, and therefore cannot observe chat traffic. All packet capture happens inside the
VMs; `.pcap` files are copied to the host afterwards for analysis in the Wireshark GUI.

---

## 2. Topology

```
                              HOST — Ubuntu 24.04.4 LTS
                          (no interface on secure-chat)
                                       │
        ┌──────────────────────────────┴────────────────────────────────┐
        │                                                               │
  Adapter 1: NAT                                       Adapter 2: Internal Network
  one isolated 10.0.2.0/24 per VM                              "secure-chat"
  internet + apt + inbound SSH                          10.10.0.0/24, no DHCP,
  via 127.0.0.1 port-forwards                           no router, no DNS
        │                                                               │
        │              ┌───────────────┬───────────────┬────────────────┤
        │         10.10.0.10      10.10.0.11      10.10.0.12      10.10.0.13
        │         vm1-server      vm2-client1     vm3-client2     vm4-mallory
        │             (S)             (C1)            (C2)             (M)
        │              │               │               │                │
        └──────────────┴───────────────┴───────────────┴────────────────┘
```

All chat traffic, all packet captures, and all MITM work happen on `secure-chat`. The NAT adapter
exists only so the VMs can install packages and so the host can SSH in.

---

## 3. Virtual machine configuration

| | vm1-server (S) | vm2-client1 (C1) | vm3-client2 (C2) | vm4-mallory (M) |
|---|---|---|---|---|
| RAM | 2048 MB | 1536 MB | 1536 MB | 1536 MB |
| vCPUs | 2 | 2 | 2 | 2 |
| Disk | 15 GB VDI | 10 GB VDI | 10 GB VDI | 10 GB VDI |
| Firmware | BIOS | BIOS | BIOS | BIOS |
| Guest OS | Ubuntu 26.04.1 LTS Server | ← same | ← same | ← same |
| Guest user | `server` | `client` | `client` | `mallory` |
| Host SSH port | 2201 | 2202 | 2203 | 2204 |

Total footprint with all four running: **6656 MB** of host RAM.

> installed from `ubuntu-26.04.1-live-server-amd64.iso` 

### Guest toolchain (identical on all four)

| Component | Version |
|---|---|
| g++ | 15.2.0 (Ubuntu 15.2.0-16ubuntu1) |
| OpenSSL | 3.5.5 (27 Jan 2026) |
| libssl-dev | 3.5.5-1ubuntu3.5 |
| TShark | 4.6.4 |
| Also present | `rsync`, `make`, `ip`, `ss`, `ping` |

Guest OpenSSL (3.5.5) differs from host OpenSSL (3.0.13). All binaries are therefore compiled **on
the VMs**; any host build is a syntax check only.

---

## 4. Network adapters

Every VM has two adapters, both Intel PRO/1000 MT Desktop (`82540EM`), cable connected.

### Adapter 1 — NAT

| VM | MAC | Guest interface | Address |
|---|---|---|---|
| vm1-server | `08:00:27:26:4F:0D` | `enp0s3` | `10.0.2.15/24` (DHCP) |
| vm2-client1 | `08:00:27:1F:38:6B` | `enp0s3` | `10.0.2.15/24` (DHCP) |
| vm3-client2 | `08:00:27:40:2A:B2` | `enp0s3` | `10.0.2.15/24` (DHCP) |
| vm4-mallory | `08:00:27:E5:04:D4` | `enp0s3` | `10.0.2.15/24` (DHCP) |

**The identical address on all four is correct, not a misconfiguration.** VirtualBox NAT creates a
separate, isolated network *per VM* rather than one shared network. Within each, the layout is always
gateway `10.0.2.2`, DNS `10.0.2.3`, guest `10.0.2.15`. These addresses have meaning only inside their
own VM's NAT network and are never compared against each other.

The direct consequence: **VMs cannot reach one another over NAT** — from C1, `10.0.2.15` means
*itself*. That is precisely why Adapter 2 exists.

### Adapter 2 — Internal Network `secure-chat`

| VM | MAC | Guest interface | Address |
|---|---|---|---|
| vm1-server | `08:00:27:11:08:0E` | `enp0s8` | `10.10.0.10/24` (static) |
| vm2-client1 | `08:00:27:2A:3C:7B` | `enp0s8` | `10.10.0.11/24` (static) |
| vm3-client2 | `08:00:27:32:22:C2` | `enp0s8` | `10.10.0.12/24` (static) |
| vm4-mallory | `08:00:27:26:94:51` | `enp0s8` | `10.10.0.13/24` (static) |

Promiscuous mode: **Deny** (VirtualBox default, unchanged). Not required, because the Phase 2/3 MITM
demonstration points the victim client at Mallory's address explicitly — permitted by assignment
§3.3. Only a fully transparent ARP-spoofing variant would need `Allow All`.

A VirtualBox Internal Network is a bare virtual Ethernet switch: **no DHCP server, no router, no
DNS**, and no connection to the host or the outside world. Hence static addressing, and hence the
isolation that makes the captures meaningful.

`08:00:27` is the OUI registered to Oracle VirtualBox — every VirtualBox NIC carries it.

---

## 5. Address plan

| Role | VM | `secure-chat` address | Purpose |
|---|---|---|---|
| S | vm1-server | `10.10.0.10` | chat server; Phase 3 CA host |
| C1 | vm2-client1 | `10.10.0.11` | client 1 |
| C2 | vm3-client2 | `10.10.0.12` | client 2 |
| M | vm4-mallory | `10.10.0.13` | MITM proxy (Phases 2–3) |

Network `10.10.0.0/24` — usable `.1`–`.254`, broadcast `.255`, netmask `255.255.255.0`.
RFC 1918 private space, never routed on the public internet.

**Service port: 5555.** Mallory's proxy listens on `10.10.0.13:5555` and forwards to
`10.10.0.10:5555`.

**Phase 3 server identity:** certificate CN/SAN `chatserver.local`, plus SAN `IP:10.10.0.10`.

---

## 6. Host → guest SSH access

NAT is a one-way door: outbound works, but nothing outside can initiate a connection inward. Each VM
therefore has an explicit NAT port-forward rule.

| VM | Rule |
|---|---|
| vm1-server | `Forwarding(0)="ssh,tcp,127.0.0.1,2201,,22"` |
| vm2-client1 | `Forwarding(0)="ssh,tcp,127.0.0.1,2202,,22"` |
| vm3-client2 | `Forwarding(0)="ssh,tcp,127.0.0.1,2203,,22"` |
| vm4-mallory | `Forwarding(0)="ssh,tcp,127.0.0.1,2204,,22"` |

Format: `name,protocol,host-ip,host-port,guest-ip,guest-port`. The guest-ip field is empty so the rule
applies to whatever address the guest's DHCP lease gives it.

Bound to **`127.0.0.1`, not `0.0.0.0`** — these SSH doors are reachable only from this host, never
from other machines on the LAN.

Authentication is by password (lab-only decision, recorded in `infra/docs/01-lab-setup.md` §5).

Access helpers: `scripts/connect.sh <s|c1|c2|m>` and `scripts/vm.sh {up|down|status|kill}`.

---

## 7. Guest network configuration

`enp0s3` is configured by the Ubuntu installer's `/etc/netplan/00-installer-config.yaml` (DHCP) and
was **not modified**.

`enp0s8` is configured by a separate file, `/etc/netplan/99-secure-chat.yaml` — separate so that a
mistake can never break the interface carrying the SSH session, and `99-` so it sorts after `00-`.

```yaml
network:
  version: 2
  ethernets:
    enp0s8:
      dhcp4: false
      addresses:
        - 10.10.0.10/24        # .11 on C1, .12 on C2, .13 on M
```

File mode `600` (netplan refuses world-readable configuration). Applied with `sudo netplan apply`.

**Deliberately no `gateway4`, no `routes`, no `nameservers`.** `secure-chat` has no router and no DNS.
A default route here would tie with the NAT adapter's `0.0.0.0/0` route and could hand internet
traffic to a network with nothing to forward it — breaking connectivity intermittently.
