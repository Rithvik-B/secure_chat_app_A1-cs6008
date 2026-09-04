# Phase 0 — Lab Infrastructure

**This is the section which I used most AI regarding setup and understading VM's networking and other configurations before actual assignment work**
**Rest all phases (actual project phases) are done without much use of AI**
**Main AI usage was used to write scripts to automate tests (.sh files)**

Environment bring-up: VirtualBox VMs, SSH access, package installation, the `secure-chat` network,
and the supporting documentation. No application code in this phase.

## 0.1 Planning and ground rules

1. *(Long context document.)* Supplied a written hand-off describing the assignment, the host
   environment, the four existing VMs, the VirtualBox network topology already configured, and what
   remained TODO. Asked for a plan, with the assignment PDF attached.
   → Produced a staged plan covering infrastructure through Phase 5.

2. *"lets do step by step, I want to learn and write code on my own, your goal should be like a helper
   telling me what to read, how to implement and what commands to run, you are not supposed to write
   anything and run anything, everything should be done by me, but under your supervision"*
   → Established mentor mode: explanations and specifications from the assistant, all code and
   commands from the author.

## 0.2 SSH access to the VMs

3. *"what all left to do before we start phase 1"* — asked at intervals to confirm remaining work.

4. Pasted `ssh` failure output: `kex_exchange_identification: read: Connection reset by peer`.
   → Diagnosed as the NAT port-forward working but no sshd listening in the guest.

5. *"ssh worked, hostname is vm1-server"* / *"done with setup of all 4"*
   → Progress checkpoints.

## 0.3 SSH, Network Configuration and Tooling

6. *"i actually want a script to 1. on and off vms 2. open connection shortcut (I dont want
   persistant, just short single command like ./connect.sh s)"*
   → Produced `scripts/vm.sh` (`up`/`down`/`status`/`kill` by role) and `scripts/connect.sh` (shell or
   one-shot command by role, auto `-t` for `sudo`). SSH connection multiplexing deliberately rejected,
   since `ControlPersist` would leave an authenticated session open in the background.

7. *"first i have to setup tshark.. and what else do we need?"*
   → Package list per role: `build-essential`, `libssl-dev`, `tshark`, `rsync` on all four VMs;
   `wireshark`, `build-essential`, `libssl-dev` on the host. Established that git runs host-side only.

8. Pasted `ip -br addr` and `ls /etc/netplan/` output from all four VMs.
    → Confirmed `enp0s3` = NAT (`10.0.2.15/24`) and `enp0s8` = `secure-chat` with no IPv4 address.
    Produced `/etc/netplan/99-secure-chat.yaml` assigning static `10.10.0.10-13/24` — as a separate
    file from the installer's, with no gateway or DNS so the default route stays on the NAT adapter.

9. Pasted toolchain and ping-matrix verification output from all four VMs.
    → Confirmed g++ 15.2.0, OpenSSL 3.5.5, libssl-dev, TShark 4.6.4 and `rsync` present on every VM,
    and a 16/16 ping matrix across `secure-chat`. Environment signed off as ready for Phase 1.

## 0.4 Documentation

10. *"before we continue further, first write all the things we did so far regarding infra in
    infra/docs/ as most of the things we did manually, not maintained and documented, i want to save
    this knowledge"* … *"write all this networking concepts to infra/docs too"*
    → Produced `infra/docs/01-lab-setup.md` (runbook, decisions table, troubleshooting) and
    `infra/docs/02-networking-concepts.md` (CIDR, NAT, interface naming, routing, ARP).

11. *"in evidence/phase0/ maintain 2 docs (one complete network and vm configuration and stuff)
    (second one verification), make these two changes."*
    → Produced `evidence/phase0/01-network-and-vm-configuration.md` and
    `evidence/phase0/02-connectivity-verification.md`

---

# Phase 1 — Baseline Chat Application

12. *"Done with coding, read and understand the code, point out if any bugs exist and write documentations in docs/protol.md, phase1/README.md and add comments in all the code files to help readers understand the implementations, I have kept server.pcap, server.log, c1.pcap, c2.pcap in evidence/phase1 along with screenshots of wiresharks, write report until this phase0 and phase1 as described in assignement linking all of these in report/main.tex final report at report.pdf"*

---

# Phase 2 — Client–Server Confidentiality

13. *"Done with coding, read and understand the code, point out if any bugs exist and write documentations in docs/protol.md, phase2/README.md and add comments in all the code files to help readers understand the implementations, I have collected `evidence/phase2/`: the self-test, matching-fingerprint logs, a ciphertext capture with Wireshark screenshots, Mallory's captured plaintext with mismatched fingerprints, and the tamper-rejection logs, write report until this phase2 as described in assignement linking all of these in report/main.tex final report at report.pdf"*
---

# Phase 3 — Server Authentication via PKI

14. *"Done with coding, read and understand the code, point out if any bugs exist and write documentations in docs/protocol.md, phase3/README.md and add comments in all the code files to help readers understand the implementations, I have collected `evidence/phase3/`: the PKI scripts and certificate summary, the legit authenticated-flow transcript with a Wireshark screenshot of the certificate in the handshake, the certificate-validation output over every cert variant, and the two MITM-now-fails transcripts (self-signed cert rejected by the chain check, stolen cert rejected by proof of possession), write report until this phase3 as described in assignement linking all of these in report/main.tex final report at report.pdf"*

---

# Phase 4 — End-to-End Encryption Between Clients

15. *"Done with coding, read and understand the code, point out if any bugs exist and write documentations in docs/protocol.md, phase4/README.md and add comments in all the code files to help readers understand the implementations, I have collected `evidence/phase4/`: the self-test, the interleaved end-to-end transcript with the matching client-to-client fingerprints, the server relay log showing readable text before /e2e and opaque __E2E_MSG__ after it, and a Wireshark screenshot confirming the wire carries only ciphertext, write report until this phase4 as described in assignement linking all of these in report/main.tex final report at report.pdf"*

---

# Phase 5 — Forward Secrecy via Key Rotation

16. *"Done with coding, read and understand the code, point out if any bugs exist and write documentations in docs/protocol.md, phase5/README.md and add comments in all the code files to help readers understand the implementations, I have collected `evidence/phase5/`: the self-test, the fingerprint timeline showing two rotations with changing-and-matching fingerprints, and the interleaved rekey transcript showing messages delivered before, across and after each rotation, write report until this phase5 as described in assignement linking all of these in report/main.tex final report at report.pdf"*
