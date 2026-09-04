#!/usr/bin/env bash
# scripts/deploy.sh — push a phase directory to lab VMs and build it there.
#
#   ./scripts/deploy.sh phase1              deploy to all four VMs
#   ./scripts/deploy.sh phase1 s c1 c2      deploy to those roles only
#   ./scripts/deploy.sh phase1 --no-build   copy only, skip make
#
# Source lives on the host and is version-controlled here; the VMs hold a
# disposable build directory. Binaries are compiled on the VM because the guest
# toolchain (g++ 15.2, OpenSSL 3.5.5) differs from the host's.
set -euo pipefail

port_for() {
    case "$1" in
        s)  echo 2201 ;;
        c1) echo 2202 ;;
        c2) echo 2203 ;;
        m)  echo 2204 ;;
        *)  echo "unknown role: $1 (use s, c1, c2, m)" >&2; exit 1 ;;
    esac
}

user_for() {
    case "$1" in
        s)     echo server ;;
        c1|c2) echo client ;;
        m)     echo mallory ;;
    esac
}

[[ $# -ge 1 ]] || { echo "usage: $0 <phaseN> [s c1 c2 m] [--no-build]" >&2; exit 1; }

phase="$1"; shift
[[ -d "$phase" ]] || { echo "no such directory: $phase" >&2; exit 1; }

build=1
roles=()
for arg in "$@"; do
    if [[ "$arg" == "--no-build" ]]; then build=0; else roles+=("$arg"); fi
done
[[ ${#roles[@]} -gt 0 ]] || roles=(s c1 c2 m)

for r in "${roles[@]}"; do
    port=$(port_for "$r")
    user=$(user_for "$r")
    echo "=== $r ($user@127.0.0.1:$port) -> ~/$phase/"

    # --delete keeps the VM a mirror of the source tree, while the excludes
    # protect build output, logs and captures that only exist on the VM.
    rsync -a --delete --info=stats1 \
        --exclude='*.o' --exclude='server' --exclude='client' --exclude='mitm' \
        --exclude='*.log' --exclude='*.pcap' \
        -e "ssh -p $port -o StrictHostKeyChecking=accept-new -o IdentityFile=$HOME/.ssh/id_securechat -o IdentitiesOnly=yes" \
        "$phase/" "$user@127.0.0.1:~/$phase/"

    if [[ $build -eq 1 ]]; then
        ssh -p "$port" -o StrictHostKeyChecking=accept-new \
            -o IdentityFile="$HOME/.ssh/id_securechat" -o IdentitiesOnly=yes \
            "$user@127.0.0.1" "make -C ~/$phase"
    fi
done

echo
echo "deployed $phase to: ${roles[*]}"
