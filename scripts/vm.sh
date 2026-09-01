#!/bin/bash
# scripts/vm.sh — start/stop the CS6008 lab VMs by role.
#
#   ./scripts/vm.sh status          show all four
#   ./scripts/vm.sh up              start all (headless)
#   ./scripts/vm.sh up s c1         start only those
#   ./scripts/vm.sh down            graceful shutdown (ACPI power button)
#   ./scripts/vm.sh kill m          hard power off, use only if stuck

set -euo pipefail

vm_for() {
    case "$1" in
        s)  echo vm1-server  ;;
        c1) echo vm2-client1 ;;
        c2) echo vm3-client2 ;;
        m)  echo vm4-mallory ;;
        *)  echo "unknown role: $1 (use s, c1, c2, m)" >&2; exit 1 ;;
    esac
}

ALL=(s c1 c2 m)

running() { VBoxManage list runningvms | grep -q "\"$1\""; }

cmd="${1:-status}"
shift || true
roles=("$@")
[[ ${#roles[@]} -gt 0 ]] || roles=("${ALL[@]}")

case "$cmd" in
    up)
        for r in "${roles[@]}"; do
            vm=$(vm_for "$r")
            if running "$vm"; then
                echo "$r ($vm) already running"
            else
                VBoxManage startvm "$vm" --type headless
            fi
        done
        ;;
    down)
        for r in "${roles[@]}"; do
            vm=$(vm_for "$r")
            if running "$vm"; then
                VBoxManage controlvm "$vm" acpipowerbutton
                echo "$r ($vm) shutting down"
            else
                echo "$r ($vm) not running"
            fi
        done
        ;;
    kill)
        for r in "${roles[@]}"; do
            vm=$(vm_for "$r")
            VBoxManage controlvm "$vm" poweroff || true
            echo "$r ($vm) powered off"
        done
        ;;
    status)
        for r in "${ALL[@]}"; do
            vm=$(vm_for "$r")
            if running "$vm"; then 
                echo "$r   $vm   RUNNING"
            else 
                echo "$r   $vm   off"
            fi
        done
        ;;
    *)
        echo "usage: $0 {up|down|kill|status} [s c1 c2 m]" >&2
        exit 1
        ;;
esac