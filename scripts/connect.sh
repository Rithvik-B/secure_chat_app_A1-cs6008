#!/usr/bin/env bash
# scripts/connect.sh — open a shell (or run a command) on a lab VM.
#
#   ./scripts/connect.sh s                 interactive shell on the server VM
#   ./scripts/connect.sh c1 'ip -br addr'  run one command on client1
set -euo pipefail

case "${1:-}" in
    s)  port=2201; user=server  ;;
    c1) port=2202; user=client  ;;
    c2) port=2203; user=client  ;;
    m)  port=2204; user=mallory ;;
    *)  echo "usage: $0 <s|c1|c2|m> [command...]" >&2; exit 1 ;;
esac
shift

# sudo needs a terminal to prompt for its password
tty_flag=()
[[ "${*:-}" == *sudo* ]] && tty_flag=(-t)

exec ssh "${tty_flag[@]}" \
     -o StrictHostKeyChecking=accept-new \
     -o IdentityFile="$HOME/.ssh/id_securechat" \
     -o IdentitiesOnly=yes \
     -p "$port" "$user@127.0.0.1" "$@"