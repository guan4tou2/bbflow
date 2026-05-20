#!/bin/bash
# bbvps.sh — Local wrapper: run bbflow subcommands on the Oracle VPS via SSH
# Version: 1.0 (2026-04-22)
#
# Usage: tools/vps/bbvps.sh <subcommand> <target> [options]
# Same subcommands as bbflow-vps.sh on the VPS.
#
# Env:
#   VPS_HOST    default: ubuntu@138.2.59.206
#   VPS_KEY     default: ~/.ssh/orcale
#   H1USER      your HackerOne username (for X-Bug-Bounty header)

set -euo pipefail

VPS_HOST="${VPS_HOST:-ubuntu@138.2.59.206}"
VPS_KEY="${VPS_KEY:-$HOME/.ssh/orcale}"
H1USER="${H1USER:-}"

if [ "${1:-}" = "--local-help" ]; then
  cat <<EOF
bbvps.sh — Local SSH wrapper for Oracle Cloud Bug Bounty VPS

Runs bbflow commands on the VPS remotely.

Environment variables:
  VPS_HOST=$VPS_HOST
  VPS_KEY=$VPS_KEY
  H1USER=${H1USER:-(unset)}

All other arguments are forwarded to 'bbflow' on the VPS.

Try:
  tools/vps/bbvps.sh help                       # show remote bbflow help
  tools/vps/bbvps.sh tools                      # list VPS-side tools
  tools/vps/bbvps.sh lite clearme.com           # quick recon
  tools/vps/bbvps.sh status clearme.com         # check workspace
  H1USER=younglee_tw tools/vps/bbvps.sh xss https://target.com/?q=test

Special local subcommands:
  fetch <target>    rsync remote workspaces-osmedeus/<target>/ to workshop/<target>/scan_results/osmedeus/
  ssh               open interactive SSH session to VPS
EOF
  exit 0
fi

sub="${1:-help}"
TARGET="${2:-}"

case "$sub" in
  fetch)
    if [ -z "$TARGET" ]; then echo "Usage: bbvps.sh fetch <target>"; exit 1; fi
    dest="${BBFLOW_WORKSPACE:-$PWD}/workshop/$TARGET/scan_results/osmedeus/"
    mkdir -p "$dest"
    echo "[bbvps] rsync VPS:$TARGET → $dest"
    exec rsync -avz -e "ssh -i $VPS_KEY" "$VPS_HOST:~/workspaces-osmedeus/$TARGET/" "$dest"
    ;;

  ssh)
    exec ssh -i "$VPS_KEY" "$VPS_HOST"
    ;;

  *)
    # Forward all args to bbflow on VPS, passing H1USER as env
    ssh -i "$VPS_KEY" "$VPS_HOST" -t "bash -l -c 'H1USER=\"$H1USER\" bbflow $*'"
    ;;
esac
