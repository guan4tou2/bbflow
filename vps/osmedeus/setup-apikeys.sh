#!/bin/bash
# setup-apikeys.sh — Configure Osmedeus subfinder/urlfinder/amass API keys
# Version: 1.0 (2026-04-22)
#
# Usage:
#   # Set env vars with your keys, then run:
#   GITHUB_TOKEN=ghp_... CHAOS_API_KEY=... VIRUSTOTAL_API=... ./setup-apikeys.sh
#
# All keys are OPTIONAL. Each missing key just means that data source won't be used.
# Recommended (free) keys:
#   GITHUB_TOKEN — free, boosts github-subdomains by 10x
#   CHAOS_API_KEY — free via https://chaos.projectdiscovery.io/ (PD API)
#   VIRUSTOTAL_API — free tier 500 req/day
#   SECURITYTRAILS_API — free 50 req/month
#   BEVIGIL_API — free 100 req/month
#   SHODAN_API — paid but many researchers already have it

set -euo pipefail

CFG=~/osmedeus-base/external-configs/subfinder-provider-config.yaml

if [ ! -f "$CFG" ]; then
  echo "ERROR: $CFG missing — Osmedeus not installed?"
  exit 1
fi

# Helper: set/replace a key list
set_key() {
  local name=$1
  local value=$2
  if [ -z "$value" ]; then return; fi
  if grep -q "^${name}: " "$CFG"; then
    sed -i "s|^${name}: .*|${name}: [\"${value}\"]|" "$CFG"
    echo "  ✓ ${name}"
  else
    echo "  ⚠ ${name} not in config"
  fi
}

echo "Updating $CFG ..."
set_key github          "${GITHUB_TOKEN:-}"
set_key chaos           "${CHAOS_API_KEY:-}"
set_key virustotal      "${VIRUSTOTAL_API:-}"
set_key securitytrails  "${SECURITYTRAILS_API:-}"
set_key bevigil         "${BEVIGIL_API:-}"
set_key shodan          "${SHODAN_API:-}"
set_key censys          "${CENSYS_API:-}"
set_key fofa            "${FOFA_API:-}"
set_key binaryedge      "${BINARYEDGE_API:-}"
set_key passivetotal    "${PASSIVETOTAL_API:-}"
set_key whoisxmlapi     "${WHOISXML_API:-}"
set_key intelx          "${INTELX_API:-}"
set_key leakix          "${LEAKIX_API:-}"
set_key netlas          "${NETLAS_API:-}"
set_key fullhunt        "${FULLHUNT_API:-}"

echo ""
echo "Current populated sources:"
grep -v ': \[\]$' "$CFG" | grep -E ': \[' | head -20

echo ""
echo "Osmedeus will automatically pick these up on the next run."
echo ""
echo "Quick test — re-run recon on a small domain with new keys:"
echo "  osmedeus run -f bbflow-safe -t example.com"
