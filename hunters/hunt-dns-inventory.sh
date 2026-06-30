#!/usr/bin/env bash
# hunt-dns-inventory.sh — Canonical DNS inventory via dnsx, with takeover candidate hints
#
# Purpose:
#   Build a machine-readable DNS baseline before takeover scanners run.
#   This hunter does not confirm takeover; it only emits DNS evidence and
#   "needs manual validation" candidate hints for CNAME/NS/MX review.
#
# Usage:
#   ./hunt-dns-inventory.sh example.com
#   ./hunt-dns-inventory.sh -f subdomains.txt
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <domain> | -f <subdomains.txt>"; exit 1; }

OUT_DIR="${OUT_DIR:-./dns_inventory_out}"
mkdir -p "$OUT_DIR"

log(){ echo "[$(date +%H:%M:%S)] $*"; }
warn(){ echo "🟡 $*"; }
ok(){ echo "🟢 $*"; }

slugify() {
  echo "$1" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | tr '[:upper:]' '[:lower:]' | sed 's/^www\.//' | tr '.:/ ' '____'
}

TMP_INPUT="$(mktemp)"
cleanup(){ rm -f "$TMP_INPUT"; }
trap cleanup EXIT

if [ "$INPUT" = "-f" ]; then
  FILE="${2:-}"
  [ -z "$FILE" ] || [ ! -f "$FILE" ] && { echo "usage: $0 -f <subdomains.txt>"; exit 1; }
  SLUG="$(basename "$FILE" | sed 's/[^A-Za-z0-9_.-]/_/g' | sed 's/\.[^.]*$//')"
  grep -Ehv '^\s*(#|$)' "$FILE" | sed -E 's|^https?://||; s|/.*$||; s|:.*$||' \
    | tr '[:upper:]' '[:lower:]' | sort -u > "$TMP_INPUT"
else
  DOMAIN="$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//' | tr '[:upper:]' '[:lower:]')"
  SLUG="$(slugify "$DOMAIN")"
  printf '%s\n' "$DOMAIN" > "$TMP_INPUT"
fi

COUNT="$(wc -l < "$TMP_INPUT" | tr -d ' ')"
OUT_TXT="$OUT_DIR/${SLUG}_dns_inventory.txt"
OUT_JSONL="$OUT_DIR/${SLUG}_dnsx.jsonl"
CANDIDATES="$OUT_DIR/${SLUG}_takeover_candidates.tsv"
RESOLVERS="${DNSX_RESOLVERS:-1.1.1.1,8.8.8.8,9.9.9.9}"
: > "$OUT_TXT"
: > "$OUT_JSONL"
: > "$CANDIDATES"

{
  log "=== DNS inventory ==="
  log "Input count: $COUNT"
  log "Text output: $OUT_TXT"
  log "JSONL output: $OUT_JSONL"
  log "Candidates: $CANDIDATES"
} | tee -a "$OUT_TXT"

if command -v dnsx >/dev/null 2>&1; then
  log "Running dnsx inventory..." | tee -a "$OUT_TXT"
  dnsx -l "$TMP_INPUT" -silent -j -resolver "$RESOLVERS" \
    -a -aaaa -cname -ns -mx -txt -soa -resp 2>>"$OUT_TXT" \
    | tee "$OUT_JSONL" >/dev/null || true
  if [ -s "$OUT_JSONL" ]; then
    ok "dnsx JSONL written: $OUT_JSONL ($(wc -l < "$OUT_JSONL" | tr -d ' ') rows)" | tee -a "$OUT_TXT"
  else
    warn "dnsx returned no JSONL rows" | tee -a "$OUT_TXT"
  fi
else
  warn "dnsx not found; using dig fallback (text only)" | tee -a "$OUT_TXT"
  while read -r host; do
    [ -z "$host" ] && continue
    {
      echo "## $host"
      for rt in A AAAA CNAME NS MX TXT SOA; do
        ans="$(dig +short "$rt" "$host" @1.1.1.1 2>/dev/null | sed 's/\.$//' || true)"
        [ -n "$ans" ] && printf '%s\n%s\n' "$rt:" "$ans"
      done
      echo
    } >> "$OUT_TXT"
  done < "$TMP_INPUT"
fi

# Takeover candidate hints. These are deliberately yellow: a provider fingerprint
# or dangling DNS condition still needs claimability validation before reporting.
provider_hint() {
  case "$1" in
    *s3*.amazonaws.com*|*github.io*|*herokuapp.com*|*herokudns.com*|*myshopify.com*|*trafficmanager.net*|*azurewebsites.net*|*cloudapp.net*|*cloudapp.azure.com*|*fastly.net*|*pantheonsite.io*|*surge.sh*|*wordpress.com*|*tumblr.com*|*zendesk.com*|*unbouncepages.com*|*ghost.io*|*thinkific.com*|*readme.io*|*uservoice.com*)
      return 0 ;;
    *)
      return 1 ;;
  esac
}

while read -r host; do
  [ -z "$host" ] && continue

  cname="$(dig +short CNAME "$host" @1.1.1.1 2>/dev/null | head -1 | sed 's/\.$//' || true)"
  if [ -n "$cname" ]; then
    arec="$(dig +short A "$host" @1.1.1.1 2>/dev/null | head -1 || true)"
    if provider_hint "$cname"; then
      printf '%s\tCNAME\t%s\tknown-provider\tneeds_manual_validation\n' "$host" "$cname" >> "$CANDIDATES"
    elif [ -z "$arec" ]; then
      printf '%s\tCNAME\t%s\tdangling-or-unresolved\tneeds_manual_validation\n' "$host" "$cname" >> "$CANDIDATES"
    fi
  fi

  ns_records="$(dig +short NS "$host" @1.1.1.1 2>/dev/null | sed 's/\.$//' || true)"
  if [ -n "$ns_records" ]; then
    echo "$ns_records" | while read -r ns; do
      [ -z "$ns" ] && continue
      ns_a="$(dig +short A "$ns" @1.1.1.1 2>/dev/null | head -1 || true)"
      [ -z "$ns_a" ] && printf '%s\tNS\t%s\tunresolved-nameserver\tneeds_manual_validation\n' "$host" "$ns" >> "$CANDIDATES"
    done
  fi
done < "$TMP_INPUT"

if [ -s "$CANDIDATES" ]; then
  warn "DNS takeover candidates require manual validation: $(wc -l < "$CANDIDATES" | tr -d ' ') → $CANDIDATES" | tee -a "$OUT_TXT"
  sed 's/^/  /' "$CANDIDATES" | tee -a "$OUT_TXT" >/dev/null
else
  ok "No DNS takeover candidate hints from inventory layer" | tee -a "$OUT_TXT"
fi

log "=== Done ===" | tee -a "$OUT_TXT"
