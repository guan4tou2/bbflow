#!/usr/bin/env bash
# hunt-subdomain-resolve.sh — Mass DNS resolution with wildcard filtering via puredns
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

# ─── Input ───────────────────────────────────────────────────────────────────
INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <domain>"; echo "  OUT_DIR=<path> $0 <domain>"; exit 1; }
DOMAIN=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')

OUT_DIR="${OUT_DIR:-./subdomain_resolve_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}_resolve.txt"
MERGED="$OUT_DIR/${SLUG}_merged_input.txt"
RESOLVED="$OUT_DIR/${SLUG}_resolved.txt"
CLEANED="$OUT_DIR/${SLUG}_cleaned_subdomains.txt"
PREV="$OUT_DIR/${SLUG}_subdomains_prev.txt"
: > "$OUT"

log()     { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
ok()      { echo "🟢 $*" | tee -a "$OUT"; }
hit()     { echo "🔴 $*" | tee -a "$OUT"; }
section() { echo "" | tee -a "$OUT"; echo "──── $* ────" | tee -a "$OUT"; }

RESOLVERS="8.8.8.8,1.1.1.1,9.9.9.9"

log "=== Subdomain Mass Resolve: $DOMAIN ==="
log "Output: $OUT"

# ─── Tool checks ─────────────────────────────────────────────────────────────
HAS_PUREDNS=0; HAS_DNSX=0
command -v puredns &>/dev/null && HAS_PUREDNS=1
command -v dnsx    &>/dev/null && HAS_DNSX=1
[ $HAS_PUREDNS -eq 0 ] && log "[WARN] puredns not found — will fallback to dnsx"
[ $HAS_DNSX -eq 0 ]    && log "[WARN] dnsx not found"

# ─── Step 1: Collect subdomains from all available sources ───────────────────
section "1. Collecting Subdomain Sources"
: > "$MERGED"

# bbot/subdomains.txt from prior recon
for bbot_dir in "$OUT_DIR"/../bbot_out "$OUT_DIR"/../../bbot_out; do
  f="$bbot_dir/subdomains.txt"
  [ -f "$f" ] && { wc -l < "$f" | xargs -I{} log "  bbot subdomains.txt: {} entries"; cat "$f" >> "$MERGED"; }
done

# subfinder output
for sf in "$OUT_DIR"/../subfinder_out/"${SLUG}"*.txt "$OUT_DIR"/../../subfinder_out/"${SLUG}"*.txt; do
  [ -f "$sf" ] && { wc -l < "$sf" | xargs -I{} log "  subfinder: {} entries ($sf)"; cat "$sf" >> "$MERGED"; }
done

# TLS SAN output from tls-audit
for tls in "$OUT_DIR"/../tls_audit_out/"${SLUG}"*.txt "$OUT_DIR"/../../tls_audit_out/"${SLUG}"*.txt; do
  [ -f "$tls" ] && { wc -l < "$tls" | xargs -I{} log "  tls-audit SANs: {} entries ($tls)"; cat "$tls" >> "$MERGED"; }
done

# alterx permutation output
for ax in "$OUT_DIR"/../alterx_out/"${SLUG}"*.txt "$OUT_DIR"/../../alterx_out/"${SLUG}"*.txt; do
  [ -f "$ax" ] && { wc -l < "$ax" | xargs -I{} log "  alterx permutations: {} entries ($ax)"; cat "$ax" >> "$MERGED"; }
done

# Also include any existing cleaned list from prior run
[ -f "$CLEANED" ] && cat "$CLEANED" >> "$MERGED"

RAW_COUNT=$(wc -l < "$MERGED" 2>/dev/null || echo 0)
log "Total raw entries collected: $RAW_COUNT"

# ─── Step 2: Merge + deduplicate ─────────────────────────────────────────────
section "2. Deduplicating"
DEDUPED="$OUT_DIR/${SLUG}_deduped.txt"
grep -iE "\.${DOMAIN//./\\.}$|^${DOMAIN//./\\.}$" "$MERGED" 2>/dev/null \
  | tr '[:upper:]' '[:lower:]' | sort -u > "$DEDUPED" || true
DEDUP_COUNT=$(wc -l < "$DEDUPED" 2>/dev/null || echo 0)
log "Unique subdomains after dedup: $DEDUP_COUNT"
[ "$DEDUP_COUNT" -eq 0 ] && { log "[WARN] No subdomains to resolve — add recon sources first"; exit 0; }

# Save previous resolved list for diff
[ -f "$CLEANED" ] && cp "$CLEANED" "$PREV" || : > "$PREV"

# ─── Step 3+4: Resolve with wildcard filtering ───────────────────────────────
section "3-4. Resolving (wildcard-filtered)"
if [ $HAS_PUREDNS -eq 1 ]; then
  log "Using puredns with resolvers: $RESOLVERS"
  RESOLVER_FILE="$OUT_DIR/resolvers.txt"
  echo "$RESOLVERS" | tr ',' '\n' > "$RESOLVER_FILE"
  puredns resolve "$DEDUPED" \
    --resolvers "$RESOLVER_FILE" \
    --write "$RESOLVED" \
    --wildcard-tests 3 \
    --rate-limit 5000 2>>"$OUT" || true
else
  log "[FALLBACK] Using dnsx directly (no wildcard filtering)"
  dnsx -l "$DEDUPED" \
    -resolver "$RESOLVERS" \
    -silent -o "$RESOLVED" 2>>"$OUT" || true
fi

RESOLVED_COUNT=$(wc -l < "$RESOLVED" 2>/dev/null || echo 0)
log "Resolved subdomains: $RESOLVED_COUNT"

# ─── Step 5: Diff against previous ──────────────────────────────────────────
section "5. New Discoveries"
NEW_SUBS=$(comm -23 <(sort "$RESOLVED" 2>/dev/null) <(sort "$PREV" 2>/dev/null) || true)
if [ -n "$NEW_SUBS" ]; then
  NEW_COUNT=$(echo "$NEW_SUBS" | wc -l)
  log "New subdomains found: $NEW_COUNT"
  echo "$NEW_SUBS" | while read -r sub; do log "  NEW: $sub"; done
else
  log "No new subdomains since last run"
fi

# ─── Step 6: Classify IPs ────────────────────────────────────────────────────
section "6. IP Classification"
if [ $HAS_DNSX -eq 1 ] && [ -f "$RESOLVED" ]; then
  dnsx -l "$RESOLVED" -a -resp-only -silent 2>/dev/null | sort -u | while read -r ip; do
    if echo "$ip" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
      hit "Internal IP detected: $ip"
    else
      ok "Public IP: $ip"
    fi
  done | tee -a "$OUT" || true
elif [ -f "$RESOLVED" ]; then
  log "[INFO] dnsx not available — skipping IP classification"
fi

# ─── Step 7: Write cleaned_subdomains.txt ────────────────────────────────────
section "7. Output"
cp "$RESOLVED" "$CLEANED" 2>/dev/null || : > "$CLEANED"
FINAL_COUNT=$(wc -l < "$CLEANED" 2>/dev/null || echo 0)
log "Wrote $FINAL_COUNT verified subdomains → $CLEANED"
log "=== Done ==="
