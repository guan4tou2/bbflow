#!/usr/bin/env bash
# hunt-js-analysis.sh — JS file endpoint/secret/path extractor
#
# Pipeline:
#   [1] katana  — crawl + extract .js file URLs
#   [2] jsluice urls   — extract endpoints from each JS file
#   [3] jsluice secrets — find hardcoded secrets
#   [4] xnLinkFinder   — deeper link extraction (optional)
#   [5] merge + dedup + high-risk flagging
#   [6] summary with 🔴/🟡/🟢 categorisation
#
# Usage:
#   OUT_DIR=/path hunt-js-analysis.sh https://target.com
#   OUT_DIR=/path hunt-js-analysis.sh target.com

set -uo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "usage: OUT_DIR=<dir> $0 <URL or domain>"
  echo "       Crawls JS files and extracts endpoints, secrets, and high-risk paths."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

OUT_DIR="${OUT_DIR:-/tmp/bb-js-analysis-$$}"
mkdir -p "$OUT_DIR"

# Normalise target to URL
[[ "$TARGET" =~ ^https?:// ]] || TARGET="https://$TARGET"
DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)

JS_LIST="$OUT_DIR/js_files.txt"
ALL_ENDPOINTS="$OUT_DIR/all_endpoints.txt"
ALL_SECRETS="$OUT_DIR/all_secrets.txt"
SUMMARY="$OUT_DIR/summary.txt"
: > "$JS_LIST"; : > "$ALL_ENDPOINTS"; : > "$ALL_SECRETS"; : > "$SUMMARY"

MAX_JS_FILES=50
MAX_JS_BYTES=$((2 * 1024 * 1024))   # 2 MB
UA="${CURL_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36}"

HIGH_RISK_RE='api|admin|internal|config|graphql|debug|token|secret|key|auth|credential|password|passwd'

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUMMARY"; }
hit()  { echo "$*" | tee -a "$SUMMARY"; }
warn() { echo "[WARN] $*" | tee -a "$SUMMARY"; }

KATANA="$(command -v katana 2>/dev/null || true)"
JSLUICE="$(command -v jsluice 2>/dev/null || true)"
XNLINKFINDER="$(command -v xnLinkFinder 2>/dev/null || true)"

log "=== JS analysis: $TARGET (domain=$DOMAIN) ==="

# ═══════════════════════════════════════════════════════════════
# [1] Crawl — extract .js URLs with katana
# ═══════════════════════════════════════════════════════════════
log "[1/5] Crawling for JS files..."
if [ -n "$KATANA" ]; then
  "$KATANA" -u "$TARGET" \
    -d "${KATANA_DEPTH:-3}" \
    -jc \
    -ct "${KATANA_CRAWL_DURATION:-5m}" \
    -c "${KATANA_CONCURRENCY:-10}" \
    -rl "${KATANA_RATE_LIMIT:-150}" \
    -ef css,png,jpg,gif,svg,ico,woff,ttf,eot,pdf,mp4 \
    -silent 2>/dev/null \
    | grep -E '\.js(\?|$)' \
    | grep -v '\.json' \
    | sort -u \
    | head -n "$MAX_JS_FILES" > "$JS_LIST"
  log "  katana: $(wc -l < "$JS_LIST") JS files found"
else
  warn "katana not found; trying curl+grep fallback"
  curl -sk -A "$UA" --max-time 15 "$TARGET" 2>/dev/null \
    | grep -oE 'https?://[^"'"'"'<> ]+\.js(\?[^"'"'"'<> ]*)?' \
    | sort -u | head -n "$MAX_JS_FILES" > "$JS_LIST"
  log "  fallback: $(wc -l < "$JS_LIST") JS files found"
fi

JS_COUNT=$(wc -l < "$JS_LIST")
if [ "$JS_COUNT" -eq 0 ]; then
  warn "No JS files found. Exiting early."
  hit "🔴 No JS files discovered — check TARGET or crawl depth"
  exit 0
fi

# ═══════════════════════════════════════════════════════════════
# [2] jsluice urls — endpoint extraction
# ═══════════════════════════════════════════════════════════════
log "[2/5] Extracting endpoints with jsluice (urls)..."
if [ -n "$JSLUICE" ]; then
  JS_CACHE="$OUT_DIR/js_cache"
  mkdir -p "$JS_CACHE"
  processed=0
  while IFS= read -r js_url; do
    [ -z "$js_url" ] && continue
    safe_name=$(echo "$js_url" | md5sum | cut -c1-12)
    local_file="$JS_CACHE/${safe_name}.js"
    # Download with size limit
    curl -sk -A "$UA" --max-time 15 \
      --max-filesize "$MAX_JS_BYTES" \
      -o "$local_file" "$js_url" 2>/dev/null
    [ -s "$local_file" ] || continue
    "$JSLUICE" urls "$local_file" 2>/dev/null \
      | grep -o '"url":"[^"]*"' | sed 's/"url":"//;s/"$//' \
      >> "$ALL_ENDPOINTS"
    (( processed++ )) || true
  done < "$JS_LIST"
  log "  jsluice urls: $(wc -l < "$ALL_ENDPOINTS") raw endpoints from $processed files"
else
  warn "jsluice not found; skipping endpoint extraction"
fi

# ═══════════════════════════════════════════════════════════════
# [3] jsluice secrets — hardcoded secret detection
# ═══════════════════════════════════════════════════════════════
log "[3/5] Detecting secrets with jsluice (secrets)..."
if [ -n "$JSLUICE" ] && [ -d "${JS_CACHE:-}" ]; then
  while IFS= read -r js_url; do
    safe_name=$(echo "$js_url" | md5sum | cut -c1-12)
    local_file="$JS_CACHE/${safe_name}.js"
    [ -s "$local_file" ] || continue
    "$JSLUICE" secrets "$local_file" 2>/dev/null >> "$ALL_SECRETS"
  done < "$JS_LIST"
  SECRET_COUNT=$(wc -l < "$ALL_SECRETS")
  log "  jsluice secrets: $SECRET_COUNT potential secrets"
  if [ "$SECRET_COUNT" -gt 0 ]; then
    cp "$ALL_SECRETS" "$OUT_DIR/secrets_raw.json"
  fi
else
  warn "jsluice not found or no cache; skipping secret scan"
fi

# ═══════════════════════════════════════════════════════════════
# [4] xnLinkFinder — deeper extraction (optional)
# ═══════════════════════════════════════════════════════════════
log "[4/5] xnLinkFinder deeper extraction..."
if [ -n "$XNLINKFINDER" ]; then
  "$XNLINKFINDER" -i "$TARGET" -sf "$DOMAIN" -o "$OUT_DIR/xnlf_out.txt" -op "$OUT_DIR/xnlf_params.txt" -sp 200 -spo -silent 2>/dev/null || true
  if [ -s "$OUT_DIR/xnlf_out.txt" ]; then
    cat "$OUT_DIR/xnlf_out.txt" >> "$ALL_ENDPOINTS"
    log "  xnLinkFinder: $(wc -l < "$OUT_DIR/xnlf_out.txt") additional links"
  fi
else
  warn "xnLinkFinder not found; skipping"
fi

# ═══════════════════════════════════════════════════════════════
# [5] Merge, deduplicate, categorise
# ═══════════════════════════════════════════════════════════════
log "[5/5] Deduplicating and categorising endpoints..."
DEDUPED="$OUT_DIR/endpoints_deduped.txt"
sort -u "$ALL_ENDPOINTS" 2>/dev/null | grep -v '^$' > "$DEDUPED"
TOTAL=$(wc -l < "$DEDUPED")

HIGH_RISK="$OUT_DIR/endpoints_high_risk.txt"
NORMAL="$OUT_DIR/endpoints_normal.txt"
grep -Ei "$HIGH_RISK_RE" "$DEDUPED" > "$HIGH_RISK" 2>/dev/null || true
grep -vEi "$HIGH_RISK_RE" "$DEDUPED" > "$NORMAL" 2>/dev/null || true

HR_COUNT=$(wc -l < "$HIGH_RISK")
NR_COUNT=$(wc -l < "$NORMAL")
SECRET_COUNT=$(wc -l < "$ALL_SECRETS")

# ═══════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════
log ""
log "═══════════════════ JS ANALYSIS SUMMARY ═══════════════════"
log "Target:      $TARGET"
log "JS files:    $JS_COUNT (max $MAX_JS_FILES, 2MB limit)"
log "Endpoints:   $TOTAL total"
log ""
if [ "$SECRET_COUNT" -gt 0 ]; then
  hit "🔴 SECRETS ($SECRET_COUNT):"
  head -n 20 "$ALL_SECRETS" | while IFS= read -r line; do
    hit "   $line"
  done
fi
if [ "$HR_COUNT" -gt 0 ]; then
  hit "🟡 HIGH-RISK ENDPOINTS ($HR_COUNT):"
  head -n 30 "$HIGH_RISK" | while IFS= read -r line; do
    hit "   $line"
  done
fi
if [ "$NR_COUNT" -gt 0 ]; then
  hit "🟢 NORMAL ENDPOINTS ($NR_COUNT):"
  head -n 20 "$NORMAL" | while IFS= read -r line; do
    hit "   $line"
  done
fi
log ""
log "Output dir: $OUT_DIR"
log "  js_files.txt          — crawled JS URLs"
log "  endpoints_deduped.txt — all unique endpoints"
log "  endpoints_high_risk.txt"
log "  endpoints_normal.txt"
[ -s "$ALL_SECRETS" ] && log "  secrets_raw.json      — jsluice secret hits"
log "═══════════════════════════════════════════════════════════"
