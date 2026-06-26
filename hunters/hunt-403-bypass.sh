#!/usr/bin/env bash
# hunt-403-bypass.sh — Find 403/401 URLs and attempt bypass via nomore403
#
# Usage:
#   ./hunt-403-bypass.sh <URL-or-domain>
#   OUT_DIR=/tmp/out ./hunt-403-bypass.sh https://target.com
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <https://target-url-or-domain>"
  echo "  Optional env: OUT_DIR, BBFLOW_PROFILE"
  exit 1
fi

# Normalize target — ensure scheme
[[ "$TARGET" =~ ^https?:// ]] || TARGET="https://$TARGET"
TARGET="${TARGET%/}"

OUT_DIR="${OUT_DIR:-./403bypass_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$TARGET" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}-403bypass.txt"
: > "$OUT"

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit()  { echo "🔴 $*" | tee -a "$OUT"; }
warn() { echo "🟡 $*" | tee -a "$OUT"; }
info() { echo "    $*" | tee -a "$OUT"; }

MAX_URLS=30
UA="${CURL_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36}"
CURL_TIMEOUT="${CURL_TIMEOUT:-10}"

log "=== 403/401 bypass hunt: $TARGET ==="

# ─── Step 1: gather candidate 403/401 URLs from prior recon ────────────────
declare -a CANDIDATES=()

# Look for live_hosts.txt or urls files produced by earlier hunters
for candidate_file in \
  "$OUT_DIR/../live_hosts.txt" \
  "$OUT_DIR/../urls.txt" \
  "$OUT_DIR/../../live_hosts.txt" \
  "$OUT_DIR/../../urls.txt"
do
  if [ -f "$candidate_file" ]; then
    log "Probing URLs from $candidate_file for 403/401..."
    while IFS= read -r url; do
      [ -z "$url" ] && continue
      [[ "$url" =~ ^https?:// ]] || continue
      status=$(curl -sk -o /dev/null -w "%{http_code}" \
        -A "$UA" -m "$CURL_TIMEOUT" --max-redirs 0 "$url" 2>/dev/null || true)
      if [[ "$status" == "403" || "$status" == "401" ]]; then
        CANDIDATES+=("$url")
        info "[$status] $url"
        [ "${#CANDIDATES[@]}" -ge "$MAX_URLS" ] && break 2
      fi
    done < "$candidate_file"
  fi
done

# ─── Step 2: probe common admin/sensitive paths ────────────────────────────
SENSITIVE_PATHS=(
  /admin /dashboard /console /manager /actuator
  /debug /internal /api/admin /swagger /.env /config
)

log "Probing ${#SENSITIVE_PATHS[@]} common sensitive paths on $TARGET..."
for path in "${SENSITIVE_PATHS[@]}"; do
  [ "${#CANDIDATES[@]}" -ge "$MAX_URLS" ] && break
  url="${TARGET}${path}"
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    -A "$UA" -m "$CURL_TIMEOUT" --max-redirs 0 "$url" 2>/dev/null || true)
  if [[ "$status" == "403" || "$status" == "401" ]]; then
    CANDIDATES+=("$url")
    info "[$status] $url"
  fi
done

log "Total 403/401 candidates: ${#CANDIDATES[@]} (cap: $MAX_URLS)"

if [ "${#CANDIDATES[@]}" -eq 0 ]; then
  log "No 403/401 URLs found — nothing to bypass."
  exit 0
fi

# ─── Step 3 + 4 + 5: run nomore403 and parse results ─────────────────────
if ! command -v nomore403 &>/dev/null; then
  log "⚠️  nomore403 not found in PATH — skipping bypass attempts."
  log "    Install: go install github.com/iamj0ker/bypass-403@latest"
  log "    (binary name: bypass-403, may need renaming to nomore403)"
  log "    Candidates were written to $OUT — run nomore403 manually."
  exit 0
fi

BYPASS_COUNT=0
REDIRECT_COUNT=0

log "Running nomore403 against ${#CANDIDATES[@]} URL(s)..."
for url in "${CANDIDATES[@]}"; do
  log "--- Attempting: $url"

  # nomore403 writes colored output; capture it and strip ANSI
  nm_out=$(nomore403 -u "$url" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' || true)

  # Parse lines that show a status code (nomore403 format: "200 ... <technique>")
  while IFS= read -r line; do
    code=$(echo "$line" | grep -oE '^[0-9]{3}' || true)
    case "$code" in
      200)
        hit "BYPASS 200 — $url — $line"
        BYPASS_COUNT=$((BYPASS_COUNT + 1))
        ;;
      301|302)
        warn "REDIRECT $code — $url — $line"
        REDIRECT_COUNT=$((REDIRECT_COUNT + 1))
        ;;
      403|404|"")
        : # skip — still blocked or not found
        ;;
      *)
        [ -n "$code" ] && info "[$code] $url — $line"
        ;;
    esac
  done <<< "$nm_out"
done

# ─── Summary ──────────────────────────────────────────────────────────────
log "=== Summary ==="
log "Candidates tested : ${#CANDIDATES[@]}"
log "🔴 Confirmed bypasses (200) : $BYPASS_COUNT"
log "🟡 Redirects (301/302)      : $REDIRECT_COUNT"
log "Output: $OUT"
