#!/usr/bin/env bash
# hunt-api-discovery.sh — API endpoint discovery via kiterunner (kr)
#
# 對目標跑 kiterunner route-based API 探測，比傳統 dir brute 更精準
# 因為 .kite wordlist 包含 HTTP method + content-type + route 三元組。
#
# Fallback：若 kr 未安裝，退回 gobuster fuzz 模式。
#
# Severity（機械 hunter 只報訊號，severity 交 LLM 判斷）：
#   🔴 SENSITIVE — admin/config/internal/debug/actuator 等敏感端點
#   🟡 INTERESTING — api/v1/graphql/swagger 等有趣端點
#   🟢 SUMMARY — 最終統計
#
# 用法：
#   ./hunt-api-discovery.sh https://api.example.com
#   ./hunt-api-discovery.sh api.example.com
#
# 環境變數：
#   OUT_DIR           輸出目錄（預設 ./api_discovery_out）
#   BBFLOW_PROFILE    safe/deep/stealth（影響 concurrency + delay）
#   KR_WORDLIST       自訂 .kite wordlist 路徑
#   KR_EXTRA_FLAGS    傳給 kr 的額外 flag

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <url-or-domain>"; exit 1; }

# Normalize to URL
TARGET="$INPUT"
case "$TARGET" in
  http://*|https://*) ;;
  *) TARGET="https://$TARGET" ;;
esac
TARGET=$(echo "$TARGET" | sed -E 's|/$||')

HOST=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)

OUT_DIR="${OUT_DIR:-./api_discovery_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | tr '.' '_' | tr ':' '_')
OUT="$OUT_DIR/${SLUG}.txt"
RAW="$OUT_DIR/${SLUG}_raw.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }

# ── Profile-aware settings ──────────────────────────────────────────
case "${BBFLOW_PROFILE:-safe}" in
  deep)
    KR_CONCURRENCY="${KR_CONCURRENCY:-20}"
    KR_DELAY="${KR_DELAY:-0}"
    GB_THREADS="${GB_THREADS:-20}"
    GB_DELAY="${GB_DELAY:-}"
    ;;
  stealth)
    KR_CONCURRENCY="${KR_CONCURRENCY:-2}"
    KR_DELAY="${KR_DELAY:-500}"
    GB_THREADS="${GB_THREADS:-2}"
    GB_DELAY="${GB_DELAY:-1s}"
    ;;
  *)
    KR_CONCURRENCY="${KR_CONCURRENCY:-10}"
    KR_DELAY="${KR_DELAY:-100}"
    GB_THREADS="${GB_THREADS:-10}"
    GB_DELAY="${GB_DELAY:-}"
    ;;
esac

# ── Sensitive / interesting path patterns ───────────────────────────
# Used for categorizing discovered endpoints
# These are grep -iE patterns (extended regex, case insensitive)
SENSITIVE_PATTERN='admin|internal|debug|actuator|config|configprops|management|console|shell|phpinfo|phpmyadmin|wp-admin|_profiler|__debug__|telescope|horizon|jolokia|heapdump|env|secret|credential|token|passwd|htpasswd|backup|dump|trace|httptrace|loggers|mappings|beans|shutdown|restart|cgi-bin|server-status|server-info|wp-config|\.git|\.env|\.htaccess|_wpeprivate'
INTERESTING_PATTERN='api|graphql|graphiql|swagger|openapi|api-docs|redoc|rapidoc|v1|v2|v3|webhook|oauth|auth|login|register|signup|reset|forgot|verify|callback|healthcheck|health|metrics|status|info|version|users|accounts|upload|download|export|import|search|query|batch|bulk|proxy|gateway|ws|socket|sse|stream|feed|rss|sitemap|robots'

# ── Locate tools ────────────────────────────────────────────────────
KR="$(command -v kr 2>/dev/null || echo '')"
GOBUSTER="$(command -v gobuster 2>/dev/null || echo '')"

if [ -z "$KR" ] && [ -z "$GOBUSTER" ]; then
  echo "✗ neither kr nor gobuster found"
  echo "  kr: download from https://github.com/assetnote/kiterunner/releases"
  echo "  gobuster: go install github.com/OJ/gobuster/v3@latest"
  exit 0
fi

# ── Locate wordlists ───────────────────────────────────────────────
# For kr: prefer .kite wordlists
KR_WL="${KR_WORDLIST:-}"
if [ -z "$KR_WL" ] && [ -n "$KR" ]; then
  for _kw in \
    "$HOME/Tools/wordlists/routes-large.kite" \
    "$HOME/Tools/wordlists/routes-small.kite" \
    "$HOME/Tools/kiterunner-wordlists/routes-large.kite" \
    "$HOME/wordlists/routes-large.kite"; do
    [ -f "$_kw" ] && KR_WL="$_kw" && break
  done
fi

# For gobuster fallback: SecLists API wordlist
if [ -z "${SECLISTS:-}" ]; then
  for _sl in \
    "$HOME/Tools/SecLists" \
    "$(brew --prefix seclists 2>/dev/null)/share/seclists" \
    "/opt/homebrew/share/seclists" \
    "/usr/local/share/seclists" \
    "/usr/share/seclists"; do
    [ -d "$_sl/Discovery/Web-Content" ] && SECLISTS="$_sl" && break
  done
  SECLISTS="${SECLISTS:-}"
fi

# ── Build API-focused wordlist for gobuster fallback ────────────────
API_WL="$OUT_DIR/api_paths.txt"
cat > "$API_WL" <<'WORDLIST'
api
api/v1
api/v2
api/v3
api/v1/users
api/v1/admin
api/v1/config
api/v1/health
api/v1/status
api/v1/docs
api/v1/swagger.json
api/v2/swagger.json
api/v3/api-docs
api/docs
api/swagger
api/swagger.json
api/swagger-ui.html
api/openapi.json
api/graphql
api/internal
api/admin
api/debug
api/config
api/version
api/info
api/me
api/user
api/users
api/account
api/accounts
api/auth
api/login
api/register
api/token
api/oauth
api/callback
api/webhook
api/webhooks
api/upload
api/download
api/export
api/import
api/search
api/query
api/batch
api/bulk
api/proxy
api/gateway
graphql
graphql/playground
graphiql
swagger
swagger.json
swagger.yaml
swagger-ui
swagger-ui.html
swagger-resources
openapi.json
openapi.yaml
openapi/v1
openapi/v3
v1/api-docs
v2/api-docs
v3/api-docs
redoc
rapidoc
docs
admin
admin/api
internal
internal/api
debug
debug/vars
debug/pprof
_debug_
actuator
actuator/env
actuator/health
actuator/info
actuator/mappings
actuator/configprops
actuator/beans
actuator/httptrace
actuator/heapdump
actuator/loggers
actuator/threaddump
actuator/jolokia
management
console
metrics
prometheus/metrics
healthcheck
health
status
info
version
.well-known/openapi
.well-known/security.txt
server-status
server-info
_profiler
__debug__
telescope
horizon
WORDLIST

# Append SecLists API endpoints if available
WL_API="${SECLISTS:+$SECLISTS/Discovery/Web-Content/api/api-endpoints-res.txt}"
if [ -n "$WL_API" ] && [ -f "$WL_API" ]; then
  cat "$WL_API" >> "$API_WL"
fi

# Dedup
DEDUP_WL="$OUT_DIR/api_paths_dedup.txt"
sort -u "$API_WL" > "$DEDUP_WL"
WL_COUNT=$(wc -l < "$DEDUP_WL" | tr -d ' ')

log "=== API discovery hunt: $HOST profile=$BBFLOW_PROFILE ==="

# ── Primary: kiterunner (kr) ────────────────────────────────────────
SCAN_TOOL=""
if [ -n "$KR" ]; then
  if [ -n "$KR_WL" ]; then
    log "--- kr scan (kiterunner) with .kite wordlist: $KR_WL ---"
    SCAN_TOOL="kr-scan"

    KR_FLAGS=(
      "-x" "$KR_CONCURRENCY"
      "--fail-status-codes" "404,429,503"
      "-q"
    )
    [ "$KR_DELAY" -gt 0 ] 2>/dev/null && KR_FLAGS+=("--delay" "${KR_DELAY}ms")

    "$KR" scan "$TARGET" \
      -w "$KR_WL" \
      "${KR_FLAGS[@]}" \
      ${KR_EXTRA_FLAGS:-} \
      2>&1 | tee "$RAW" || true
  else
    # No .kite wordlist — use kr brute with plain text
    log "--- kr brute (no .kite wordlist found, using plain text) ---"
    log "    wordlist: $DEDUP_WL ($WL_COUNT entries)"
    SCAN_TOOL="kr-brute"

    KR_FLAGS=(
      "-x" "$KR_CONCURRENCY"
      "--fail-status-codes" "404,429,503"
      "-q"
    )
    [ "$KR_DELAY" -gt 0 ] 2>/dev/null && KR_FLAGS+=("--delay" "${KR_DELAY}ms")

    "$KR" brute "$TARGET" \
      -w "$DEDUP_WL" \
      "${KR_FLAGS[@]}" \
      ${KR_EXTRA_FLAGS:-} \
      2>&1 | tee "$RAW" || true
  fi

# ── Fallback: gobuster fuzz ─────────────────────────────────────────
elif [ -n "$GOBUSTER" ]; then
  log "--- gobuster fuzz fallback (kr not installed) ---"
  log "    wordlist: $DEDUP_WL ($WL_COUNT entries)"
  SCAN_TOOL="gobuster"

  GB_FLAGS=(
    "-t" "$GB_THREADS"
    "-q"
    "-k"
  )
  [ -n "${GB_DELAY:-}" ] && GB_FLAGS+=("-d" "$GB_DELAY")

  "$GOBUSTER" fuzz \
    -u "${TARGET}/FUZZ" \
    -w "$DEDUP_WL" \
    --exclude-length 0 \
    "${GB_FLAGS[@]}" \
    2>&1 | tee "$RAW" || true
fi

# ── Parse and categorize results ────────────────────────────────────
log "--- categorizing results ($SCAN_TOOL) ---"

SENSITIVE_COUNT=0
INTERESTING_COUNT=0
TOTAL_COUNT=0

while IFS= read -r line; do
  # Skip empty lines, banners, progress lines
  [ -z "$line" ] && continue
  echo "$line" | grep -qE '^\s*$|^#|^\[INF\]|^Progress|^Scanning' && continue

  # Extract URL/path and status code from the line
  # kr output: METHOD STATUS_CODE URL CONTENT_LENGTH
  # gobuster output: Found: [Status=200] [Length=1234] -- URL
  url=""
  status=""

  # Try kr format: e.g. "GET     200 [    1234,   89,  12] https://target/api/v1 ..."
  if echo "$line" | grep -qE '^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[0-9]'; then
    status=$(echo "$line" | sed -E 's/^[A-Z]+\s+([0-9]+)\s+.*/\1/')
    url=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
  # Try gobuster format
  elif echo "$line" | grep -qE 'Status=[0-9]+'; then
    status=$(echo "$line" | sed -E 's/.*Status=([0-9]+).*/\1/')
    url=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
    # gobuster fuzz may show the path differently
    if [ -z "$url" ]; then
      url=$(echo "$line" | sed -E 's/.*-- //' | sed -E 's/\s*$//')
    fi
  # Generic: any line with a URL
  elif echo "$line" | grep -qE 'https?://'; then
    url=$(echo "$line" | grep -oE 'https?://[^ ]+' | head -1)
    status=$(echo "$line" | grep -oE '[0-9]{3}' | head -1)
  else
    continue
  fi

  [ -z "$url" ] && continue
  TOTAL_COUNT=$((TOTAL_COUNT + 1))

  # Categorize
  path=$(echo "$url" | sed -E 's|^https?://[^/]+||')

  if echo "$path" | grep -qiE "$SENSITIVE_PATTERN"; then
    hit "[SENSITIVE] [$status] $url"
    SENSITIVE_COUNT=$((SENSITIVE_COUNT + 1))
  elif echo "$path" | grep -qiE "$INTERESTING_PATTERN"; then
    info_hit "[INTERESTING] [$status] $url"
    INTERESTING_COUNT=$((INTERESTING_COUNT + 1))
  else
    # Regular endpoint — log but no emoji
    echo "    [${status:-???}] $url" >> "$OUT"
  fi

done < "$RAW"

# ── Summary ─────────────────────────────────────────────────────────
OTHER_COUNT=$((TOTAL_COUNT - SENSITIVE_COUNT - INTERESTING_COUNT))
echo "🟢 SUMMARY ($SCAN_TOOL): $TOTAL_COUNT endpoints discovered — $SENSITIVE_COUNT sensitive, $INTERESTING_COUNT interesting, $OTHER_COUNT other" | tee -a "$OUT"

if [ "$SENSITIVE_COUNT" -gt 0 ]; then
  log "⚠ Sensitive endpoints detected — verify access (auth required? SPA catch-all?)"
  log "  Next: run hunt-actuator-deep.sh / hunt-swagger.sh / hunt-devops-unauth.sh on confirmed endpoints"
fi

log "=== done: API discovery complete → $OUT ==="
