#!/usr/bin/env bash
# hunt-graphql-deep.sh — GraphQL 深度安全分析
#
# Pipeline:
#   1. Probe common GraphQL endpoints
#   2. Try introspection query to dump schema
#   3. Fingerprint engine via graphw00f (if introspection disabled)
#   4. Schema recovery via clairvoyance (if available + introspection disabled)
#   5. Common vuln checks: batch query, field suggestions, depth limit, alias DoS
#
# 用法：
#   ./hunt-graphql-deep.sh https://target.com
#   OUT_DIR=/tmp/out ./hunt-graphql-deep.sh https://target.com
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <URL|domain>"; echo "  OUT_DIR=./gql_out $0 https://target.com"; exit 1; }
# Normalise: add https:// if no scheme given
[[ "$TARGET" =~ ^https?:// ]] || TARGET="https://$TARGET"
TARGET="${TARGET%/}"

OUT_DIR="${OUT_DIR:-./graphql_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$TARGET" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit()  { echo "🔴 $*" | tee -a "$OUT"; }
warn() { echo "🟡 $*" | tee -a "$OUT"; }

CURL_OPTS=(-sk --max-time 12 -H "Content-Type: application/json")

# ── Introspection payload ────────────────────────────────────────
INTROSPECT_PAYLOAD='{"query":"{ __schema { queryType { name } types { name kind fields { name type { name kind ofType { name kind } } } } } }"}'

# ── Step 1: Probe common GraphQL endpoints ───────────────────────
log "=== GraphQL deep hunt: $TARGET ==="
ENDPOINTS=(/graphql /graphiql /altair /playground /gql /query
           /api/graphql /v1/graphql /v2/graphql /graphql/console)

FOUND_ENDPOINTS=()
for EP in "${ENDPOINTS[@]}"; do
  URL="${TARGET}${EP}"
  CODE=$(curl "${CURL_OPTS[@]}" -o /dev/null -w "%{http_code}" \
         -X POST -d '{"query":"{ __typename }"}' "$URL" 2>/dev/null)
  if [[ "$CODE" =~ ^(200|400|401|403|405|500)$ ]]; then
    BODY=$(curl "${CURL_OPTS[@]}" -X POST -d '{"query":"{ __typename }"}' "$URL" 2>/dev/null)
    # Consider it a GraphQL endpoint if response contains 'data' or 'errors' JSON keys
    if echo "$BODY" | grep -qE '"data"|"errors"'; then
      log "Found endpoint: $URL [$CODE]"
      FOUND_ENDPOINTS+=("$URL")
    fi
  fi
done

if [ ${#FOUND_ENDPOINTS[@]} -eq 0 ]; then
  log "No GraphQL endpoints found — exit"
  exit 0
fi

# ── Step 2–5: Per-endpoint analysis ─────────────────────────────
for EP_URL in "${FOUND_ENDPOINTS[@]}"; do
  log "--- Analysing: $EP_URL ---"
  EP_SLUG=$(echo "$EP_URL" | sed 's|https\?://||;s|[/:]|_|g')
  SCHEMA_FILE="$OUT_DIR/${EP_SLUG}_schema.json"
  INTROSPECTION_OK=0

  # ── Step 2: Introspection ──────────────────────────────────────
  INTRO_RESP=$(curl "${CURL_OPTS[@]}" -X POST -d "$INTROSPECT_PAYLOAD" "$EP_URL" 2>/dev/null)
  if echo "$INTRO_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
types = d.get('data', {}).get('__schema', {}).get('types', [])
sys.exit(0 if len(types) > 2 else 1)
" 2>/dev/null; then
    echo "$INTRO_RESP" > "$SCHEMA_FILE"
    hit "Introspection ENABLED → full schema dumped: $SCHEMA_FILE"
    TYPE_COUNT=$(echo "$INTRO_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(len(d.get('data',{}).get('__schema',{}).get('types',[])))
" 2>/dev/null || echo "?")
    hit "  Schema: $TYPE_COUNT types"
    INTROSPECTION_OK=1
  else
    log "Introspection disabled or blocked"

    # ── Step 3: graphw00f fingerprint ────────────────────────────
    GW="$HOME/Tools/graphw00f/main.py"
    if [ -f "$GW" ]; then
      log "Running graphw00f on $EP_URL"
      GW_OUT=$(python3 "$GW" -d -t "$EP_URL" 2>/dev/null || true)
      if [ -n "$GW_OUT" ]; then
        warn "Engine fingerprint via graphw00f:"
        echo "$GW_OUT" | grep -v '^$' | while read -r L; do warn "  $L"; done
        echo "$GW_OUT" >> "$OUT"
      fi
    else
      log "graphw00f not found at $GW — skipping fingerprint"
    fi

    # ── Step 4: clairvoyance schema recovery ─────────────────────
    if command -v clairvoyance &>/dev/null; then
      log "Running clairvoyance schema recovery on $EP_URL"
      CLAIR_FILE="$OUT_DIR/${EP_SLUG}_clairvoyance.json"
      clairvoyance -o "$CLAIR_FILE" "$EP_URL" 2>/dev/null && \
        hit "Clairvoyance schema recovery succeeded: $CLAIR_FILE" || \
        log "Clairvoyance did not recover schema"
    else
      log "clairvoyance not in PATH — skipping schema recovery"
    fi
  fi

  # ── Step 5: Common vuln checks ───────────────────────────────
  # 5a: Batch query — DoS / rate-limit bypass
  BATCH_RESP=$(curl "${CURL_OPTS[@]}" -X POST \
    -d '[{"query":"{ __typename }"},{"query":"{ __typename }"}]' \
    "$EP_URL" 2>/dev/null)
  if echo "$BATCH_RESP" | python3 -c "
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if isinstance(d, list) and len(d) > 1 else 1)
" 2>/dev/null; then
    hit "Batch queries ACCEPTED → DoS/rate-limit bypass possible"
  else
    log "Batch queries rejected or not array response"
  fi

  # 5b: Field suggestion leak — "Did you mean" in error
  TYPO_RESP=$(curl "${CURL_OPTS[@]}" -X POST \
    -d '{"query":"{ usr { ide } }"}' "$EP_URL" 2>/dev/null)
  if echo "$TYPO_RESP" | grep -qi "did you mean"; then
    warn "Field suggestion leak — server exposes field names via 'Did you mean' hints"
  fi

  # 5c: Depth limit — deeply nested query (8 levels)
  DEEP_Q='{"query":"{ a { a { a { a { a { a { a { a { __typename } } } } } } } } }"}'
  DEEP_RESP=$(curl "${CURL_OPTS[@]}" -X POST -d "$DEEP_Q" "$EP_URL" 2>/dev/null)
  # If we get data back (not an error about depth), depth limit is absent
  if echo "$DEEP_RESP" | grep -q '"data"' && ! echo "$DEEP_RESP" | grep -qi "depth\|complexity\|limit"; then
    warn "No query depth limit detected (deeply nested query not rejected)"
  fi

  # 5d: Alias-based DoS — 100 aliases in one query
  ALIAS_Q='{"query":"{ '$(python3 -c "print(' '.join(f'q{i}: __typename' for i in range(100)))")' }"}'
  ALIAS_RESP=$(curl "${CURL_OPTS[@]}" -X POST -d "$ALIAS_Q" "$EP_URL" 2>/dev/null)
  if echo "$ALIAS_RESP" | grep -q '"data"' && ! echo "$ALIAS_RESP" | grep -qi "alias\|complexity\|limit"; then
    hit "Alias-based DoS — 100 aliases accepted in single query (no complexity/alias limit)"
  fi

  log "--- Done: $EP_URL ---"
done

log "=== GraphQL hunt complete → $OUT ==="
