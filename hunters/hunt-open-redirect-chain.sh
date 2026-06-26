#!/usr/bin/env bash
# hunt-open-redirect-chain.sh — Open Redirect detection with chain escalation signals
#
# Scans URL parameters for open redirect via GET-only probes. Beyond basic
# detection, checks if the redirect endpoint is part of an OAuth flow (code/token
# in response or redirect chain) which escalates severity significantly.
#
# GET-only, safe: uses a controlled domain that the operator owns or a
# non-resolvable canary. No state mutation.
#
# Usage:
#   OUT_DIR=/path hunt-open-redirect-chain.sh <url>
#   REDIRECT_CANARY=https://evil.example.com hunt-open-redirect-chain.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-redir-$$}"
mkdir -p "$OUT_DIR"

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
CANARY="${REDIRECT_CANARY:-https://evil.example.com}"
CANARY_HOST=$(echo "$CANARY" | sed -E 's|^https?://||' | cut -d/ -f1)

KATANA="$(command -v katana 2>/dev/null || echo '')"
GAU="$(command -v gau 2>/dev/null || echo '')"

OUT="$OUT_DIR/redirect_results.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟠 $*" | tee -a "$OUT"; }

REDIRECT_PARAMS=(
  redirect redirect_uri redirect_url return return_url returnTo next
  next_url url to dest destination continue goto rurl target
  redir callback forward out view login_url image_url domain
  checkout_url return_path successUrl failUrl ref site
)

# ── URL collection ──────────────────────────────────────────
ALL_URLS="$OUT_DIR/all_urls.txt"
: > "$ALL_URLS"

if [ -n "$KATANA" ]; then
  "$KATANA" -u "$TARGET" -d 3 -jc -silent -o "$OUT_DIR/katana.txt" 2>/dev/null || true
  [ -s "$OUT_DIR/katana.txt" ] && cat "$OUT_DIR/katana.txt" >> "$ALL_URLS"
fi
if [ -n "$GAU" ]; then
  echo "$DOMAIN" | "$GAU" --threads 3 --subs \
    --blacklist eot,svg,ttf,woff,png,jpg,gif,ico,css,pdf 2>/dev/null >> "$ALL_URLS" || true
fi

grep -E '\?' "$ALL_URLS" | sort -u > "$OUT_DIR/param_urls.txt" || true

# also probe common redirect endpoints
COMMON_ENDPOINTS=(
  "/redirect?url=" "/login?return_url=" "/logout?redirect=" "/oauth/authorize?redirect_uri="
  "/sso/login?returnTo=" "/auth/callback?next=" "/go?to=" "/out?url="
  "/link?url=" "/away?to=" "/cgi-bin/redirect.cgi?url="
)
for ep in "${COMMON_ENDPOINTS[@]}"; do
  echo "https://$DOMAIN${ep}${CANARY}" >> "$OUT_DIR/param_urls.txt"
done

sort -u -o "$OUT_DIR/param_urls.txt" "$OUT_DIR/param_urls.txt"
URL_COUNT=$(wc -l < "$OUT_DIR/param_urls.txt" | tr -d ' ')
log "=== Open Redirect hunt: $DOMAIN ($URL_COUNT candidate URLs) ==="

# ── build test URLs with canary injected into redirect-like params ─
TEST_URLS="$OUT_DIR/test_urls.txt"
: > "$TEST_URLS"

while IFS= read -r url; do
  for param in "${REDIRECT_PARAMS[@]}"; do
    if echo "$url" | grep -qiE "[?&]${param}="; then
      modified=$(echo "$url" | sed -E "s|([?&]${param}=)[^&]*|\1${CANARY}|i")
      echo "$modified" >> "$TEST_URLS"
    fi
  done
done < "$OUT_DIR/param_urls.txt"

# add common endpoint probes (already have canary)
grep -F "$CANARY" "$OUT_DIR/param_urls.txt" >> "$TEST_URLS" 2>/dev/null || true
sort -u -o "$TEST_URLS" "$TEST_URLS"

TEST_COUNT=$(wc -l < "$TEST_URLS" | tr -d ' ')
[ "$TEST_COUNT" -eq 0 ] && { log "no redirect-param URLs found"; exit 0; }
log "testing $TEST_COUNT redirect probes..."

# ── probe ──────────────────────────────────────────────────
while IFS= read -r test_url; do
  [ -z "$test_url" ] && continue
  resp=$(curl -sk -m 10 -D- -o /dev/null -w "%{redirect_url}\n%{http_code}" "$test_url" 2>/dev/null)
  redir_target=$(echo "$resp" | head -1)
  http_code=$(echo "$resp" | tail -1)

  case "$http_code" in
    301|302|303|307|308)
      if echo "$redir_target" | grep -qiF "$CANARY_HOST"; then
        # check OAuth chain signal
        full_resp=$(curl -sk -m 10 -D- "$test_url" 2>/dev/null | head -c 2000)
        if echo "$full_resp" | grep -qiE 'oauth|authorize|client_id|response_type=code|scope='; then
          hit "[CRITICAL] Open Redirect in OAuth flow → token theft: $test_url → $redir_target"
        else
          hit "[HIGH] Open Redirect ($http_code): $test_url → $redir_target"
        fi
      fi
      ;;
    200)
      body=$(curl -sk -m 10 "$test_url" 2>/dev/null | head -c 2000)
      if echo "$body" | grep -qiE "location\.href\s*=\s*[\"'].*${CANARY_HOST}|window\.location\s*=\s*[\"'].*${CANARY_HOST}|meta.*refresh.*url=.*${CANARY_HOST}"; then
        warn "[MEDIUM] JS/Meta redirect to canary: $test_url"
      fi
      ;;
  esac
  sleep 0.3
done < "$TEST_URLS"

log "=== done: open redirect sweep complete ==="
