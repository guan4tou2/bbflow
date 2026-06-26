#!/usr/bin/env bash
# hunt-cache-deception.sh — Web Cache Deception / Path Confusion detector
#
# Probes whether CDN/reverse-proxy caches user-specific responses when a
# static-looking extension is appended (e.g. /account/settings/x.css).
# GET-only, safe: no state mutation, no auth bypass attempt.
#
# Technique:
#   1. Identify cacheable extension set (.css, .js, .png, .svg, .ico, .woff2)
#   2. Append path suffix to authenticated pages → check if response differs
#   3. Compare cache headers (Age, X-Cache, CF-Cache-Status) for cache hit signals
#   4. Check path confusion via delimiter injection (/path;.css, /path%0a.js)
#
# Usage:
#   OUT_DIR=/path hunt-cache-deception.sh <url>
#   WCD_COOKIE="session=xxx" hunt-cache-deception.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-wcd-$$}"
mkdir -p "$OUT_DIR"

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
COOKIE="${WCD_COOKIE:-}"

KATANA="$(command -v katana 2>/dev/null || echo '')"
GAU="$(command -v gau 2>/dev/null || echo '')"

CACHE_EXTENSIONS=(".css" ".js" ".png" ".svg" ".ico" ".woff2" ".gif" ".jpg")
PATH_DELIMITERS=(";" "%0a" "%23" "%3f" "%00")

OUT="$OUT_DIR/wcd_results.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }

CURL_OPTS=(-sk -m 10 -D-)
[ -n "$COOKIE" ] && CURL_OPTS+=(-b "$COOKIE")

# ── collect dynamic URLs ──────────────────────────────────────
ALL_URLS="$OUT_DIR/dynamic_urls.txt"
: > "$ALL_URLS"

if [ -n "$KATANA" ]; then
  "$KATANA" -u "$TARGET" -d 2 -jc -silent -o "$OUT_DIR/katana.txt" 2>/dev/null || true
  [ -s "$OUT_DIR/katana.txt" ] && cat "$OUT_DIR/katana.txt" >> "$ALL_URLS"
fi
if [ -n "$GAU" ]; then
  echo "$DOMAIN" | "$GAU" --threads 3 --subs \
    --blacklist eot,svg,ttf,woff,png,jpg,gif,ico,css,pdf,js 2>/dev/null >> "$ALL_URLS" || true
fi

# filter to dynamic-looking paths (no static extension, has path depth)
grep -vE '\.(css|js|png|jpg|gif|svg|ico|woff|ttf|eot|pdf)(\?|$)' "$ALL_URLS" \
  | grep -E "^https?://$DOMAIN/" \
  | sort -u | head -30 > "$OUT_DIR/dynamic_filtered.txt" || true

# add the target itself
echo "$TARGET" >> "$OUT_DIR/dynamic_filtered.txt"
sort -u -o "$OUT_DIR/dynamic_filtered.txt" "$OUT_DIR/dynamic_filtered.txt"

URL_COUNT=$(wc -l < "$OUT_DIR/dynamic_filtered.txt" | tr -d ' ')
log "=== Web Cache Deception hunt: $DOMAIN ($URL_COUNT dynamic URLs) ==="
[ "$URL_COUNT" -eq 0 ] && { log "no dynamic URLs found"; exit 0; }

# ── cache header detection ────────────────────────────────────
is_cached(){
  local headers="$1"
  echo "$headers" | grep -qiE \
    'x-cache:\s*(HIT|hit)|cf-cache-status:\s*(HIT|DYNAMIC)|age:\s*[1-9]|x-varnish.*[0-9]+ [0-9]+|x-fastly-request-id'
}

# ── probe each URL ────────────────────────────────────────────
while IFS= read -r url; do
  [ -z "$url" ] && continue
  url_clean="${url%%\?*}"

  # baseline: normal request
  baseline=$(curl "${CURL_OPTS[@]}" "$url_clean" 2>/dev/null | head -c 3000)
  baseline_len=$(echo "$baseline" | wc -c | tr -d ' ')

  for ext in "${CACHE_EXTENSIONS[@]}"; do
    # path append: /account/x.css
    probe_url="${url_clean}/wcdtest${RANDOM}${ext}"
    probe_resp=$(curl "${CURL_OPTS[@]}" "$probe_url" 2>/dev/null | head -c 3000)
    probe_len=$(echo "$probe_resp" | wc -c | tr -d ' ')

    # check: same content-length as baseline + cache headers = WCD candidate
    len_diff=$((probe_len - baseline_len))
    [ "$len_diff" -lt 0 ] && len_diff=$((-len_diff))

    if [ "$len_diff" -lt 100 ] && is_cached "$probe_resp"; then
      hit "[HIGH] WCD candidate: $probe_url — response matches baseline ($baseline_len≈$probe_len) + cache HIT detected"
    fi

    # delimiter confusion: /account;wcd.css
    for delim in "${PATH_DELIMITERS[@]}"; do
      delim_url="${url_clean}${delim}wcdtest${ext}"
      delim_resp=$(curl "${CURL_OPTS[@]}" "$delim_url" 2>/dev/null | head -c 3000)
      delim_len=$(echo "$delim_resp" | wc -c | tr -d ' ')

      len_diff=$((delim_len - baseline_len))
      [ "$len_diff" -lt 0 ] && len_diff=$((-len_diff))

      if [ "$len_diff" -lt 100 ] && is_cached "$delim_resp"; then
        hit "[HIGH] WCD path-confusion: $delim_url — delimiter '$delim' + cache HIT"
      fi
    done
  done
  sleep 0.5
done < "$OUT_DIR/dynamic_filtered.txt"

log "=== done: WCD sweep complete ==="
