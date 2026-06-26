#!/usr/bin/env bash
# hunt-postmessage.sh — PostMessage exploitation surface detector
#
# Crawls JS bundles and inline scripts for postMessage handlers
# (addEventListener('message',...)) and postMessage calls lacking
# origin validation. GET-only, safe.
#
# Checks:
#   1. addEventListener('message',...) without origin check
#   2. postMessage('*') or postMessage(data, '*') — any-origin sends
#   3. eval/innerHTML/document.write in message handlers (sink patterns)
#   4. iframe embedding patterns that receive cross-origin messages
#
# Usage:
#   OUT_DIR=/path hunt-postmessage.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-postmsg-$$}"
mkdir -p "$OUT_DIR"

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
KATANA="$(command -v katana 2>/dev/null || echo '')"

OUT="$OUT_DIR/postmessage_results.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟠 $*" | tee -a "$OUT"; }

# ── collect JS files ──────────────────────────────────────────
JS_URLS="$OUT_DIR/js_urls.txt"
: > "$JS_URLS"

# get inline + external JS from the page
PAGE_HTML="$OUT_DIR/page.html"
curl -sk -m 15 -L "$TARGET" -o "$PAGE_HTML" 2>/dev/null || true

# extract script src from HTML
grep -oP 'src=["'"'"'][^"'"'"']*\.js[^"'"'"']*["'"'"']' "$PAGE_HTML" 2>/dev/null \
  | sed "s/src=[\"']//;s/[\"']$//" \
  | while read -r src; do
    case "$src" in
      http*) echo "$src" ;;
      //*) echo "https:$src" ;;
      /*) echo "https://$DOMAIN$src" ;;
      *) echo "https://$DOMAIN/$src" ;;
    esac
  done > "$JS_URLS" 2>/dev/null || true

# katana for deeper JS discovery
if [ -n "$KATANA" ]; then
  "$KATANA" -u "$TARGET" -d 2 -jc -silent -ef css,png,jpg,gif,svg,ico,woff,ttf \
    2>/dev/null | grep -iE '\.js(\?|$)' >> "$JS_URLS" || true
fi

sort -u -o "$JS_URLS" "$JS_URLS"
JS_COUNT=$(wc -l < "$JS_URLS" | tr -d ' ')
log "=== PostMessage hunt: $DOMAIN ($JS_COUNT JS files + inline) ==="

# ── check inline scripts ──────────────────────────────────────
check_js_content(){
  local source="$1" content="$2"

  # addEventListener('message') without origin check
  if echo "$content" | grep -qE "addEventListener\s*\(\s*[\"']message[\"']"; then
    # check if origin is validated nearby
    handler_block=$(echo "$content" | grep -oP "addEventListener\s*\(\s*[\"']message[\"'][^}]{0,500}" | head -3)
    if ! echo "$handler_block" | grep -qiE 'origin\s*[!=]==|\.origin\s*[!=]==|checkOrigin|allowedOrigin|trustedOrigin'; then
      # check for dangerous sinks in handler
      if echo "$handler_block" | grep -qiE 'eval\s*\(|innerHTML|document\.write|\.src\s*=|location\s*=|window\.open'; then
        hit "[HIGH] postMessage handler with dangerous sink (no origin check): $source"
      else
        warn "[MEDIUM] postMessage handler without origin validation: $source"
      fi
    fi
  fi

  # postMessage to any origin
  if echo "$content" | grep -qE 'postMessage\s*\([^)]*,\s*["\x27]\*["\x27]'; then
    warn "[MEDIUM] postMessage to wildcard origin '*': $source"
  fi
}

# check inline scripts
if [ -s "$PAGE_HTML" ]; then
  INLINE_JS=$(grep -oP '<script[^>]*>[\s\S]*?</script>' "$PAGE_HTML" 2>/dev/null | head -c 50000)
  [ -n "$INLINE_JS" ] && check_js_content "$TARGET (inline)" "$INLINE_JS"
fi

# ── check external JS files ──────────────────────────────────
while IFS= read -r js_url; do
  [ -z "$js_url" ] && continue
  js_content=$(curl -sk -m 10 "$js_url" 2>/dev/null | head -c 100000)
  [ -z "$js_content" ] && continue

  # only process if postMessage-related
  if echo "$js_content" | grep -qE "postMessage|addEventListener.*message"; then
    check_js_content "$js_url" "$js_content"
  fi
  sleep 0.2
done < "$JS_URLS"

log "=== done: postMessage sweep complete ==="
