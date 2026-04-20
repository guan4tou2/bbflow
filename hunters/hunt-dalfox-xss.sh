#!/usr/bin/env bash
# hunt-dalfox-xss.sh — XSS hunting via dalfox + gf pattern pre-filter
#
# 流程：
#   1. 從 katana/gau 收集 URL（或直接用已有的 param_urls.txt）
#   2. gf xss 過濾：只保留含 xss-prone params 的 URL
#   3. dalfox pipe 掃描
#
# Usage: OUT_DIR=/path hunt-dalfox-xss.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-dalfox-$$}"
mkdir -p "$OUT_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DALFOX="$(command -v dalfox 2>/dev/null || echo '')"
KATANA="$(command -v katana 2>/dev/null || echo '')"
GAU="$(command -v gau 2>/dev/null || echo '')"
GF="$(command -v gf 2>/dev/null || echo '')"
URO="$(command -v uro 2>/dev/null || echo '')"

[ -z "$DALFOX" ] && { echo "✗ dalfox not found"; exit 0; }

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
ALL_URLS="$OUT_DIR/all_urls.txt"
> "$ALL_URLS"

# ── URL collection ──────────────────────────────────────────
# Check if param-fuzz already collected URLs for this host
PARENT_SLUG=$(echo "$TARGET" | sed -E 's|^https?://||' | tr '/:.' '_')
CACHED_PARAMS=$(find "$(dirname "$OUT_DIR")" -name "param_urls.txt" 2>/dev/null | head -1)

if [ -n "$CACHED_PARAMS" ] && [ -s "$CACHED_PARAMS" ]; then
  cp "$CACHED_PARAMS" "$ALL_URLS"
else
  # Fast crawl
  if [ -n "$KATANA" ]; then
    "$KATANA" -u "$TARGET" -d 3 -jc -silent -o "$OUT_DIR/katana.txt" 2>/dev/null || true
    [ -s "$OUT_DIR/katana.txt" ] && cat "$OUT_DIR/katana.txt" >> "$ALL_URLS"
  fi
  if [ -n "$GAU" ]; then
    echo "$DOMAIN" | "$GAU" --threads 5 \
      --blacklist eot,svg,ttf,woff,png,jpg,gif,ico,css,pdf 2>/dev/null >> "$ALL_URLS" || true
  else
    curl -sf "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey&limit=2000" \
      2>/dev/null >> "$ALL_URLS" || true
  fi
fi

# ── gf xss filter ─────────────────────────────────────────
XSS_URLS="$OUT_DIR/xss_candidates.txt"
if [ -n "$GF" ] && [ -f "$HOME/.gf/xss.json" ]; then
  grep -E '\?' "$ALL_URLS" | sort -u \
    | { "$GF" xss 2>/dev/null || cat; } > "$XSS_URLS"
else
  # fallback: manual XSS-prone param pattern
  grep -iE '[?&](q|s|search|query|keyword|input|text|content|comment|message|title|name|desc|redirect|url|next|return|callback|data|value|param|ref|page|id|cat|type|lang|locale|theme|style|template|view|action|file|path|src|href|link)[=]' \
    "$ALL_URLS" | sort -u > "$XSS_URLS" || true
fi

[ -n "$URO" ] && "$URO" < "$XSS_URLS" > "$OUT_DIR/xss_deduped.txt" 2>/dev/null \
  && mv "$OUT_DIR/xss_deduped.txt" "$XSS_URLS" || true

XSS_COUNT=$(wc -l < "$XSS_URLS" | tr -d ' ')
[ "$XSS_COUNT" -eq 0 ] && exit 0

# ── dalfox scan ─────────────────────────────────────────────
DALFOX_OUT="$OUT_DIR/dalfox_results.txt"
> "$DALFOX_OUT"

"$DALFOX" pipe \
  --silence \
  --no-color \
  --output "$DALFOX_OUT" \
  --worker 5 \
  --timeout 10 \
  --delay 100 \
  < "$XSS_URLS" 2>/dev/null || true

# Output hits
while IFS= read -r line; do
  # dalfox output: [VULN] or [POC] lines
  echo "$line" | grep -qiE '\[VULN\]|\[POC\]|\[G\]' && echo "🔴 XSS $line"
done < "$DALFOX_OUT" 2>/dev/null || true
