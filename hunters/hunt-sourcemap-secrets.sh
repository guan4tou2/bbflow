#!/usr/bin/env bash
# hunt-sourcemap-secrets.sh — Source map 發現 → 原始碼內密鑰提取
# 來源：SPA source map exposure (disclosed writeup)
#      multi-brand SSO app.example.com _next/static/chunks/*.js.map（2002 files）
#      another disclosed source map case
#
# 流程：
#   1. 抓 HTML 找所有 .js 參考
#   2. 對每個 .js 嘗試 .map
#   3. Parse map JSON → sources + sourcesContent
#   4. grep sourcesContent 找 API key / token / secret / credentials
#
# 用法：
#   ./hunt-sourcemap-secrets.sh https://insight.example.com
#   ./hunt-sourcemap-secrets.sh https://passport.example.com
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./sourcemap_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }

log "=== sourcemap hunt: $HOST ==="

# ── Step 1: list .js files referenced in HTML ───────────────────
HTML=$(curl -sk --max-time 10 "$HOST/")
[ -z "$HTML" ] && { log "empty body"; exit 0; }

# Extract relative + absolute .js URLs
JS_LIST=$(echo "$HTML" | grep -oE '(src|href)=["\x27][^"\x27]*\.js[^"\x27]*["\x27]' | \
  sed -E 's/(src|href)=["\x27]([^"\x27]+)["\x27]/\2/' | sort -u)
# Also check for Next.js / webpack chunk patterns
CHUNK_LIST=$(echo "$HTML" | grep -oE '"[^"]*_next/static/chunks/[^"]*\.js"' | tr -d '"' | sort -u)
JS_LIST="$JS_LIST
$CHUNK_LIST"
JS_LIST=$(echo "$JS_LIST" | grep -v "^$" | head -20)

log "found $(echo "$JS_LIST" | wc -l | tr -d ' ') js refs"

MAP_COUNT=0
for JS in $JS_LIST; do
  # Resolve absolute URL
  if [[ "$JS" == http* ]]; then
    URL="$JS"
  elif [[ "$JS" == /* ]]; then
    URL="$HOST$JS"
  else
    URL="$HOST/$JS"
  fi
  MAP_URL="${URL}.map"

  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$MAP_URL")
  [ "$CODE" != "200" ] && continue

  MAP_COUNT=$((MAP_COUNT+1))
  MAP_FILE="$OUT_DIR/${SLUG}_map_${MAP_COUNT}.json"
  curl -sk --max-time 15 "$MAP_URL" -o "$MAP_FILE"
  [ ! -s "$MAP_FILE" ] && continue

  # Parse sources + grep secrets
  python3 - "$MAP_FILE" "$URL" "$OUT" <<'PY'
import json, sys, re, os
mf, url, out = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(mf) as f: d = json.load(f)
except Exception:
    sys.exit(0)

sources = d.get('sources', [])
contents = d.get('sourcesContent', []) or []
own = [s for s in sources if 'node_modules' not in s]
outfh = open(out, 'a')
outfh.write(f"✓ MAP {url}.map — {len(sources)} sources, {len(own)} own\n")

patterns = {
    'AIza': r'AIza[0-9A-Za-z_-]{35}',
    'sk_live': r'sk_live_[0-9a-zA-Z]{24,}',
    'pk_live': r'pk_live_[0-9a-zA-Z]{24,}',
    'sk_test': r'sk_test_[0-9a-zA-Z]{24,}',
    'Sentry DSN': r'https://[a-f0-9]{20,}@[a-z0-9.-]+\.sentry\.io/\d+',
    'Shopify storefront': r'[a-f0-9]{32}',  # rough
    'AWS key id': r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',
    'JWT': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    'password=': r'password["\']?\s*[:=]\s*["\'][^"\']{6,}["\']',
    'apiKey=': r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\'][^"\']{16,}["\']',
    'clientSecret=': r'client[_-]?secret["\']?\s*[:=]\s*["\'][^"\']{16,}["\']',
    'Bearer ': r'Bearer [A-Za-z0-9._-]{20,}',
    'v1.public': r'v1\.public\.[A-Za-z0-9_-]{40,}',
}

hits = set()
for idx, c in enumerate(contents):
    if not c or 'node_modules' in (sources[idx] if idx < len(sources) else ''):
        continue
    for label, pat in patterns.items():
        for m in re.findall(pat, c):
            v = m if isinstance(m, str) else m[0]
            # Filter Shopify: only if near "storefront"
            if label == 'Shopify storefront' and 'storefront' not in c.lower():
                continue
            hits.add(f"{label}: {v[:80]}  (in {sources[idx] if idx < len(sources) else '?'})")

for h in sorted(hits):
    outfh.write(f"🔴 {h}\n")
outfh.close()
PY
done

if [ "$MAP_COUNT" -eq 0 ]; then
  log "no .map files exposed"
fi
log "=== done → $OUT ($MAP_COUNT maps) ==="
