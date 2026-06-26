#!/usr/bin/env bash
# hunt-sourcemap-endpoint-family.sh — Source map → API endpoint family + auth flow extraction
# 來源：Pattern - SourceMap Endpoint Family Disclosure（KB）
#      openfind Submission OF-014 #102（AICS 3.8MB source map → 6 endpoint family）
#
# 與 hunt-sourcemap-secrets.sh 互補：
#   - hunt-sourcemap-secrets   ：grep .map 內的硬編碼密鑰
#   - hunt-sourcemap-endpoint-family：抽 API endpoint / baseURL / auth flow / route table
#
# 流程：
#   1. 抓 HTML 找所有 .js 參考 + 嘗試對應 .map
#   2. parse map JSON → sourcesContent
#   3. 抽取：
#        a. /api/* endpoint
#        b. /v\d+/* versioned API
#        c. baseURL: / API_BASE
#        d. axios.create / fetch / XMLHttpRequest 呼叫
#        e. localStorage.setItem / sessionStorage（auth flow 線索）
#        f. <Route path="..."> / Router.route（前端路由）
#        g. process.env.REACT_APP_* / VITE_* / NEXT_PUBLIC_*（build-time env）
#
# 用法：
#   ./hunt-sourcemap-endpoint-family.sh https://aics.mailcloud.com.tw
#   ./hunt-sourcemap-endpoint-family.sh https://app.example.com
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./sourcemap_endpoint_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟠 $*" | tee -a "$OUT"; }
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }

log "=== sourcemap endpoint family hunt: $HOST ==="

# Phase 1: HTML → .js list
HTML=$(curl -sk --max-time 15 "$HOST/" 2>/dev/null)
if [ -z "$HTML" ]; then
  warn "Empty HTML response — host might be down or require non-default path"
  exit 0
fi

# 抽 <script src> + <link href> + 各種 framework bundle paths
JS_LIST=$(
  {
    echo "$HTML" | grep -oE '(src|href)=["\x27][^"\x27]*\.js[^"\x27]*["\x27]' | \
      sed -E 's/^[^=]+=["\x27]//; s/["\x27]$//'
    echo "$HTML" | grep -oE '"[^"]*/(_next|_nuxt|static|assets|dist)/[^"]*\.js"' | tr -d '"'
  } | sort -u | grep -v "^$" | head -30
)

if [ -z "$JS_LIST" ]; then
  warn "No .js references found in HTML"
  exit 0
fi
log "Found $(echo "$JS_LIST" | wc -l | tr -d ' ') .js files in HTML"

# Phase 2: 對每個 .js 試 .map
MAP_COUNT=0
MAP_FILES=()
for JS in $JS_LIST; do
  # 相對路徑 → 絕對
  if [[ "$JS" =~ ^https?:// ]]; then
    URL="$JS"
  elif [[ "$JS" =~ ^// ]]; then
    URL="https:${JS}"
  elif [[ "$JS" =~ ^/ ]]; then
    URL="${HOST}${JS}"
  else
    URL="${HOST}/${JS}"
  fi
  MAP_URL="${URL}.map"

  STATUS=$(curl -sk --max-time 10 -o /dev/null -w "%{http_code}" "$MAP_URL")
  if [ "$STATUS" != "200" ]; then
    continue
  fi

  MAP_COUNT=$((MAP_COUNT+1))
  MAP_FILE="$OUT_DIR/${SLUG}_map_${MAP_COUNT}.json"
  curl -sk --max-time 30 "$MAP_URL" -o "$MAP_FILE"
  SIZE=$(stat -f "%z" "$MAP_FILE" 2>/dev/null || stat -c "%s" "$MAP_FILE" 2>/dev/null || echo 0)
  if [ "$SIZE" -lt 1000 ]; then
    rm -f "$MAP_FILE"
    continue
  fi
  hit "MAP found: $MAP_URL ($SIZE bytes)"
  MAP_FILES+=("$MAP_FILE")
done

if [ ${#MAP_FILES[@]} -eq 0 ]; then
  log "No source maps found — likely properly disabled in production build"
  log "Output: $OUT"
  exit 0
fi

# Phase 3: 從 .map 抽 endpoint / auth flow / route
log ""
log "── Extracting endpoint family ──"

python3 - "$OUT" "${MAP_FILES[@]}" <<'PY'
import json, sys, re
from collections import Counter

out_path = sys.argv[1]
map_files = sys.argv[2:]

endpoints = Counter()
base_urls = Counter()
api_versions = Counter()
auth_clues = Counter()
routes = Counter()
build_env = Counter()
http_calls = Counter()

for mf in map_files:
    try:
        with open(mf) as f:
            d = json.load(f)
    except Exception as e:
        continue
    contents = d.get("sourcesContent") or []
    sources = d.get("sources") or []
    for idx, c in enumerate(contents):
        if not c:
            continue
        src = sources[idx] if idx < len(sources) else ""
        if "node_modules" in src or "webpack:///webpack" in src:
            continue

        # 1. /api/* endpoints
        for m in re.findall(r"['\"\`]/api/[a-zA-Z0-9_/\-]+['\"\`]", c):
            endpoints[m.strip("'\"\`")] += 1

        # 2. versioned /v\d+/* paths
        for m in re.findall(r"['\"\`]/v\d+/[a-zA-Z0-9_/\-]+['\"\`]", c):
            api_versions[m.strip("'\"\`")] += 1

        # 3. baseURL / API_BASE
        for m in re.findall(r"(?:baseURL|API_BASE|apiBase|API_URL|backendURL)\s*[:=]\s*['\"\`]([^'\"\`]+)['\"\`]", c):
            if len(m) > 4 and len(m) < 200:
                base_urls[m] += 1

        # 4. axios.create / axios.get/post / fetch
        for m in re.findall(r"axios\.(?:create|get|post|put|delete|patch)\s*\(\s*['\"\`]([^'\"\`]+)['\"\`]", c):
            http_calls[("axios", m)] += 1
        for m in re.findall(r"fetch\s*\(\s*['\"\`]([^'\"\`]+)['\"\`]", c):
            http_calls[("fetch", m)] += 1

        # 5. auth flow clues
        if "localStorage.setItem" in c or "localStorage.getItem" in c:
            for m in re.findall(r"localStorage\.(setItem|getItem)\s*\(\s*['\"\`]([^'\"\`]+)['\"\`]", c):
                auth_clues[("localStorage", m[1])] += 1
        if "sessionStorage" in c:
            for m in re.findall(r"sessionStorage\.(setItem|getItem)\s*\(\s*['\"\`]([^'\"\`]+)['\"\`]", c):
                auth_clues[("sessionStorage", m[1])] += 1
        if "Authorization" in c and "Bearer" in c:
            auth_clues[("Bearer-header", "in-source")] += 1
        if "document.cookie" in c:
            auth_clues[("cookie-direct", "")] += 1
        if "SameSite" in c:
            auth_clues[("SameSite-mentioned", "")] += 1

        # 6. Front-end routes
        for m in re.findall(r"['\"\`](/[a-z][a-z0-9/_-]*)['\"\`]\s*,\s*(?:component|element|page)", c):
            if "/api/" not in m:
                routes[m] += 1
        for m in re.findall(r"<Route\s+path\s*=\s*['\"\`]([^'\"\`]+)['\"\`]", c):
            routes[m] += 1

        # 7. build-time env
        for m in re.findall(r"process\.env\.(REACT_APP_[A-Z_]+|NEXT_PUBLIC_[A-Z_]+|VITE_[A-Z_]+|VUE_APP_[A-Z_]+)", c):
            build_env[m] += 1

# Output
with open(out_path, "a") as f:
    f.write("\n══ Endpoint Family Extraction Summary ══\n\n")

    f.write(f"### Backend API endpoints (/api/*) — {len(endpoints)} unique\n")
    for ep, cnt in endpoints.most_common(50):
        f.write(f"  {ep}  (×{cnt})\n")

    f.write(f"\n### Versioned API (/v\\d+/*) — {len(api_versions)} unique\n")
    for ep, cnt in api_versions.most_common(30):
        f.write(f"  {ep}  (×{cnt})\n")

    f.write(f"\n### baseURL / API_BASE hardcoded — {len(base_urls)} unique\n")
    for u, cnt in base_urls.most_common(20):
        f.write(f"  {u}  (×{cnt})\n")

    f.write(f"\n### HTTP client calls (axios/fetch) — {len(http_calls)} unique\n")
    for (lib, ep), cnt in http_calls.most_common(30):
        f.write(f"  {lib}: {ep}  (×{cnt})\n")

    f.write(f"\n### Auth flow clues — {len(auth_clues)} unique\n")
    for (kind, val), cnt in auth_clues.most_common():
        f.write(f"  {kind}: {val}  (×{cnt})\n")

    f.write(f"\n### Front-end routes — {len(routes)} unique\n")
    for r, cnt in routes.most_common(30):
        f.write(f"  {r}  (×{cnt})\n")

    f.write(f"\n### Build-time env vars referenced — {len(build_env)} unique\n")
    for e, cnt in build_env.most_common():
        f.write(f"  {e}  (×{cnt})\n")

# Severity hints
print()
total = len(endpoints) + len(api_versions)
if total >= 10:
    print(f"🔴 HIGH-VALUE: {total} unique API endpoints leaked → P3-P2 candidate")
elif total >= 3:
    print(f"🟠 MODERATE: {total} unique API endpoints → P4-P3 candidate")
elif total > 0:
    print(f"🟡 LOW: {total} unique API endpoints — limited attack surface expansion")

if any(k[0] == "Bearer-header" for k in auth_clues):
    print("🟠 Auth = Bearer JWT (likely localStorage) — if also CORS ACAC:true, see Pattern - CORS ACAC True with Bearer Auth")
if any(k[0] == "cookie-direct" for k in auth_clues):
    print("🔴 Auth = Cookie-based — if CORS ACAC:true reflected, instant CSRF risk")
PY

log ""
log "=== done → $OUT ==="
