#!/usr/bin/env bash
# hunt-arjun-params.sh — 隱藏 HTTP parameter discovery via arjun
#
# 用途：發現沒有出現在正常 URL 的隱藏 GET/POST/JSON parameters
# 改進：
#   - 使用 SecLists burp-parameter-names.txt（>6000 params）
#   - JSON output for structured parsing
#   - GET + POST + JSON 三種方法
#   - 支援 authenticated 掃描（ARJUN_HEADERS/ARJUN_COOKIES）
#   - Passive mode（只查歷史資料，不主動掃描）
#
# Usage:
#   OUT_DIR=/path ARJUN_HEADERS="Authorization: Bearer xxx" hunt-arjun-params.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-arjun-$$}"
mkdir -p "$OUT_DIR"

ARJUN="$(command -v arjun 2>/dev/null || echo '')"
[ -z "$ARJUN" ] && { echo "✗ arjun not found (pip3 install arjun --break-system-packages)"; exit 0; }

# 環境變數
EXTRA_HEADERS="${ARJUN_HEADERS:-}"
COOKIES="${ARJUN_COOKIES:-}"

# 字典優先序: SecLists > arjun 內建
SECLISTS_PARAMS="$HOME/Tools/SecLists/Discovery/Web-Content/burp-parameter-names.txt"
ASSETNOTE_PARAMS="$HOME/Tools/SecLists/Discovery/Web-Content/api/api-endpoints.txt"

ARJUN_FLAGS=(
  "-u" "$TARGET"
  "-m" "GET" "POST" "JSON"
  "-t" "10"
  "--stable"
  "-q"
  "-oJ" "$OUT_DIR/arjun_results.json"
)

# 使用更完整的字典
if [ -f "$SECLISTS_PARAMS" ]; then
  ARJUN_FLAGS+=("-w" "$SECLISTS_PARAMS")
fi

# Authenticated scan
[ -n "$EXTRA_HEADERS" ] && ARJUN_FLAGS+=("--headers" "$EXTRA_HEADERS")
[ -n "$COOKIES" ] && ARJUN_FLAGS+=("--include" "Cookie: $COOKIES")

# Passive mode（快速，不主動請求）
ARJUN_FLAGS+=("--passive")

"$ARJUN" "${ARJUN_FLAGS[@]}" 2>/dev/null || true

# ── also scan common API sub-paths ────────────────────────
for SUFFIX in "/api" "/api/v1" "/api/v2" "/graphql" "/rest"; do
  API_URL="${TARGET}${SUFFIX}"
  # quick check if endpoint exists
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$API_URL" 2>/dev/null)
  if [[ "$STATUS" =~ ^(200|401|403|405)$ ]]; then
    local_flags=("-u" "$API_URL" "-m" "GET" "POST" "JSON" "-t" "10" "-q"
                 "-oJ" "$OUT_DIR/arjun_api_$(echo $SUFFIX | tr '/' '_').json")
    [ -f "$SECLISTS_PARAMS" ] && local_flags+=("-w" "$SECLISTS_PARAMS")
    [ -n "$EXTRA_HEADERS" ] && local_flags+=("--headers" "$EXTRA_HEADERS")
    "$ARJUN" "${local_flags[@]}" 2>/dev/null || true
  fi
done

# ── parse all JSON results ─────────────────────────────────
python3 - <<'PYEOF' 2>/dev/null || true
import json, os, glob

out_dir = os.environ.get('OUT_DIR', '/tmp')
results = []

for jf in glob.glob(f'{out_dir}/arjun*.json'):
    try:
        data = json.load(open(jf))
        if isinstance(data, dict):
            for endpoint, info in data.items():
                params = info.get('params', []) if isinstance(info, dict) else info
                if isinstance(params, list) and params:
                    results.append((endpoint, params))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get('params'):
                    results.append((item.get('url', '?'), item['params']))
    except Exception:
        pass

for endpoint, params in results:
    high_interest = [p for p in params if any(k in p.lower() for k in
        ['id','user','admin','token','key','secret','password','pass','auth','role','redirect',
         'url','file','path','cmd','exec','shell','debug','test','internal'])]
    if high_interest:
        print(f'🔴 ARJUN [high-interest] {endpoint} → {high_interest}')
    else:
        print(f'🔴 ARJUN [hidden-params] {endpoint} → {params[:8]}')
PYEOF
