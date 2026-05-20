#!/usr/bin/env bash
# hunt-version-json.sh — 版本/環境對映 JSON 洩漏探測
# 來源：EVERY8D TP-S18 — hs.e8d.tw/json/version.json + /json/version_pmo.json
#       回傳 {"localhost":"localhost","develop":"dev-portalite.e8d.cc","test":"test-portalite.e8d.cc"}
#       揭露 dev/test/UAT/production 環境主機名稱
#
# 泛化對象：PHP/Fat-Free Framework / 自製部署 app，常把環境 routing map 放在
#   /json/version.json, /json/version_pmo.json, /json/config.json, /version.json,
#   /config.json, /api/version, /api/config
#
# 判斷邏輯：
#   1. HTTP 200 + Content-Type: application/json (或 body 以 { 開頭)
#   2. Python3 解析 JSON，grep 含 "develop" / "test" / "uat" / "staging" / "localhost" 的 key 或 value
#   3. 額外標記含 .cc TLD / .dev / .local / 內網 IP (10./192.168./172.) 的主機名稱
#
# 用法：
#   ./hunt-version-json.sh https://target.com
#   cat bbot/live_hosts.txt | while read h; do ./hunt-version-json.sh "$h"; done
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"

OUT_DIR="${OUT_DIR:-./version_json_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

log "=== version-json hunt: $HOST ==="

CANDIDATES=(
  "/json/version.json"
  "/json/version_pmo.json"
  "/json/config.json"
  "/version.json"
  "/config.json"
  "/api/version"
  "/api/config"
  "/app/version.json"
  "/static/version.json"
)

for PATH_CAND in "${CANDIDATES[@]}"; do
  URL="${HOST}${PATH_CAND}"
  BODY=$(curl -sk --max-time 8 "$URL" 2>/dev/null)
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$URL" 2>/dev/null)

  [ "$CODE" != "200" ] && continue

  # Must look like JSON (object or array)
  echo "$BODY" | grep -qE '^\s*[\[{]' || continue

  python3 - "$URL" "$OUT" <<PY
import json, sys, re
url, out_path = sys.argv[1], sys.argv[2]

body = """$BODY"""
try:
    data = json.loads(body)
except Exception:
    # Try to extract first JSON object from body
    m = re.search(r'\{.+\}', body, re.DOTALL)
    if not m:
        sys.exit(0)
    try:
        data = json.loads(m.group(0))
    except Exception:
        sys.exit(0)

out = open(out_path, 'a')
def say(msg): print(msg); out.write(msg + "\n")

# Flatten all string key-value pairs for analysis
pairs = []
def walk(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            walk(v, k)
    elif isinstance(obj, list):
        for item in obj:
            walk(item, prefix)
    elif isinstance(obj, str):
        pairs.append((prefix, obj))

walk(data)

if not pairs:
    out.close(); sys.exit(0)

env_keys = re.compile(r'develop|test|uat|staging|local|qa|sandbox|demo|preview|rc\d|beta|alpha', re.I)
internal_val = re.compile(
    r'\.cc$|\.dev$|\.local$|\.internal$|localhost'
    r'|^10\.\d+\.\d+\.\d+$'
    r'|^192\.168\.\d+\.\d+$'
    r'|^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$',
    re.I
)

found_any = False
for key, val in pairs:
    is_env_key = bool(env_keys.search(key)) or bool(env_keys.search(val))
    is_internal = bool(internal_val.search(val))
    if is_env_key or is_internal:
        found_any = True
        label = ""
        if is_internal:
            label = " [INTERNAL HOST/IP]"
        elif is_env_key:
            label = " [ENV MAPPING]"
        say(f"🔴 version-json {url} key={key!r} → value={val!r}{label}")

if not found_any:
    # Still flag it — JSON at this path is unusual even without env keys
    say(f"🟡 version-json {url} → JSON exposed (no obvious env keys, manual review)")
    say(f"     content: {body[:300]}")

out.close()
PY

done

log "=== done → $OUT ==="
