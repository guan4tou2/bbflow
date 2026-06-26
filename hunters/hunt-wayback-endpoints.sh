#!/usr/bin/env bash
# hunt-wayback-endpoints.sh — Wayback Machine CDX endpoint mining（OSINT Arsenal §16.17）
#
# 查詢 Wayback CDX API，撈出歷史上存在但可能被移除的端點，
# 篩選高價值路徑（admin / api / config / backup / debug / internal 等）。
# 補足 CT log 與 live 掃描看不到的「已下線但可能復活」攻擊面。
#
# 用法（domain 模式，bbflow 從 ROOT_DOMAIN 呼叫）：
#   ./hunt-wayback-endpoints.sh example.com [known_paths_file]
#   known_paths_file: 每行一個 path，命中則跳過

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <domain> [known_paths_file]"; exit 1; }
DOMAIN=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')
KNOWN_FILE="${2:-}"

OUT_DIR="${OUT_DIR:-./wayback_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }

WAYMORE="$(command -v waymore 2>/dev/null || echo '')"

log "=== Wayback CDX endpoint mine: $DOMAIN ==="

# ── CDX API 查詢 ───────────────────────────────────────────────────────────────
CDX_URL="https://web.archive.org/cdx/search/cdx"
CDX_PARAMS="url=*.${DOMAIN}/*&output=json&fl=original&collapse=urlkey&limit=8000&filter=statuscode:200"

log "  Querying CDX API (limit 8000 unique URLs)..."
CDX_RAW=$(curl -sk -m 60 "${CDX_URL}?${CDX_PARAMS}" 2>/dev/null)

CDX_URLS=""
if [ -n "$CDX_RAW" ] && [ "$CDX_RAW" != "[]" ]; then
  CDX_URLS=$(echo "$CDX_RAW" | python3 -c "
import sys, json
try:
    rows = json.load(sys.stdin)
    for row in rows[1:]:
        if row and row[0]:
            print(row[0])
except:
    pass
" 2>/dev/null)
fi

# ── waymore 補充（multi-source：CommonCrawl + OTX + URLScan + VirusTotal）────
WAYMORE_URLS=""
if [ -n "$WAYMORE" ]; then
  log "  waymore: querying 7 sources (Wayback+CC+OTX+URLScan+VT+IntelX+GA)..."
  WAYMORE_DIR="$OUT_DIR/waymore_${SLUG}"
  mkdir -p "$WAYMORE_DIR"
  "$WAYMORE" -i "$DOMAIN" -mode U -oU "$WAYMORE_DIR/urls.txt" \
    -f -t 30 -p 3 --stream -nlf 2>/dev/null || true
  if [ -s "$WAYMORE_DIR/urls.txt" ]; then
    WAYMORE_URLS=$(cat "$WAYMORE_DIR/urls.txt")
    WM_COUNT=$(wc -l < "$WAYMORE_DIR/urls.txt" | tr -d ' ')
    log "  waymore: $WM_COUNT additional URLs"
  fi
fi

# merge + dedup
ALL_URLS=$(printf '%s\n%s' "$CDX_URLS" "$WAYMORE_URLS" | sort -u | grep -v '^$')

if [ -z "$ALL_URLS" ]; then
  log "  No URLs found from any source"
  exit 0
fi

TOTAL=$(echo "$ALL_URLS" | wc -l | tr -d ' ')
log "  Total unique URLs from CDX: $TOTAL"

# ── 載入已知路徑 set ───────────────────────────────────────────────────────────
declare -A KNOWN_SET
if [ -n "$KNOWN_FILE" ] && [ -f "$KNOWN_FILE" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && KNOWN_SET["${line,,}"]=1
  done < "$KNOWN_FILE"
fi

# ── 高價值路徑篩選 patterns ────────────────────────────────────────────────────
# §16.17 — 優先攻擊面關鍵字
HIGH_VALUE_RE='/(admin|administrator|manage|console|dashboard|cp|cpanel|backend|cms|wp-admin|phpmyadmin|adminer|dbadmin)'
HIGH_VALUE_RE+='|(api|v1|v2|v3|v4|graphql|rest|swagger|openapi|api-docs|api/docs)'
HIGH_VALUE_RE+='|(config|configuration|settings|setup|install|installer|update|upgrade)'
HIGH_VALUE_RE+='|(backup|bak|old|copy|archive|_backup|\.bak|\.old|\.orig|\.zip|\.tar|\.sql|\.dump)'
HIGH_VALUE_RE+='|(debug|test|dev|staging|stg|uat|qa|demo|preview|sandbox)'
HIGH_VALUE_RE+='|(internal|intranet|private|hidden|secret|credentials?|passwd|password|\.env|\.git)'
HIGH_VALUE_RE+='|(user|account|profile|member|login|signin|register|signup|auth|oauth|token|session)'
HIGH_VALUE_RE+='|(upload|file|files|download|attachment|storage|media|assets)'
HIGH_VALUE_RE+='|(report|export|import|log|logs|audit|monitor|status|health|metrics)'
HIGH_VALUE_RE+='|(\.php|\.asp|\.aspx|\.jsp|\.cfm|\.cgi|\.pl|\.rb|\.py)'
HIGH_VALUE_RE+='|(\.xml|\.json|\.yaml|\.yml|\.env|\.conf|\.cfg|\.ini|\.bak|\.sql)'

# ── 路徑萃取與去重 ───────────────────────────────────────────────────────────
INTERESTING_PATHS=$(echo "$ALL_URLS" | python3 -c "
import sys, re
from urllib.parse import urlparse
from collections import OrderedDict

high_re = re.compile(r'$HIGH_VALUE_RE', re.IGNORECASE)
seen = OrderedDict()

for url in sys.stdin:
    url = url.strip()
    if not url:
        continue
    try:
        p = urlparse(url)
        path = p.path
        if not path or path == '/':
            continue
        path_key = path.lower()
        if path_key not in seen and high_re.search(path):
            seen[path_key] = (url, path)
    except:
        pass

for url, path in list(seen.values())[:200]:
    print(path + '\t' + url)
" 2>/dev/null)

INTERESTING_COUNT=$(echo "$INTERESTING_PATHS" | grep -c '.' 2>/dev/null || echo 0)
log "  High-value paths: $INTERESTING_COUNT"

if [ "$INTERESTING_COUNT" -eq 0 ]; then
  log "  No high-value historical paths found"
  exit 0
fi

echo "" >> "$OUT"
echo "## High-Value Historical Endpoints (from Wayback CDX)" >> "$OUT"

NEW_COUNT=0
while IFS=$'\t' read -r path url; do
  [ -z "$path" ] && continue
  # 跳過已知路徑
  [ "${KNOWN_SET[${path,,}]+_}" ] && continue

  NEW_COUNT=$((NEW_COUNT + 1))

  # 分類 severity
  SEV="INFO"
  echo "$path" | grep -qiE '\.(bak|old|sql|dump|zip|tar|env|git)$|backup|credential|password|\.env|admin|phpmyadmin' && SEV="HIGH"
  echo "$path" | grep -qiE '/api/|/v[0-9]+/|swagger|openapi|graphql|/admin|/config|/debug' && SEV="MEDIUM"

  case "$SEV" in
    HIGH)   hit "[HIGH] Historical path: $path (example: $url)" ;;
    MEDIUM) info_hit "[MEDIUM] Historical path: $path" ;;
    *)      echo "  $path" >> "$OUT" ;;
  esac

done <<< "$INTERESTING_PATHS"

echo "" >> "$OUT"
log "=== done: $NEW_COUNT new historical paths found ==="
