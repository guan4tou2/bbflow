#!/usr/bin/env bash
# ============================================================================
# hunt-nuclei-deep.sh — 擴充 nuclei 攻擊面
#   覆蓋：XSS / SQLi / SSRF / LFI / RCE / Path Traversal / Info Leak / Debug
#   覆蓋：Weak login / Default cred / Exposed panels / Misconfig / CVE
#   覆蓋：Takeover / CORS / Open Redirect / SSTI / XXE
#
# 設計原則：
#   - 預設 template 往往 miss deep surface，這個腳本分「類」跑更精準 tag
#   - 每個類別都可獨立關掉（CATEGORY=xss 只跑 XSS）
#   - 自動整合 bb-recon 自訂 template（若存在）
#
# Usage:
#   tools/hunters/hunt-nuclei-deep.sh https://target.com
#   CATEGORY=xss,sqli tools/hunters/hunt-nuclei-deep.sh https://target.com
#   URL_LIST=urls.txt tools/hunters/hunt-nuclei-deep.sh
#   FAST=1 tools/hunters/hunt-nuclei-deep.sh https://target.com     # 只跑 high/crit
#   RATE=20 CONC=5 tools/hunters/hunt-nuclei-deep.sh https://target.com   # 低噪音
#
# Env:
#   CATEGORY  要跑的類別（逗號分隔）預設 all
#             可選：xss|sqli|ssrf|lfi|rce|redirect|ssti|xxe|takeover|cors|
#                  info|debug|panel|cve|misconfig|weak-login|cloud|oast
#   FAST      1 = 只跑 severity >= high
#   RATE      50 (nuclei -rate-limit)
#   CONC      25 (nuclei -c)
#   DAST      1 = 開啟 -dast mode（fuzz payload）
#   OAST      1 = 開啟 interactsh（需要 network）
#   BB_RECON  $PWD/tools/nuclei-templates/bb-recon  自訂模板目錄
# ============================================================================

set -u

TARGET="${1:-}"
OUTDIR="${OUTDIR:-./nuclei_deep_out}"
CATEGORY="${CATEGORY:-all}"
FAST="${FAST:-0}"
RATE="${RATE:-50}"
CONC="${CONC:-25}"
DAST="${DAST:-0}"
OAST="${OAST:-0}"
BB_RECON="${BB_RECON:-$(dirname "$0")/../nuclei-templates/bb-recon}"
URL_LIST="${URL_LIST:-}"

if [[ -z "$TARGET" && -z "$URL_LIST" ]]; then
  echo "Usage: $0 <https://target> | URL_LIST=urls.txt $0" >&2
  echo "       CATEGORY=xss,sqli $0 <target>" >&2
  exit 1
fi

command -v nuclei >/dev/null 2>&1 || { echo "nuclei required"; exit 1; }

mkdir -p "$OUTDIR"

if [[ -n "$URL_LIST" ]]; then
  TAG_SLUG=$(basename "$URL_LIST" | tr -c 'a-zA-Z0-9._-' '_')
  OUT="$OUTDIR/list_${TAG_SLUG}.txt"
  INPUT_FLAG="-l $URL_LIST"
else
  TAG_SLUG=$(echo "$TARGET" | sed 's|https\?://||; s|/|_|g' | tr -c 'a-zA-Z0-9._-' '_')
  OUT="$OUTDIR/${TAG_SLUG}.txt"
  INPUT_FLAG="-u $TARGET"
fi

: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "$*" | tee -a "$OUT"; }

SEVERITY_FILTER="low,medium,high,critical"
if [[ "$FAST" == "1" ]]; then
  SEVERITY_FILTER="high,critical"
fi

NUCLEI_BASE=(
  -rate-limit "$RATE"
  -c "$CONC"
  -severity "$SEVERITY_FILTER"
  -silent
  -ni            # no interactsh unless OAST=1
)

if [[ "$OAST" == "1" ]]; then
  NUCLEI_BASE=("${NUCLEI_BASE[@]/-ni/}")
fi

DAST_FLAG=""
if [[ "$DAST" == "1" ]]; then
  DAST_FLAG="-dast"
fi

BB_RECON_FLAG=""
if [[ -d "$BB_RECON" ]]; then
  BB_RECON_FLAG="-t $BB_RECON"
fi

log "=== Nuclei-deep hunt: ${TARGET:-$URL_LIST} (CATEGORY=$CATEGORY FAST=$FAST DAST=$DAST) ==="

run_cat() {
  local name="$1"; shift
  local args=("$@")
  log "--- [$name] ---"
  nuclei $INPUT_FLAG "${NUCLEI_BASE[@]}" $BB_RECON_FLAG $DAST_FLAG "${args[@]}" 2>/dev/null \
    | tee -a "$OUT"
}

want() {
  [[ "$CATEGORY" == "all" ]] && return 0
  [[ ",$CATEGORY," == *",$1,"* ]]
}

# ============================================================================
# 1. XSS — reflected / stored / DOM
# ============================================================================
if want xss; then
  run_cat "XSS" -tags xss,dom -type http
fi

# ============================================================================
# 2. SQL Injection — error-based / time-based / boolean
# ============================================================================
if want sqli; then
  run_cat "SQLi" -tags sqli,sql-injection -type http
fi

# ============================================================================
# 3. SSRF — blind / reflected / cloud metadata
# ============================================================================
if want ssrf; then
  run_cat "SSRF" -tags ssrf -type http
fi

# ============================================================================
# 4. LFI / Path Traversal
# ============================================================================
if want lfi; then
  run_cat "LFI" -tags lfi,file,file-upload,traversal -type http
fi

# ============================================================================
# 5. RCE — Log4j / Spring4Shell / Struts / Fastjson / Shiro / etc
# ============================================================================
if want rce; then
  run_cat "RCE" -tags rce,cmd,log4j,spring,struts,fastjson,shiro,thinkphp,weblogic -type http
fi

# ============================================================================
# 6. Open Redirect
# ============================================================================
if want redirect; then
  run_cat "OpenRedirect" -tags redirect,open-redirect -type http
fi

# ============================================================================
# 7. SSTI — Template injection
# ============================================================================
if want ssti; then
  run_cat "SSTI" -tags ssti -type http
fi

# ============================================================================
# 8. XXE
# ============================================================================
if want xxe; then
  run_cat "XXE" -tags xxe -type http
fi

# ============================================================================
# 9. Subdomain Takeover
# ============================================================================
if want takeover; then
  run_cat "Takeover" -tags takeover -type http
fi

# ============================================================================
# 10. CORS misconfig
# ============================================================================
if want cors; then
  run_cat "CORS" -tags cors,misconfig -type http
fi

# ============================================================================
# 11. Info Disclosure — token / key / secret / email
# ============================================================================
if want info; then
  run_cat "InfoDisclosure" -tags exposure,exposed,disclosure,token,key -type http
fi

# ============================================================================
# 12. Debug endpoints — /debug /actuator /phpinfo /server-status
# ============================================================================
if want debug; then
  run_cat "Debug" -tags debug,phpinfo,actuator,springboot,jmx,prometheus,trace -type http
fi

# ============================================================================
# 13. Exposed Panels — /admin /login /manager
# ============================================================================
if want panel; then
  run_cat "Panel" -tags panel,exposed-panel -type http
fi

# ============================================================================
# 14. Default Login / Weak creds
# ============================================================================
if want weak-login; then
  run_cat "WeakLogin" -tags default-login,default-logins,weak-credential -type http
fi

# ============================================================================
# 15. CVE — all known CVE templates
# ============================================================================
if want cve; then
  run_cat "CVE" -tags cve -severity "${SEVERITY_FILTER}" -type http
fi

# ============================================================================
# 16. Misconfig — generic
# ============================================================================
if want misconfig; then
  run_cat "Misconfig" -tags misconfig,misconfiguration -type http
fi

# ============================================================================
# 17. Cloud — AWS / Azure / GCP misconfig
# ============================================================================
if want cloud; then
  run_cat "Cloud" -tags aws,azure,gcp,s3,cloud -type http
fi

# ============================================================================
# 18. OAST — Out-of-band（需要 interactsh）
# ============================================================================
if want oast && [[ "$OAST" == "1" ]]; then
  run_cat "OAST" -tags oast -type http
fi

log "=== Done. Results in $OUT ==="

# 匯總 hit 數
HITS=$(grep -cE '^\[.*\].*\]' "$OUT" 2>/dev/null || echo "0")
log "Total hits: $HITS"
