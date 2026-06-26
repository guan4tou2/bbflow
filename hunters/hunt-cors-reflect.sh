#!/usr/bin/env bash
# hunt-cors-reflect.sh — Reflective CORS + null origin + regex prefix bypass + auth-mechanism awareness
# 來源：
#   - reflective CORS pattern（research/target/*）
#   - app-hub (differential response pattern).example.com
#   - [[Pattern - CORS ACAC True with Bearer Auth]]（auth-aware downgrade，2026-05-13 加）
#
# 測試四層：
#   A. 任意 Origin 反射（worst case）
#   B. null origin 反射
#   C. Regex prefix bypass（原 allowed = example.com → 測 attackui.com / notui.com）
#   D. Credentials: true 確認（決定是否可 browser exploit）
#
# 自動判斷 auth 機制（2026-05-13 新增）：
#   - Set-Cookie + ACAC:true        → 🔴 instant CSRF (P2/P3)
#   - Authorization: Bearer + ACAC  → 🟠 misconfig only (P4/P5)  ← 降級，避免 N/A
#   - 無法判斷                       → 🟡 manual review needed
#
# 用法：
#   ./hunt-cors-reflect.sh https://cloudaccess.svc.example.com/devices

#   cat bbot/live_hosts.txt | while read h; do ./hunt-cors-reflect.sh "$h/"; done
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

URL="${1:-}"
[ -z "$URL" ] && { echo "Usage: $0 <full-url>"; exit 1; }
OUT_DIR="${OUT_DIR:-./cors_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$URL" | sed 's|https\?://||;s|[/:?&=]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "🔴 $*" | tee -a "$OUT"; }

# Derive legitimate suffix to test prefix bypass (domain after first dot)
DOMAIN=$(echo "$URL" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
TLD=$(echo "$DOMAIN" | awk -F. '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')

probe() {
  local origin="$1" label="$2"
  local resp
  resp=$(curl -skI --max-time 8 -H "Origin: $origin" "$URL" 2>/dev/null)
  local acao aclc
  acao=$(echo "$resp" | grep -i "^access-control-allow-origin:" | tr -d '\r\n' | awk '{print $2}')
  aclc=$(echo "$resp" | grep -i "^access-control-allow-credentials:" | tr -d '\r\n' | awk '{print $2}')
  if [ -n "$acao" ]; then
    if [ "$acao" = "$origin" ] || [ "$acao" = "null" ]; then
      if [ "$aclc" = "true" ]; then
        hit "$label: ACAO=$acao  ACAC=true  ← browser-exploitable"
      else
        echo "🟡 $label: ACAO=$acao  ACAC=${aclc:-none}" | tee -a "$OUT"
      fi
    else
      echo "   $label: ACAO=$acao (not reflected)" >> "$OUT"
    fi
  fi
}

log "=== CORS hunt: $URL (tld=$TLD) ==="

# A. arbitrary reflection
probe "https://attacker-random-$(date +%s).com" "A arbitrary"
# B. null
probe "null" "B null"
# C. regex prefix bypass (2 char prefix)
probe "https://attack${TLD}" "C prefix bypass (attack${TLD})"
# C2. suffix bypass (targetcom.evil → looks like target.com)
probe "https://${DOMAIN}.attacker.com" "C suffix bypass (${DOMAIN}.attacker.com)"
# C3. char substitution (swap . for -)
probe "https://$(echo "$DOMAIN" | tr . -).com" "C dot-to-dash"

# Preflight check
PRE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" "$URL")
echo "   preflight OPTIONS → HTTP $PRE" >> "$OUT"

# ── Auth mechanism detection（2026-05-13 加 — Pattern - CORS ACAC True with Bearer Auth）
# 判斷 ACAC:true 是否真的可 CSRF：cookie auth = 是；Bearer JWT = 否（降級）
# 為什麼分開判斷：
#   - 同個 endpoint 看 GET / login flow / typical API 都不同
#   - login POST 通常 Set-Cookie，後續 API 用 Authorization header
RESP_FULL=$(curl -skI --max-time 8 "$URL" 2>/dev/null)
SET_COOKIE=$(echo "$RESP_FULL" | grep -ci "^set-cookie:")
AUTH_HEADER_CHALLENGE=$(echo "$RESP_FULL" | grep -ci "^www-authenticate:.*bearer")
# 看 JSON body 是否提示 Bearer flow（401 多半是）
RESP_BODY=$(curl -sk --max-time 8 "$URL" 2>/dev/null | head -c 500)
JWT_HINT=$(echo "$RESP_BODY" | grep -cE 'token|bearer|jwt|access_token' || true)

echo "" >> "$OUT"
echo "── Auth Mechanism Detection ──" >> "$OUT"
echo "   Set-Cookie present: $([ "$SET_COOKIE" -gt 0 ] && echo "yes ($SET_COOKIE cookies)" || echo "no")" >> "$OUT"
echo "   WWW-Authenticate Bearer: $([ "$AUTH_HEADER_CHALLENGE" -gt 0 ] && echo "yes" || echo "no")" >> "$OUT"
echo "   JWT/token mention in body: $([ "$JWT_HINT" -gt 0 ] && echo "yes" || echo "no")" >> "$OUT"

# 若先前 probe 已 hit ACAC=true（OUT 內含 'ACAC=true'），看 auth 機制決定 severity 提示
if grep -q "ACAC=true" "$OUT"; then
  if [ "$SET_COOKIE" -gt 0 ]; then
    hit "Cookie-based auth + ACAC:true → P2/P3 instant CSRF candidate（送高 severity）"
  elif [ "$AUTH_HEADER_CHALLENGE" -gt 0 ] || [ "$JWT_HINT" -gt 0 ]; then
    echo "🟠 Bearer JWT auth + ACAC:true → P4/P5 misconfig only（attacker JS 無法跨域偷 localStorage）" | tee -a "$OUT"
    echo "    → 報送時要寫清楚「目前 Bearer auth 不可 CSRF」+「未來改回 cookie 立刻變漏洞」" | tee -a "$OUT"
    echo "    → 詳見：[[Pattern - CORS ACAC True with Bearer Auth]]" | tee -a "$OUT"
  else
    echo "🟡 ACAC:true 但 auth 機制不明 — 手動確認 (DevTools → Network → 看後續 API 怎麼帶 auth)" | tee -a "$OUT"
  fi
fi

log "=== done → $OUT ==="
