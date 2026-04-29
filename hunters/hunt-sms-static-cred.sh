#!/usr/bin/env bash
# hunt-sms-static-cred.sh — SMS Gateway 靜態憑證探測
# 來源：EVERY8D TP-S45 pattern
#   in-api.e8d.tw/sms：act=e8d&pwd=<MD5>&mobile=...&content=...
#   靜態 MD5 密碼洩漏於 .git config / MongoDB log / source code
#   無 IP 白名單 → 外網任意呼叫
#
# 此 hunter 只做探測，不實際發送 SMS（mobile 用無效號碼 / content 用 probe marker）
# 命中條件：resp_status=成功 / 回應非 3xx / HTTP 200 且 body 含成功指標
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT_DIR="${OUT_DIR:-./sms_static_cred_out}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

UA="Mozilla/5.0 (compatible; bbflow/sms-static-cred)"
# Probe-only mobile — not a real subscriber (000 prefix = invalid in TW)
PROBE_MOBILE="0000000000"
PROBE_CONTENT="bbflow-probe-$(date +%s | tail -c 6)"

# SMS gateway endpoint candidates
SMS_PATHS=(
  "/sms"
  "/api/sms"
  "/sms/send"
  "/send-sms"
  "/sendsms"
  "/sms/sendSMS"
  "/api/send"
  "/SMS"
  "/msg/send"
)

# act= parameter values (gateway identifiers)
ACT_VALUES=(
  "e8d"
  "sms"
  "send"
  "api"
  "default"
)

# MD5 patterns — test with known-bad MD5 to see if endpoint exists
# A valid MD5 response = endpoint exists (even if auth fails with wrong MD5)
PROBE_MD5="00000000000000000000000000000000"

log "=== sms-static-cred hunt: $HOST ==="

FOUND_ENDPOINT=0
for PATH_EP in "${SMS_PATHS[@]}"; do
  URL="${HOST}${PATH_EP}"
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$URL" 2>/dev/null)
  [[ "$CODE" == "000" ]] && continue
  log "  candidate: $URL [HTTP $CODE]"
  FOUND_ENDPOINT=1

  for ACT in "${ACT_VALUES[@]}"; do
    # POST probe with invalid MD5 — should get auth error, not 404
    BODY=$(curl -sk --max-time 10 \
      -X POST "$URL" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "User-Agent: $UA" \
      -d "act=${ACT}&pwd=${PROBE_MD5}&mobile=${PROBE_MOBILE}&content=${PROBE_CONTENT}" 2>/dev/null)
    RCODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
      -X POST "$URL" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "User-Agent: $UA" \
      -d "act=${ACT}&pwd=${PROBE_MD5}&mobile=${PROBE_MOBILE}&content=${PROBE_CONTENT}" 2>/dev/null)

    # If endpoint returns structured response (not 404/3xx) it may be an SMS gateway
    if [[ "$RCODE" == "200" ]] && [ -n "$BODY" ]; then
      # Check for SMS gateway response markers
      if echo "$BODY" | grep -qi "resp_status\|resp_code\|status.*成功\|status.*error\|invalid.*pwd\|wrong.*password\|auth\|mobile"; then
        warn "[P2] SMS gateway endpoint found: $URL act=${ACT} [HTTP $RCODE]"
        warn "  Response: $(echo "$BODY" | head -c 200)"
        warn "  Action: check source code / .git for static pwd; if found → test with real MD5"

        # Extra check: does it differentiate wrong-MD5 vs wrong-act?
        # Wrong-act should give different response than wrong-pwd
        BODY_WRONG_ACT=$(curl -sk --max-time 10 \
          -X POST "$URL" \
          -H "Content-Type: application/x-www-form-urlencoded" \
          -H "User-Agent: $UA" \
          -d "act=__invalid_act_xyz__&pwd=${PROBE_MD5}&mobile=${PROBE_MOBILE}&content=${PROBE_CONTENT}" 2>/dev/null)

        if [ "$BODY" != "$BODY_WRONG_ACT" ]; then
          hit "[P2+] SMS gateway differentiates act values — static cred pattern likely: $URL"
          log "  valid-act response:   $(echo "$BODY" | head -c 150)"
          log "  invalid-act response: $(echo "$BODY_WRONG_ACT" | head -c 150)"
        fi
      fi
    fi
  done
done

[ "$FOUND_ENDPOINT" = "0" ] && log "  no SMS gateway endpoints found"
log "=== done → $OUT ==="
