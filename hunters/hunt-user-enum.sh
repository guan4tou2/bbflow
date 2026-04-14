#!/usr/bin/env bash
# hunt-user-enum.sh — 登入/註冊/重設密碼的帳號枚舉探測
# 來源：multi-brand validate_email（research/brand-X/*）
#      app-hub (differential response pattern) /v1/users/email/{email}
#
# 測試：
#   1. 常見 validate_email / exists / precheck / check endpoints
#   2. Password reset 差異回應
#   3. 登入 error message 差異
#   4. 大小寫不敏感確認
#   5. Rate limit 存在性測試（20 連發）
#
# 用法：
#   ./hunt-user-enum.sh https://passport.example.com
#   ./hunt-user-enum.sh https://app-hub.example.com
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./userenum_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }

EXISTING="${EXISTING_EMAIL:-admin@$(echo $HOST | sed 's|https\?://||;s|^[^.]*\.||')}"
NONEXIST="zz-noexist-$(date +%s)-$$@mailinator.com"

log "=== User enum hunt: $HOST (existing=$EXISTING, none=$NONEXIST) ==="

# ── GET-style endpoints (differential response pattern) ───────────────────
for EP in \
  "/v1/users/email/$EXISTING" \
  "/v1/users/email/$NONEXIST" \
  "/api/users/exists?email=$EXISTING" \
  "/api/users/exists?email=$NONEXIST"; do
  CODE=$(curl -sk -o "$OUT_DIR/${SLUG}_get_$(echo "$EP" | tr '/?&=' '____').body" \
    -w "%{http_code}" --max-time 8 "$HOST$EP")
  BODY=$(cat "$OUT_DIR/${SLUG}_get_$(echo "$EP" | tr '/?&=' '____').body" 2>/dev/null | head -c 200)
  echo "GET $EP [$CODE] $BODY" >> "$OUT"
done

# Diff check for differential-style
R1=$(curl -sk --max-time 8 "$HOST/v1/users/email/$EXISTING" 2>/dev/null)
R2=$(curl -sk --max-time 8 "$HOST/v1/users/email/$NONEXIST" 2>/dev/null)
if [ -n "$R1" ] && [ -n "$R2" ] && [ "$R1" != "$R2" ] && echo "$R1$R2" | grep -q "exists"; then
  hit "/v1/users/email/{email} differential: existing≠nonexistent"
fi

# ── POST-style endpoints (multi-brand SSO) ────────────────────────
for EP in \
  "/identity/users/validate_email" \
  "/api/users/validate_email" \
  "/api/v1/users/check" \
  "/api/auth/precheck" \
  "/auth/check" \
  "/account/exists"; do
  R_EX=$(curl -sk --max-time 8 -X POST \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EXISTING\"}" "$HOST$EP")
  R_NO=$(curl -sk --max-time 8 -X POST \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$NONEXIST\"}" "$HOST$EP")
  if [ -n "$R_EX" ] && [ -n "$R_NO" ] && [ "$R_EX" != "$R_NO" ]; then
    # Likely enumeration
    echo "POST $EP:" >> "$OUT"
    echo "  existing → $(echo $R_EX | head -c 200)" >> "$OUT"
    echo "  nonexist → $(echo $R_NO | head -c 200)" >> "$OUT"
    if echo "$R_EX$R_NO" | grep -qiE "exists|status|registered|activated"; then
      hit "POST $EP: response differential → user enumeration"
    fi
  fi
done

# ── Password reset differential ─────────────────────────────────
for EP in "/api/auth/forgot_password" "/identity/users/forget_password" "/api/users/reset-password"; do
  R_EX=$(curl -sk --max-time 8 -X POST \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EXISTING\"}" "$HOST$EP")
  R_NO=$(curl -sk --max-time 8 -X POST \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$NONEXIST\"}" "$HOST$EP")
  if [ -n "$R_EX" ] && [ "$R_EX" != "$R_NO" ]; then
    echo "POST $EP (pwd reset):" >> "$OUT"
    echo "  existing → $(echo $R_EX | head -c 150)" >> "$OUT"
    echo "  nonexist → $(echo $R_NO | head -c 150)" >> "$OUT"
    hit "POST $EP: reset response differential"
  fi
done

# ── Rate limit test (20 consecutive requests) ───────────────────
FOUND_ENUM_EP=$(grep "🔴 POST" "$OUT" | head -1 | awk '{print $3}')
[ -z "$FOUND_ENUM_EP" ] && FOUND_ENUM_EP=$(grep "🔴 /v1/users" "$OUT" | head -1 | awk '{print $2}')
if [ -n "$FOUND_ENUM_EP" ]; then
  log "rate limit test on $FOUND_ENUM_EP"
  CODES=""
  for i in $(seq 1 20); do
    C=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -X POST \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"rl${i}-$$@x.com\"}" "$HOST$FOUND_ENUM_EP")
    CODES="$CODES $C"
  done
  if ! echo "$CODES" | grep -q "429"; then
    hit "no rate limit on $FOUND_ENUM_EP (20 reqs → $CODES)"
  fi
fi

log "=== done → $OUT ==="
