#!/usr/bin/env bash
# hunt-cors-reflect.sh — Reflective CORS + null origin + regex prefix bypass
# 來源：reflective CORS pattern（research/target/*）
#      app-hub (differential response pattern).example.com
#
# 測試四層：
#   A. 任意 Origin 反射（worst case）
#   B. null origin 反射
#   C. Regex prefix bypass（原 allowed = example.com → 測 attackui.com / notui.com）
#   D. Credentials: true 確認（決定是否可 browser exploit）
#
# 用法：
#   ./hunt-cors-reflect.sh https://cloudaccess.svc.example.com/devices
#   cat bbot/live_hosts.txt | while read h; do ./hunt-cors-reflect.sh "$h/"; done
set -uo pipefail

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

log "=== done → $OUT ==="
