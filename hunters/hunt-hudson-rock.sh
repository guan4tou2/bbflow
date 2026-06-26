#!/usr/bin/env bash
# hunt-hudson-rock.sh — HudsonRock Cavalier breach corpus 查詢（OSINT Arsenal §15.0.1）
#
# 查詢 infostealer log 資料庫，找出員工或用戶裝置是否曾被 infostealer 感染
# 並洩漏目標域名的登入憑證。免費 API，無需 auth。
#
# Severity mapping（§15.1）：
#   employees ≥ 10 → CRITICAL
#   employees 1-9  → HIGH
#   users ≥ 1      → MEDIUM
#   domain in corpus, 0 accounts → INFO
#
# 用法（domain 模式，bbflow 從 ROOT_DOMAIN 呼叫）：
#   ./hunt-hudson-rock.sh example.com

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <domain>"; exit 1; }
DOMAIN=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')

OUT_DIR="${OUT_DIR:-./hudson_rock_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟠 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }

# ── 衍生相關 domain 列表（自動推斷 org 名稱 + 主要 TLD）───────────────────────
BASE=$(echo "$DOMAIN" | rev | cut -d. -f2- | rev | cut -d. -f1)  # e.g. juiker.tw → juiker

DOMAINS=("$DOMAIN")
# 嘗試常見衍生域名（去重）
for tld in com tw net org io; do
  CANDIDATE="${BASE}.${tld}"
  [ "$CANDIDATE" != "$DOMAIN" ] && DOMAINS+=("$CANDIDATE")
done

log "=== HudsonRock Cavalier breach hunt: $DOMAIN (${#DOMAINS[@]} domain variants) ==="

TOTAL_EMPLOYEES=0
TOTAL_USERS=0

for D in "${DOMAINS[@]}"; do
  sleep 1  # rate limit: 1 req/sec

  RESP=$(curl -sk -m 30 \
    "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${D}" \
    2>/dev/null)

  [ -z "$RESP" ] && { log "  $D: no response (skipping)"; continue; }

  # jq 解析
  TOTAL=$(echo "$RESP"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))"    2>/dev/null || echo 0)
  EMP=$(echo "$RESP"      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('employees',0))" 2>/dev/null || echo 0)
  USERS=$(echo "$RESP"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('users',0))"     2>/dev/null || echo 0)
  THIRD=$(echo "$RESP"    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('third_parties',0))" 2>/dev/null || echo 0)

  [ "$TOTAL" = "0" ] && { log "  $D: 0 breach records"; continue; }

  TOTAL_EMPLOYEES=$((TOTAL_EMPLOYEES + EMP))
  TOTAL_USERS=$((TOTAL_USERS + USERS))

  # ── Severity mapping（§15.1）────────────────────────────────────────────
  if   [ "$EMP" -ge 10 ] 2>/dev/null; then SEV="CRITICAL"
  elif [ "$EMP" -ge 1  ] 2>/dev/null; then SEV="HIGH"
  elif [ "$USERS" -ge 1 ] 2>/dev/null; then SEV="MEDIUM"
  else SEV="INFO"; fi

  MSG="[$SEV] $D — total:$TOTAL employees:$EMP users:$USERS third_party:$THIRD"
  case "$SEV" in
    CRITICAL) hit "$MSG" ;;
    HIGH)     warn "$MSG" ;;
    MEDIUM)   info_hit "$MSG" ;;
    INFO)     log "  $D: $MSG" ;;
  esac

  # ── employees_urls（RECON GOLD — 洩漏的內部 app URL）─────────────────────
  EMP_URLS=$(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
urls = d.get('data',{}).get('employees_urls',[])
if urls:
  sorted_urls = sorted(urls, key=lambda x: x.get('occurrence',0), reverse=True)
  for u in sorted_urls[:10]:
    print(f\"  occurrence:{u.get('occurrence','?')} url:{u.get('url','?')}\")
" 2>/dev/null)

  if [ -n "$EMP_URLS" ]; then
    [ "$SEV" = "CRITICAL" ] || [ "$SEV" = "HIGH" ] && \
      hit "employees_urls (internal apps leaked — subdomain recon gold):" || \
      info_hit "employees_urls:"
    echo "$EMP_URLS" | tee -a "$OUT"
  fi

  # ── stealer families ───────────────────────────────────────────────────────
  FAMILIES=$(echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
fams = d.get('data',{}).get('stealer_families',[])
if fams:
  names = [f.get('_key','?') for f in fams[:5]]
  print('  stealers: ' + ', '.join(names))
" 2>/dev/null)
  [ -n "$FAMILIES" ] && info_hit "$FAMILIES"

  # ── SSO_EXPOSURE check（§15.2）──────────────────────────────────────────
  # 若 employees ≥ 1 且 MX → Google/M365 → 帳密幾乎能用於 SSO
  if [ "$EMP" -ge 1 ] 2>/dev/null; then
    MX=$(dig +short MX "$D" 2>/dev/null | head -1)
    SSO_HINT=""
    echo "$MX" | grep -qi "google"      && SSO_HINT="Google Workspace SSO"
    echo "$MX" | grep -qi "outlook\|protection" && SSO_HINT="Microsoft 365 SSO"
    echo "$MX" | grep -qi "zoho"        && SSO_HINT="Zoho Mail SSO"
    if [ -n "$SSO_HINT" ]; then
      hit "SSO_EXPOSURE: $D — $EMP employee credential(s) stolen → likely reusable against $SSO_HINT"
    fi
  fi
done

# ── 彙整評估 ──────────────────────────────────────────────────────────────────
echo "" >> "$OUT"
log "=== Summary: total_employees=$TOTAL_EMPLOYEES total_users=$TOTAL_USERS ==="

if   [ "$TOTAL_EMPLOYEES" -ge 10 ] 2>/dev/null; then
  hit "OVERALL CRITICAL — ≥10 employee credentials compromised across all domains"
elif [ "$TOTAL_EMPLOYEES" -ge 1 ] 2>/dev/null; then
  warn "OVERALL HIGH — employee credentials compromised; check SSO reuse"
elif [ "$TOTAL_USERS" -ge 1 ] 2>/dev/null; then
  info_hit "OVERALL MEDIUM — user credentials compromised; credential stuffing risk"
else
  log "OVERALL CLEAN — no breach records found"
fi
