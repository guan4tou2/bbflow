#!/usr/bin/env bash
# hunt-google-api-key.sh — Google API key 自動驗證（對多個服務）
# 來源：multi-service Google API key pattern（2 組 unrestricted Google Vision/Maps key → P2 財務影響）
#      disclosed AWS Location key pattern
#
# 輸入：AIza* API key（從 envdata/sourcemap/hardcoded-js hunters 找到的）
# 輸出：
#   - unrestricted 的服務清單
#   - 每個服務的示範呼叫
#   - 潛在財務影響等級
#
# 用法：
#   ./hunt-google-api-key.sh AIzaSy...
#   EXISTING_EMAIL=me@example.com ./hunt-google-api-key.sh AIzaSy...   # Identity Toolkit 也測
#
# 測試的服務：
#   Maps Static API、Geocoding、Places、Directions、Roads、Elevation、
#   Vision (OCR + Label + Face)、Translate、Firebase RTDB (REST)、
#   Custom Search、YouTube Data v3、Timezone、Safe Browsing、
#   Firebase Cloud Messaging、Identity Toolkit (auth)
set -uo pipefail

KEY="${1:-}"
[ -z "$KEY" ] && { echo "Usage: $0 <AIzaSy...>"; exit 1; }
[[ ! "$KEY" =~ ^AIza ]] && { echo "not an AIza* key"; exit 1; }

OUT_DIR="${OUT_DIR:-./gkey_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$KEY" | head -c 20)
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

log "=== Google API key validation: ${KEY:0:12}... ==="

test_api() {
  local label="$1" url="$2" method="${3:-GET}" data="${4:-}"
  local resp code
  if [ "$method" = "GET" ]; then
    resp=$(curl -sk --max-time 8 -o /tmp/.gk_$$ -w "%{http_code}" "$url")
  else
    resp=$(curl -sk --max-time 8 -X POST \
      -H "Content-Type: application/json" -d "$data" \
      -o /tmp/.gk_$$ -w "%{http_code}" "$url")
  fi
  code="$resp"
  local body
  body=$(head -c 500 /tmp/.gk_$$ 2>/dev/null)
  rm -f /tmp/.gk_$$
  # Detect denied patterns (Google APIs often return 200 with REQUEST_DENIED body)
  if echo "$body" | grep -qiE '"status"\s*:\s*"REQUEST_DENIED"|API key not valid|API[ _]?key[ _]?expired|"error_message"\s*:\s*"[^"]*key[^"]*invalid|"code"\s*:\s*(400|401|403)|PERMISSION_DENIED|"reason"\s*:\s*"(keyInvalid|ipRefererBlocked|forbidden)"'; then
    if echo "$body" | grep -qiE "API[ _]?key[ _]?not[ _]?valid|API key expired|keyInvalid"; then
      warn "$label: key invalid/expired"
    else
      echo "   $label: denied ($code)" >> "$OUT"
    fi
    return
  fi
  if [[ "$code" =~ ^2 ]]; then
    hit "$label: UNRESTRICTED [$code]"
    # Store first bytes of body as evidence
    echo "     evidence: $(echo "$body" | head -c 200 | tr -d '\n')" >> "$OUT"
  else
    echo "   $label: HTTP $code" >> "$OUT"
  fi
}

# ── Maps Static API (disclosed tenant case) ─────────────────────
test_api "Maps Static" \
  "https://maps.googleapis.com/maps/api/staticmap?center=25.0330,121.5654&zoom=14&size=400x400&key=${KEY}"

# ── Geocoding API ──────────────────────────────────────────────
test_api "Geocoding" \
  "https://maps.googleapis.com/maps/api/geocode/json?address=Taipei&key=${KEY}"

# ── Places API (New / Legacy) ──────────────────────────────────
test_api "Places Nearby" \
  "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=25.03,121.56&radius=1000&key=${KEY}"
test_api "Places Autocomplete" \
  "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=taipei&key=${KEY}"

# ── Directions / Distance Matrix ───────────────────────────────
test_api "Directions" \
  "https://maps.googleapis.com/maps/api/directions/json?origin=Taipei&destination=Taichung&key=${KEY}"
test_api "Distance Matrix" \
  "https://maps.googleapis.com/maps/api/distancematrix/json?origins=Taipei&destinations=Taichung&key=${KEY}"

# ── Roads / Elevation / Timezone ───────────────────────────────
test_api "Roads Nearest" \
  "https://roads.googleapis.com/v1/nearestRoads?points=25.033,121.564&key=${KEY}"
test_api "Elevation" \
  "https://maps.googleapis.com/maps/api/elevation/json?locations=25.033,121.564&key=${KEY}"
test_api "Timezone" \
  "https://maps.googleapis.com/maps/api/timezone/json?location=25.033,121.564&timestamp=0&key=${KEY}"

# ── Vision API (example tenant case) ────────────────────────────
test_api "Vision (label+face+safe)" \
  "https://vision.googleapis.com/v1/images:annotate?key=${KEY}" POST \
  '{"requests":[{"image":{"source":{"imageUri":"https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"}},"features":[{"type":"LABEL_DETECTION"},{"type":"FACE_DETECTION"},{"type":"SAFE_SEARCH_DETECTION"}]}]}'

# ── Translate API ──────────────────────────────────────────────
test_api "Translate" \
  "https://translation.googleapis.com/language/translate/v2?q=hello&target=zh&key=${KEY}"

# ── Custom Search / YouTube ────────────────────────────────────
test_api "YouTube Data" \
  "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key=${KEY}"
test_api "Custom Search" \
  "https://www.googleapis.com/customsearch/v1?q=test&cx=test&key=${KEY}"

# ── Safe Browsing ──────────────────────────────────────────────
test_api "Safe Browsing" \
  "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${KEY}" POST \
  '{"client":{"clientId":"test","clientVersion":"1.0"},"threatInfo":{"threatTypes":["MALWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":"http://example.com"}]}}'

# ── Firebase RTDB (public) ─────────────────────────────────────
# 只能測 .json 檔，需 project ID — skip unless env provided
if [ -n "${FIREBASE_PROJECT:-}" ]; then
  test_api "Firebase RTDB" \
    "https://${FIREBASE_PROJECT}.firebaseio.com/.json?auth=${KEY}"
fi

# ── Identity Toolkit (auth abuse) ──────────────────────────────
test_api "Identity Toolkit getProjectConfig" \
  "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=${KEY}"
test_api "Identity Toolkit signupNewUser" \
  "https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key=${KEY}" POST \
  "{\"email\":\"test-$(date +%s)@example.com\",\"password\":\"Test123456\",\"returnSecureToken\":true}"

# ── Firebase Cloud Messaging ───────────────────────────────────
test_api "FCM send" \
  "https://fcm.googleapis.com/fcm/send" POST \
  "{\"to\":\"fake-token\",\"data\":{\"test\":1}}"

# Summary
UNREST=$(grep -c "^🔴" "$OUT" 2>/dev/null | head -1 | tr -d ' \n')
[ -z "$UNREST" ] && UNREST=0
if [ "$UNREST" -gt 0 ]; then
  echo "" >> "$OUT"
  hit "SUMMARY: $UNREST services unrestricted → potential financial abuse"
  echo "" >> "$OUT"
  echo "Severity hint:" >> "$OUT"
  echo "  Maps Static/JS unrestricted → P4 (mapped quota abuse)" >> "$OUT"
  echo "  Vision/Translate/Places unrestricted → P3 (per-call cost)" >> "$OUT"
  echo "  Identity Toolkit signupNewUser unrestricted → P2 (creates real users)" >> "$OUT"
  echo "  FCM send unrestricted → P2 (spoofed push notifications)" >> "$OUT"
fi

log "=== done → $OUT ==="
