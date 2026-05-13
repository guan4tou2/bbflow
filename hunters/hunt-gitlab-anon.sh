#!/usr/bin/env bash
# hunt-gitlab-anon.sh — GitLab anonymous fingerprinting + open signup + info disclosures
# 來源：TeamPlus rd-gitlab / rd3-gitlab（2026-04-23）
#       Pattern - GitLab Anonymous Fingerprinting（KB）
#
# 對外部可達 GitLab instance（即使無 /users/sign_up）也有大量 anon-accessible
# 路徑會 leak version / config / R&D tech stack。
#
# 探測：
#   1. Primary: /-/graphql-explorer 抓 window.gon.revision（exact commit hash）
#   2. Fallbacks: /help, /api/v4/version, /-/metrics, .well-known/openid-configuration
#   3. /users/sign_up: 200 = open signup (P3) / 302 = disabled / 404 = removed
#   4. Anon info disclosures:
#        /help/instance_configuration  → SSH fingerprint, rate-limit, backup config
#        /-/jwks                       → confirms JWT federation
#        /explore/projects              → R&D 語言（Vue/Java/Shell 等）即使 project 私有
#        /explore/groups, /explore/snippets
#        /api/v4/projects?visibility=internal → 應該 0；非 0 = config bug
#        /api/v4/users                  → 200 anon = user enum
#        /api/graphql (POST {query: introspection})
#
# 用法：
#   ./hunt-gitlab-anon.sh https://gitlab.example.com
set -uo pipefail

URL="${1:-}"
[ -z "$URL" ] && { echo "Usage: $0 <https://gitlab-instance>"; exit 1; }
URL="${URL%/}"
OUT_DIR="${OUT_DIR:-./gitlab_anon_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$URL" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "🔴 VULN $*" | tee -a "$OUT"; }
warn() { echo "🟠 $*" | tee -a "$OUT"; }
info() { echo "   $*" >> "$OUT"; }

log "=== GitLab Anonymous Probe: $URL ==="

# Pre-check: 確認是 GitLab
HOME_HTML=$(curl -sk --max-time 8 "$URL/" 2>/dev/null)
GITLAB_HINT=0
if echo "$HOME_HTML" | grep -qiE 'gitlab|gon\s*=\s*\{|/-/graphql|sign-in/' ; then
  info "GitLab signature: matched"
  GITLAB_HINT=1
else
  warn "Page does not look like GitLab — may still be one with custom branding"
fi

# ── 1. Primary: /-/graphql-explorer 抓 revision ──
log ""
log "── Version pinning ──"
GQL_EXPLORER=$(curl -sk --max-time 8 "$URL/-/graphql-explorer" 2>/dev/null)
GON_REVISION=$(echo "$GQL_EXPLORER" | grep -oE 'revision["\047]\s*:\s*["\047][a-f0-9]{6,}["\047]' | head -1 | grep -oE '[a-f0-9]{6,}' | head -1)
GITLAB_VER=$(echo "$GQL_EXPLORER" | grep -oE 'gitlab_version["\047]\s*:\s*["\047][^"\047]*["\047]' | head -1)

if [ -n "$GON_REVISION" ]; then
  hit "/-/graphql-explorer leaks gon.revision: $GON_REVISION"
  info "    Cross-ref: https://gitlab.com/gitlab-org/gitlab/-/commit/$GON_REVISION"
  [ -n "$GITLAB_VER" ] && info "    gitlab_version: $GITLAB_VER"
else
  info "/-/graphql-explorer: no gon.revision found"
fi

# Fallback 1: /api/v4/version
API_VER=$(curl -sk --max-time 6 "$URL/api/v4/version" 2>/dev/null)
if echo "$API_VER" | grep -qE '"version"|"revision"'; then
  hit "/api/v4/version anon-accessible: $(echo "$API_VER" | head -c 200)"
fi

# Fallback 2: /help (header version)
HELP_HTML=$(curl -sk --max-time 6 "$URL/help" 2>/dev/null)
HELP_VER=$(echo "$HELP_HTML" | grep -oE 'GitLab (Community|Enterprise) Edition\s+[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
[ -n "$HELP_VER" ] && hit "/help leaks: $HELP_VER"

# Fallback 3: .well-known/openid-configuration (scopes hint at major version)
OIDC=$(curl -sk --max-time 6 "$URL/.well-known/openid-configuration" 2>/dev/null)
if echo "$OIDC" | grep -qE 'scopes_supported|issuer'; then
  warn "/.well-known/openid-configuration anon-accessible"
  # 17.x 有獨特 scopes
  if echo "$OIDC" | grep -qE 'manage_runner|self_rotate|read_virtual_registry|ai_workflows|user:'; then
    info "    scopes hint version >= 17.x"
  else
    info "    scopes hint version < 17.x"
  fi
fi

# ── 2. Open Self-Registration（單一最高 impact）──
log ""
log "── Open Signup Check ──"
SIGNUP_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 "$URL/users/sign_up")
case "$SIGNUP_STATUS" in
  200) hit "/users/sign_up = HTTP 200 — OPEN SIGNUP（P3 Medium，可註冊 developer-class 帳號）" ;;
  302) info "/users/sign_up = 302 → /users/sign_in（registration disabled，good）" ;;
  404) info "/users/sign_up = 404（registration route removed，best）" ;;
  *)   warn "/users/sign_up = $SIGNUP_STATUS（unexpected）" ;;
esac

# ── 3. Anon Info Disclosures ──
log ""
log "── Anon Info Disclosures ──"

# /help/instance_configuration
CFG_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$URL/help/instance_configuration")
if [ "$CFG_STATUS" = "200" ]; then
  hit "/help/instance_configuration anon-accessible（leaks SSH fingerprints + rate limits + backup config）"
fi

# /-/jwks
JWKS_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$URL/-/jwks")
if [ "$JWKS_STATUS" = "200" ]; then
  info "/-/jwks anon-accessible — JWT federation enabled (CI job tokens / Omniauth)"
fi

# /explore/projects（語言過濾洩漏 R&D tech stack）
EXPLORE=$(curl -sk --max-time 6 "$URL/explore/projects" 2>/dev/null)
if echo "$EXPLORE" | grep -qE 'data-language|language-name'; then
  LANGS=$(echo "$EXPLORE" | grep -oE 'data-language="[A-Z][A-Za-z0-9]+"' | sort -u | head -10 | sed 's/data-language="//;s/"//' | paste -sd ',' -)
  [ -n "$LANGS" ] && warn "/explore/projects leaks R&D tech stack: $LANGS"
fi

# /explore/groups, /explore/snippets
for P in "/explore/groups" "/explore/snippets"; do
  ST=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$URL$P")
  if [ "$ST" = "200" ]; then
    info "$P → 200 anon-accessible（檢查是否 leak group / public snippet）"
  fi
done

# /api/v4/projects?visibility=internal — anon 應該 0；非 0 = bug
INTERNAL_RESP=$(curl -sk --max-time 6 "$URL/api/v4/projects?visibility=internal&per_page=1" 2>/dev/null)
# JSON array length check
if echo "$INTERNAL_RESP" | head -c 5 | grep -qE '^\s*\['; then
  COUNT=$(echo "$INTERNAL_RESP" | grep -oE '"id":[0-9]+' | wc -l | tr -d ' ')
  if [ "$COUNT" -gt 0 ]; then
    hit "/api/v4/projects?visibility=internal anon returns $COUNT result(s) — major config bug"
  else
    info "/api/v4/projects?visibility=internal anon returns 0（correct）"
  fi
fi

# /api/v4/users — anon should be 403
USERS_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$URL/api/v4/users")
if [ "$USERS_STATUS" = "200" ]; then
  hit "/api/v4/users anon-accessible — user enumeration trivial"
elif [ "$USERS_STATUS" = "403" ]; then
  info "/api/v4/users = 403（correct）"
else
  info "/api/v4/users = $USERS_STATUS"
fi

# /api/graphql introspection
GQL_INTRO=$(curl -sk --max-time 8 -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}}}"}' \
  "$URL/api/graphql" 2>/dev/null)
if echo "$GQL_INTRO" | grep -q '"queryType"'; then
  hit "/api/graphql anon introspection enabled — schema 全公開"
fi

log ""
log "═══ Summary ═══"
log "  Output: $OUT"

# Final severity hint
ANY_HIT=$(grep -c "🔴 VULN" "$OUT" 2>/dev/null || echo 0)
[ "$ANY_HIT" -gt 0 ] && log "  Hits: $ANY_HIT — review full output for next steps"

log "=== done → $OUT ==="
