#!/usr/bin/env bash
# hunt-vite-spa-json-config.sh — Vite/Vue/React SPA env config JSON leak
# 來源：TeamPlus TP-S15 (Nan Shan)
#       Pattern - Vite SPA JSON Config Leak（KB）
#
# Multi-tenant Vite SaaS app 常把環境設定 JSON 放在 /json/、/config/、/env/ 公開路徑：
#   - /json/version_pmo.json         — env dispatcher（map "uat" → "uat-xxx.com"）
#   - /json/production.json           — prod 環境設定
#   - /json/uat.json / /json/test.json— staging
#
# Yields:
#   - hostname / API URL map（包括未列出的 staging）
#   - tenant URL-slug naming pattern → tenant enumeration
#   - 偶爾：硬編碼 API key / JWT secret
#
# 流程：
#   1. 確認 Vite SPA signature（index.html 含 type="module" crossorigin）
#   2. 對常見 JSON config path 試 GET
#   3. 若 200 + JSON，解析 keys 找 hostname / key / endpoint pattern
#
# 用法：
#   ./hunt-vite-spa-json-config.sh https://app.example.com
#   for H in $(cat hosts.txt); do ./hunt-vite-spa-json-config.sh "$H"; done
set -uo pipefail

URL="${1:-}"
[ -z "$URL" ] && { echo "Usage: $0 <https://host> | for H in \$(cat hosts.txt); do $0 \"\$H\"; done"; exit 1; }
URL="${URL%/}"
OUT_DIR="${OUT_DIR:-./vite_config_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$URL" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "🔴 VULN $*" | tee -a "$OUT"; }
warn() { echo "🟠 $*" | tee -a "$OUT"; }
info() { echo "   $*" >> "$OUT"; }

log "=== Vite SPA Config Leak: $URL ==="

# Phase 1: Vite SPA signature 偵測
HTML=$(curl -sk --max-time 8 "$URL/" 2>/dev/null)
VITE_HINT=0
if echo "$HTML" | grep -qE 'type="module"\s+crossorigin\s+src="/assets/index-[a-f0-9]+\.js"'; then
  info "Vite SPA signature: matched (type=module crossorigin /assets/index-*.js)"
  VITE_HINT=1
elif echo "$HTML" | grep -qE '/assets/index-[a-f0-9]+\.js|<div id="app"></div>|<div id="root"></div>'; then
  info "Possible Vite/Vue/React SPA（partial signature）"
  VITE_HINT=1
else
  info "No Vite/Vue/React signature in index.html — pattern may still apply if SPA hosted on subpath"
fi

# Phase 2: JSON config paths probe
declare -a JSON_PATHS=(
  "/json/version_pmo.json"
  "/json/version.json"
  "/json/production.json"
  "/json/prod.json"
  "/json/uat.json"
  "/json/uat-company.json"
  "/json/staging.json"
  "/json/test.json"
  "/json/develop.json"
  "/json/dev.json"
  "/json/env.json"
  "/json/config.json"
  "/json/portal.json"
  "/config/env.json"
  "/config/config.json"
  "/config/production.json"
  "/env/env.json"
  "/env/production.json"
  "/assets/config.json"
  "/assets/env.json"
)

FOUND_CONFIGS=()
for P in "${JSON_PATHS[@]}"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$URL$P")
  if [ "$STATUS" = "200" ]; then
    # Confirm 是 JSON 不是 HTML 404 page
    CTYPE=$(curl -skI --max-time 6 "$URL$P" | grep -i "^content-type:" | head -1 | tr -d '\r\n')
    BODY=$(curl -sk --max-time 6 "$URL$P")
    # Heuristic: 開頭是 { 或 [，長度 > 20
    if echo "$BODY" | head -c 5 | grep -qE '^\s*[\{\[]' && [ "${#BODY}" -gt 20 ]; then
      hit "$P → 200 ($CTYPE, ${#BODY} bytes)"
      FOUND_CONFIGS+=("$P")
      # Save body for analysis
      echo "$BODY" > "$OUT_DIR/${SLUG}_$(echo "$P" | tr '/' '_').json"
      info "   body[0..200]: $(echo "$BODY" | head -c 200 | tr -d '\n')"
    fi
  fi
done

# Phase 3: Analyze JSON content
if [ ${#FOUND_CONFIGS[@]} -gt 0 ]; then
  log ""
  log "── Analyzing ${#FOUND_CONFIGS[@]} leaked JSON config(s) ──"

  python3 - "$OUT_DIR" "$SLUG" "$OUT" <<'PY'
import json, sys, re, os
out_dir = sys.argv[1]
slug = sys.argv[2]
out = sys.argv[3]

leaked_hosts = set()
secrets_found = []
env_keys = []
api_endpoints = set()

for fn in os.listdir(out_dir):
    if not (fn.startswith(slug+"_") and fn.endswith(".json")):
        continue
    fp = os.path.join(out_dir, fn)
    try:
        with open(fp) as f:
            data = f.read()
    except Exception:
        continue

    # Extract hostnames
    for m in re.findall(r'(?:https?://)?([a-z0-9][a-z0-9.-]{2,}\.[a-z]{2,})(?::\d+)?', data, re.I):
        if not any(skip in m.lower() for skip in ('example.com', 'localhost', 'github.io', 'w3.org')):
            leaked_hosts.add(m.lower())

    # Extract API endpoints
    for m in re.findall(r'["\'\s](/api/v?\d*/[a-z0-9/_-]+)["\'\s]', data):
        api_endpoints.add(m)

    # Detect secrets/keys
    for pat_name, pat in [
        ("aws_key", r'(AKIA|ASIA)[0-9A-Z]{16}'),
        ("google_api", r'AIza[0-9A-Za-z_-]{35}'),
        ("jwt", r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        ("private_key", r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
        ("stripe_live", r'sk_live_[0-9a-zA-Z]{24,}'),
        ("hardcoded_key", r'["\'](api[_-]?key|secret|password|token)["\']\s*:\s*["\'][^"\']{16,}["\']'),
    ]:
        for m in re.finditer(pat, data, re.I):
            secrets_found.append((pat_name, m.group(0)[:100]))

    # Extract env-like dispatcher keys (uat/prod/dev/staging mapping)
    try:
        parsed = json.loads(data)
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if isinstance(v, str) and ('.' in v) and any(env in k.lower() for env in ('uat', 'prod', 'dev', 'staging', 'test', 'pmo')):
                    env_keys.append(f"{k} → {v}")
    except Exception:
        pass

with open(out, 'a') as f:
    f.write("\n── JSON Content Analysis ──\n")
    if env_keys:
        f.write(f"\n🔴 Environment dispatcher map (high value — leaks staging/prod hostnames):\n")
        for e in env_keys[:30]:
            f.write(f"  {e}\n")
        print(f"🔴 {len(env_keys)} environment dispatcher key(s) leaked")
    if leaked_hosts:
        f.write(f"\n🟠 Hostnames discovered ({len(leaked_hosts)}):\n")
        for h in sorted(leaked_hosts)[:30]:
            f.write(f"  {h}\n")
        print(f"🟠 {len(leaked_hosts)} hostname(s) leaked from JSON")
    if api_endpoints:
        f.write(f"\n🟠 API endpoints referenced ({len(api_endpoints)}):\n")
        for e in sorted(api_endpoints)[:30]:
            f.write(f"  {e}\n")
    if secrets_found:
        f.write(f"\n🔴 Potential secrets ({len(secrets_found)}):\n")
        for name, val in secrets_found[:20]:
            f.write(f"  [{name}] {val}\n")
        print(f"🔴 {len(secrets_found)} potential secret(s) — verify each！")

PY

  log ""
  hit "Vite SPA JSON Config Leak CONFIRMED on $URL"
  info "  Leaked configs: ${FOUND_CONFIGS[*]}"
  info ""
  info "  下一步建議："
  info "  1. 用 leaked hostnames 做 tenant enumeration（[[Pattern - Vendor Product Multi-Host Enumeration]]）"
  info "  2. 若 leaked env dispatcher → 找 staging hosts 重跑同套 hunter（staging 常無 WAF）"
  info "  3. 若 leaked API endpoint → 對該 endpoint 跑 authenticated reconnaissance"
  info "  4. 若 leaked hardcoded key → 立即 verify（避免 false positive，多半是 vendor-shared）"
else
  log "🟢 No public JSON config found on $URL"
fi

log "=== done → $OUT ==="
