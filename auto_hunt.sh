#!/usr/bin/env bash
# ============================================================
# auto_hunt.sh — 全自動 Bug Bounty 偵察 + 漏洞掃描
# 用法：
#   ./tools/auto_hunt.sh underarmour.com
#   ./tools/auto_hunt.sh underarmour.com --scope "*.api.ua.com,shop.underarmour.com"
#   ./tools/auto_hunt.sh underarmour.com --mode quick     (只做 quick recon，跳過 nuclei)
#   ./tools/auto_hunt.sh underarmour.com --mode full      (完整，含 bbot)
#   ./tools/auto_hunt.sh underarmour.com --mode osmedeus  (用 Osmedeus VPS)
#
# Osmedeus VPS 設定（--mode osmedeus）：
#   export OSMEDEUS_VPS="user@167.71.198.160"
#   export OSMEDEUS_TOKEN="your-token"
# ============================================================
set -euo pipefail

# ── 工具路徑 ──────────────────────────────────────────────────
CURL="/usr/bin/curl"
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# ProjectDiscovery httpx (tools/ local binary takes priority over brew httpx)
HTTPX=""
if [ -x "$TOOLS_DIR/httpx" ]; then HTTPX="$TOOLS_DIR/httpx"
elif [ -x "$HOME/.pdtm/go/bin/httpx" ]; then HTTPX="$HOME/.pdtm/go/bin/httpx"
fi
SUBFINDER=""
if [ -x "$TOOLS_DIR/subfinder" ]; then SUBFINDER="$TOOLS_DIR/subfinder"
elif command -v subfinder &>/dev/null; then SUBFINDER="$(which subfinder)"
fi
NUCLEI=""
if [ -x "$TOOLS_DIR/nuclei" ]; then NUCLEI="$TOOLS_DIR/nuclei"
elif [ -x "$HOME/.pdtm/go/bin/nuclei" ]; then NUCLEI="$HOME/.pdtm/go/bin/nuclei"
elif command -v nuclei &>/dev/null; then NUCLEI="$(which nuclei)"
fi
BBOT="$(command -v bbot 2>/dev/null || echo "$HOME/.local/bin/bbot")"
AMASS="$(command -v amass 2>/dev/null || echo '')"
FEROX="$(command -v feroxbuster 2>/dev/null || echo '')"

# ── 參數解析 ─────────────────────────────────────────────────
TARGET="${1:-}"
MODE="quick"
SCOPE_OVERRIDE=""

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <domain> [--mode quick|full] [--scope 'domain1,domain2']"
  exit 1
fi

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --scope) SCOPE_OVERRIDE="$2"; shift 2;;
    *) shift;;
  esac
done

# ── 輸出目錄 ─────────────────────────────────────────────────
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$BASE_DIR/recon/$TARGET"
mkdir -p "$OUT"/{subs,live,vuln,js,git,api}

REPORT="$OUT/AUTO_HUNT_$(date +%Y%m%d_%H%M).md"
LOG="$OUT/hunt.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
section() { echo -e "\n## $*" | tee -a "$REPORT"; log "=== $* ==="; }
finding() { echo "- $*" | tee -a "$REPORT"; }

# ── 報告 Header ───────────────────────────────────────────────
cat > "$REPORT" <<EOF
# Auto Hunt Report: $TARGET
**Date:** $(date '+%Y-%m-%d %H:%M')
**Mode:** $MODE
**Output:** $OUT

EOF

log "Starting auto_hunt on $TARGET (mode=$MODE)"

# ============================================================
# PHASE 1: 子域名枚舉
# ============================================================
section "Phase 1: Subdomain Enumeration"

SUBS_FILE="$OUT/subs/all_subs.txt"
> "$SUBS_FILE"

# 1a. crt.sh (無需工具)
log "crt.sh enumeration..."
$CURL -s "https://crt.sh/?q=%.$TARGET&output=json" 2>/dev/null | \
  python3 -c "
import json,sys
try:
  data=json.load(sys.stdin)
  names=set()
  for e in data:
    for n in e.get('name_value','').split('\n'):
      n=n.strip().lstrip('*.')
      if n and '.' in n: names.add(n)
  for n in sorted(names): print(n)
except: pass
" >> "$SUBS_FILE" 2>/dev/null
CRT_COUNT=$(wc -l < "$SUBS_FILE" | tr -d ' ')
finding "crt.sh: $CRT_COUNT subdomains"

# 1b. subfinder
if [ -n "$SUBFINDER" ]; then
  log "subfinder enumeration..."
  $SUBFINDER -d "$TARGET" -silent 2>/dev/null >> "$SUBS_FILE" || true
fi

# 1c. Osmedeus VPS mode
if [ "$MODE" = "osmedeus" ]; then
  VPS="${OSMEDEUS_VPS:-}"
  if [ -z "$VPS" ]; then
    log "OSMEDEUS_VPS not set. Skipping Osmedeus. Set: export OSMEDEUS_VPS=user@host"
  else
    log "Triggering Osmedeus scan on VPS: $VPS..."
    OSED_OUT="$OUT/subs/osmedeus"
    mkdir -p "$OSED_OUT"
    # Run osmedeus on VPS, fetch results back
    ssh "$VPS" "osmedeus scan -f subdomain -t $TARGET --timeout 30" 2>/dev/null || true
    # Pull back subdomain results
    scp "$VPS:~/.osmedeus/workspaces/$TARGET/module/subdomain-enumeration/final-subdomain.txt" \
      "$OSED_OUT/subs.txt" 2>/dev/null || true
    # Pull back live hosts
    scp "$VPS:~/.osmedeus/workspaces/$TARGET/module/http-probing/http-probing.txt" \
      "$OSED_OUT/live.txt" 2>/dev/null || true

    if [ -f "$OSED_OUT/subs.txt" ]; then
      cat "$OSED_OUT/subs.txt" >> "$SUBS_FILE"
      OSED_COUNT=$(wc -l < "$OSED_OUT/subs.txt" | tr -d ' ')
      finding "Osmedeus (VPS): $OSED_COUNT subdomains"
      log "Osmedeus returned $OSED_COUNT subs"
    fi
  fi
fi

# 1d. bbot (full mode only) — subdomain enum + cloud bucket detection + secret detection + DNS takeover
# Modules from real bug bounty findings:
#   badsecrets  → detect known secrets in HTTP responses (public redirect_uri chain + Hybris pattern experience)
#   baddns      → subdomain takeover candidates (UA 1099+ subs experience)
#   bucket_*    → open cloud buckets (iRobot S3 experience)
if [ "$MODE" = "full" ] && [ -n "$BBOT" ] && [ -x "$BBOT" ]; then
  log "bbot enumeration + cloud/secret checks (this takes ~10 min)..."
  BBOT_OUT="$OUT/subs/bbot"
  mkdir -p "$BBOT_OUT"
  # Flags:
  #   subdomain-enum  → subdomain enumeration modules
  #   baddns          → baddns + baddns_direct + baddns_zone (takeover detection)
  #   cloud-enum      → bucket_amazon/google/firebase/microsoft/digitalocean
  # Module:
  #   badsecrets      → detect known secrets in HTTP responses (web-basic flag)
  # Output modules:
  #   txt             → output.txt (human readable)
  #   subdomains      → subdomains.txt (clean subdomain list)
  $BBOT -t "$TARGET" \
    -f subdomain-enum,baddns,cloud-enum \
    -m badsecrets \
    -om txt,subdomains \
    -o "$BBOT_OUT" --silent 2>/dev/null || true

  # Parse subdomains from bbot output
  # bbot v2: subdomains output module → subdomains.txt; fallback → grep from output.txt
  local bbot_subs="$BBOT_OUT/subdomains.txt"
  if [ -f "$bbot_subs" ]; then
    cat "$bbot_subs" >> "$SUBS_FILE"
  elif [ -f "$BBOT_OUT/output.txt" ]; then
    grep -oE "[a-zA-Z0-9._-]+\.$TARGET" "$BBOT_OUT/output.txt" 2>/dev/null >> "$SUBS_FILE" || true
  fi

  # Pull VULNERABILITY / FINDING events from output → critical alerts
  BBOT_FINDINGS_OUT="$OUT/vuln/bbot_findings.txt"
  grep -E "\[VULNERABILITY\]|\[FINDING\]" "$BBOT_OUT/output.txt" 2>/dev/null \
    > "$BBOT_FINDINGS_OUT" || true

  if [ -s "$BBOT_FINDINGS_OUT" ]; then
    # Bucket findings
    if grep -qiE "bucket|s3|gcs|azure|firebase" "$BBOT_FINDINGS_OUT" 2>/dev/null; then
      finding "🔴 bbot: open cloud buckets → $BBOT_FINDINGS_OUT"
      log "FINDING: bbot open buckets"
    fi
    # Takeover / bad secrets
    if grep -qiE "takeover|badsecret|dangling" "$BBOT_FINDINGS_OUT" 2>/dev/null; then
      finding "🔴 bbot: secrets/takeover candidates → $BBOT_FINDINGS_OUT"
      log "FINDING: bbot secrets/takeover"
    fi
    # Count all findings
    local bbot_find_count
    bbot_find_count=$(wc -l < "$BBOT_FINDINGS_OUT" | tr -d ' ')
    finding "🟡 bbot: $bbot_find_count total findings → $BBOT_FINDINGS_OUT"
  fi
fi

# 去重
sort -u "$SUBS_FILE" -o "$SUBS_FILE"
TOTAL_SUBS=$(wc -l < "$SUBS_FILE" | tr -d ' ')
finding "Total unique subdomains: **$TOTAL_SUBS**"
log "Subdomains: $TOTAL_SUBS"

# ============================================================
# PHASE 2: 存活探測
# ============================================================
section "Phase 2: Live Host Detection"

LIVE_FILE="$OUT/live/alive.txt"
LIVE_DETAIL="$OUT/live/alive_detail.txt"

if [ -n "$HTTPX" ] && [ "$TOTAL_SUBS" -gt 0 ]; then
  log "httpx probing $TOTAL_SUBS hosts..."
  touch "$LIVE_DETAIL" "$LIVE_FILE"
  cat "$SUBS_FILE" | $HTTPX \
    -title -status-code -tech-detect -content-length \
    -follow-redirects -timeout 10 -threads 50 \
    -silent -o "$LIVE_DETAIL" 2>/dev/null || true
  grep -oE 'https?://[^ ]+' "$LIVE_DETAIL" 2>/dev/null > "$LIVE_FILE" || true
  LIVE_COUNT=$(wc -l < "$LIVE_DETAIL" | tr -d ' ')
  finding "Live hosts: **$LIVE_COUNT**"

  # 列出有趣的技術 (Spring Boot, Tomcat, etc.)
  echo "" >> "$REPORT"
  echo "### Interesting Tech Detected" >> "$REPORT"
  grep -iE "spring|tomcat|actuator|django|flask|rails|graphql|swagger|kibana|jenkins|grafana|prometheus|zipkin" \
    "$LIVE_DETAIL" 2>/dev/null | while read -r line; do
    finding "$line"
  done || true
else
  # fallback: curl-based probe
  log "httpx not found, using curl fallback..."
  while IFS= read -r sub; do
    for scheme in https http; do
      code=$($CURL -so /dev/null -w "%{http_code}" --max-time 5 "$scheme://$sub/" 2>/dev/null)
      if [[ "$code" =~ ^[23] ]]; then
        echo "$scheme://$sub/ [$code]" | tee -a "$LIVE_DETAIL"
        echo "$scheme://$sub/" >> "$LIVE_FILE"
      fi
    done
  done < "$SUBS_FILE"
  LIVE_COUNT=$(wc -l < "$LIVE_DETAIL" 2>/dev/null | tr -d ' ')
  finding "Live hosts: **$LIVE_COUNT** (curl fallback)"
fi

# 套用 scope 篩選（如果有）
if [ -n "$SCOPE_OVERRIDE" ]; then
  SCOPE_LIVE="$OUT/live/alive_inscope.txt"
  > "$SCOPE_LIVE"
  IFS=',' read -ra SCOPES <<< "$SCOPE_OVERRIDE"
  for scope in "${SCOPES[@]}"; do
    scope_pattern="${scope/\*/.*}"
    grep -E "$scope_pattern" "$LIVE_FILE" >> "$SCOPE_LIVE" 2>/dev/null || true
  done
  sort -u "$SCOPE_LIVE" -o "$SCOPE_LIVE"
  SCOPE_COUNT=$(wc -l < "$SCOPE_LIVE" | tr -d ' ')
  finding "In-scope live hosts: **$SCOPE_COUNT**"
  LIVE_FILE="$SCOPE_LIVE"
fi

# ============================================================
# PHASE 3: 快速漏洞特徵檢查（並行處理，最多 15 hosts 同時）
# ============================================================
section "Phase 3: Quick Win Checks"

# SPA 偵測函式（隨機路徑返回 200 → 判定為 SPA，跳過 endpoint 探測）
_spa_check() {
  local host="$1"
  local rand_code
  rand_code=$($CURL -so /dev/null -w "%{http_code}" --max-time 5 \
    "$host/__spa_$(shuf -i 100000-999999 -n 1 2>/dev/null || echo $$)__" 2>/dev/null)
  [ "$rand_code" = "200" ] && echo "1" || echo "0"
}

# 單一 host 的完整 Phase 3 檢查
# 參數：$1=host(含scheme)  $2=輸出 tmpfile  $3=vuln dir
_check_one_host() {
  local host="$1"
  local tmpout="$2"
  local vulndir="$3"

  # ── .git 暴露 ──────────────────────────────────────────
  local git_resp
  git_resp=$($CURL -sk --max-time 5 "$host/.git/HEAD" 2>/dev/null | head -1)
  if echo "$git_resp" | grep -q "ref:"; then
    echo "- 🔴 .git EXPOSED: $host/.git/HEAD → $git_resp" >> "$tmpout"
  fi

  # ── .env 暴露（content verified，非 SPA 通用路徑）──────
  local env_resp env_code
  env_resp=$($CURL -sk --max-time 5 -w "\n__CODE__%{http_code}" "$host/.env" 2>/dev/null)
  env_code=$(echo "$env_resp" | grep -o '__CODE__[0-9]*' | grep -o '[0-9]*')
  env_resp=$(echo "$env_resp" | sed '/^__CODE__/d' | head -3)
  if [ "$env_code" = "200" ] && echo "$env_resp" | grep -qiE "DB_|APP_|SECRET|PASSWORD|KEY"; then
    echo "- 🔴 .env EXPOSED: $host/.env" >> "$tmpout"
  fi

  # ── SPA 偵測（影響後續 endpoint 探測）─────────────────
  local spa
  spa=$(_spa_check "$host")

  if [ "$spa" = "1" ]; then
    echo "  [SPA detected, skipping endpoint checks: $host]" >> "$tmpout"
  else

    # ── Spring Boot Actuator（JSON content 驗證）──────────
    for ep in /actuator /actuator/health /actuator/env /actuator/mappings /actuator/beans; do
      local resp code
      resp=$($CURL -sk --max-time 5 -w "\n__CODE__%{http_code}" \
        -H "Accept: application/json" "$host$ep" 2>/dev/null)
      code=$(echo "$resp" | grep -o '__CODE__[0-9]*' | grep -o '[0-9]*')
      resp=$(echo "$resp" | sed '/^__CODE__/d')
      if [[ "$code" =~ ^2 ]] && echo "$resp" | grep -qE '"status"|"_links"|"contexts"|"beans"|"propertySources"'; then
        local sev="🟡"
        if [[ "$ep" == "/actuator/env" ]] && echo "$resp" | grep -q "propertySources"; then
          sev="🔴"
          echo "$resp" > "$vulndir/actuator_env_$(echo "$host" | tr -cd 'a-z0-9').json"
        fi
        echo "- $sev Actuator: $host$ep [$code]" >> "$tmpout"
      fi
    done

    # ── Swagger / API Docs（content verified）─────────────
    for ep in /swagger-ui.html /swagger-ui/ /api-docs /api/docs /openapi.json \
              /swagger.json /v2/api-docs /v3/api-docs; do
      local resp code
      resp=$($CURL -sk --max-time 5 -w "\n__CODE__%{http_code}" "$host$ep" 2>/dev/null | head -c 600)
      code=$(echo "$resp" | grep -o '__CODE__[0-9]*' | grep -o '[0-9]*')
      resp=$(echo "$resp" | sed '/^__CODE__/d')
      if [[ "$code" =~ ^2 ]] && echo "$resp" | grep -qiE '"openapi"|"swagger"|SwaggerUIBundle|swagger-ui'; then
        echo "- 🟡 Swagger: $host$ep [$code]" >> "$tmpout"
      fi
    done

    # ── GraphQL introspection ──────────────────────────────
    for ep in /graphql /api/graphql /v1/graphql /query; do
      local resp
      resp=$($CURL -sk --max-time 8 -X POST "$host$ep" \
        -H "Content-Type: application/json" \
        -d '{"query":"{ __schema { types { name } } }"}' 2>/dev/null | head -c 300)
      if echo "$resp" | grep -qE '"__Schema"|"__schema"'; then
        echo "- 🔴 GraphQL introspection ON: $host$ep" >> "$tmpout"
      elif echo "$resp" | grep -qE '"errors":\[|"data":\{|"errors": \[|"data": \{'; then
        echo "- 🟡 GraphQL endpoint (introspection off): $host$ep" >> "$tmpout"
      fi
    done

    # ── SFCC / OCC API default creds（disclosed Hybris case）─────
    # Default creds: mobile_android:secret（Hybris/SAP Commerce Cloud）
    for ep in /occ/v2/basesites /api/v2/basesites /rest/v2/basesites \
              /WEBAPI/rest/v2/basesites; do
      local code
      code=$($CURL -so /dev/null -w "%{http_code}" --max-time 5 \
        -u "mobile_android:secret" \
        -H "Accept: application/json" "$host$ep" 2>/dev/null)
      if [[ "$code" =~ ^2 ]]; then
        echo "- 🔴 OCC default creds (mobile_android:secret): $host$ep [$code]" >> "$tmpout"
      fi
    done

    # ── Elasticsearch / Kibana unauthenticated ─────────────
    for ep in /_cat/indices /_cluster/health /app/kibana /.kibana; do
      local resp code
      resp=$($CURL -sk --max-time 5 -w "\n__CODE__%{http_code}" "$host$ep" 2>/dev/null | head -c 400)
      code=$(echo "$resp" | grep -o '__CODE__[0-9]*' | grep -o '[0-9]*')
      resp=$(echo "$resp" | sed '/^__CODE__/d')
      if [[ "$code" =~ ^2 ]] && echo "$resp" | grep -qiE '"index"|"health"|"green"|"yellow"|"red"|"kibana"'; then
        echo "- 🔴 Elasticsearch/Kibana open: $host$ep [$code]" >> "$tmpout"
      fi
    done

  fi  # end non-SPA checks

  # ── Source Maps（SPA 也可能有，不跳過）──────────────────
  local js_urls
  js_urls=$($CURL -sk --max-time 8 "$host/" 2>/dev/null | \
    grep -oE '/[a-zA-Z0-9._/~-]+\.[a-f0-9-]+\.js' | head -5)
  for js in $js_urls; do
    local map_body
    map_body=$($CURL -sk --max-time 5 "$host${js}.map" 2>/dev/null | head -c 100)
    if echo "$map_body" | grep -qE '"sources"|"mappings"|"version"'; then
      echo "- 🟡 Source map exposed: $host${js}.map" >> "$tmpout"
    fi
  done
}

# 匯出函式和變數供並行子 shell 使用
export -f _check_one_host _spa_check
export CURL OUT

PHASE3_TMPDIR=$(mktemp -d)
PHASE3_PIDS=()
LIVE_COUNT_P3=$(wc -l < "$LIVE_FILE" 2>/dev/null | tr -d ' ')
log "Phase 3: checking $LIVE_COUNT_P3 hosts in parallel (max 15 concurrent)..."

while IFS= read -r url; do
  host=$(echo "$url" | grep -oE 'https?://[^/]+')
  [ -z "$host" ] && continue
  tmpout="$PHASE3_TMPDIR/$(echo "$host" | tr -cd 'a-z0-9').txt"
  touch "$tmpout"

  _check_one_host "$host" "$tmpout" "$OUT/vuln" &
  PHASE3_PIDS+=($!)

  # Throttle: wait for oldest job when hitting limit
  if [ ${#PHASE3_PIDS[@]} -ge 15 ]; then
    wait "${PHASE3_PIDS[0]}" 2>/dev/null || true
    PHASE3_PIDS=("${PHASE3_PIDS[@]:1}")
  fi
done < "$LIVE_FILE"

# 等待剩餘 jobs
wait "${PHASE3_PIDS[@]}" 2>/dev/null || true

# 合併所有 host 輸出到報告
for tmpf in "$PHASE3_TMPDIR"/*.txt; do
  [ -s "$tmpf" ] && cat "$tmpf" >> "$REPORT"
done
rm -rf "$PHASE3_TMPDIR"
log "Phase 3 complete"

# ============================================================
# PHASE 4: Nuclei Scan
# ============================================================
if [ -n "$NUCLEI" ]; then
  section "Phase 4: Nuclei Scan"
  NUCLEI_OUT="$OUT/vuln/nuclei_results.txt"
  log "Running nuclei on live hosts..."

  if [ -s "$LIVE_FILE" ]; then
    $NUCLEI -l "$LIVE_FILE" \
      -severity critical,high,medium \
      -etags "dos,fuzz" \
      -timeout 10 \
      -c 25 \
      -silent \
      -o "$NUCLEI_OUT" 2>/dev/null || true

    NUCLEI_COUNT=$(wc -l < "$NUCLEI_OUT" 2>/dev/null | tr -d ' ')
    finding "Nuclei results: **$NUCLEI_COUNT** findings"

    # Extract critical/high
    if [ -s "$NUCLEI_OUT" ]; then
      echo "" >> "$REPORT"
      echo "### Nuclei Critical/High" >> "$REPORT"
      grep -iE "\[critical\]|\[high\]" "$NUCLEI_OUT" 2>/dev/null | while read -r line; do
        finding "$line"
      done || true
    fi
  fi
else
  log "nuclei not found, skipping Phase 4"
fi

# ============================================================
# PHASE 5: JS Bundle Secret Scan
# ============================================================
section "Phase 5: JS Bundle Secret Scan"

JS_SECRET_OUT="$OUT/js/secrets.txt"
> "$JS_SECRET_OUT"

# High-precision patterns: must be quoted string values, not variable names
# Matches: "apiKey":"xxxxx" / apiKey = "xxxxx" / "secret": "xxxxx"
SECRET_PATTERNS='("api[_-]?key"|"apiKey"|"client_secret"|"clientSecret"|"private_key"|"access_token"|"refresh_token"|"aws_secret"|"db_password"|"database_password"|"smtp_password")\s*[:=]\s*"[A-Za-z0-9+/=_\-]{16,}"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|ya29\.[0-9A-Za-z\-_]{60,}|"password"\s*:\s*"[^"]{8,}"'

while IFS= read -r url; do
  host=$(echo "$url" | grep -oE 'https?://[^/]+')
  page=$($CURL -sk --max-time 8 "$host/" 2>/dev/null)

  # Get all JS URLs from page
  js_list=$(echo "$page" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//' | head -10)

  for js_path in $js_list; do
    # Handle relative/absolute URLs
    if echo "$js_path" | grep -q "^http"; then
      js_url="$js_path"
    else
      js_url="$host$js_path"
    fi

    js_content=$($CURL -sk --max-time 10 "$js_url" 2>/dev/null | head -c 200000)
    secrets=$(echo "$js_content" | grep -oE "$SECRET_PATTERNS" 2>/dev/null | head -5)

    if [ -n "$secrets" ]; then
      echo "[$host] $js_path:" >> "$JS_SECRET_OUT"
      echo "$secrets" >> "$JS_SECRET_OUT"
      finding "🔴 Secrets in JS: $js_url"
    fi
  done
done < "$LIVE_FILE" 2>/dev/null || true

SECRET_COUNT=$(wc -l < "$JS_SECRET_OUT" 2>/dev/null | tr -d ' ')
finding "JS secret scan: $SECRET_COUNT potential findings in $JS_SECRET_OUT"

# ============================================================
# PHASE 6: API Endpoint Discovery
# ============================================================
section "Phase 6: API Endpoint Discovery"

API_OUT="$OUT/api/endpoints.txt"
> "$API_OUT"

while IFS= read -r url; do
  host=$(echo "$url" | grep -oE 'https?://[^/]+')
  SPA_HOST=0
  is_spa_fallback "$host" && SPA_HOST=1

  # Check robots.txt and sitemap for hints
  for file in /robots.txt /sitemap.xml; do
    content=$($CURL -sk --max-time 5 "$host$file" 2>/dev/null)
    if [ -n "$content" ]; then
      echo "[$host$file]" >> "$API_OUT"
      echo "$content" | grep -E "Disallow:|Allow:|<loc>" | head -20 >> "$API_OUT" || true
    fi
  done

  # Skip API path probe for SPA (returns 200 for everything)
  [ "$SPA_HOST" = "1" ] && continue

  # Common API prefixes — verify JSON response (not HTML)
  for ep in /api /api/v1 /api/v2 /api/v3 /v1 /v2 /rest /service /services; do
    response=$($CURL -sk --max-time 5 -H "Accept: application/json" "$host$ep" 2>/dev/null | head -c 200)
    code=$($CURL -so /dev/null -w "%{http_code}" --max-time 5 "$host$ep" 2>/dev/null)
    if [[ "$code" =~ ^[23] ]] && echo "$response" | grep -qE '^\{|^\[|"version"|"status"|"message"'; then
      echo "$host$ep [$code]" >> "$API_OUT"
      finding "🟢 API: $host$ep [$code]"
    fi
  done
done < "$LIVE_FILE" 2>/dev/null || true

# ============================================================
# SUMMARY
# ============================================================
section "Summary"

TOTAL_FINDINGS=$(grep -cE "^- (🔴|🟡|🟢)" "$REPORT" 2>/dev/null || echo 0)
finding "**Target:** $TARGET"
finding "**Subdomains found:** $TOTAL_SUBS"
finding "**Live hosts:** $(wc -l < "$LIVE_FILE" 2>/dev/null | tr -d ' ')"
finding "**Total findings:** $TOTAL_FINDINGS"
finding "**Report:** $REPORT"
finding "**Nuclei results:** $OUT/vuln/"
finding "**JS secrets:** $JS_SECRET_OUT"

echo ""
echo "========================================"
echo "  HUNT COMPLETE: $TARGET"
echo "  Report: $REPORT"
CRIT=$(grep -c '🔴' "$REPORT" 2>/dev/null || echo 0)
MED=$(grep -c '🟡' "$REPORT" 2>/dev/null || echo 0)
echo "  $CRIT critical | $MED medium"
echo "========================================"

log "Hunt complete. Report: $REPORT"
