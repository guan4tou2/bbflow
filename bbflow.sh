#!/usr/bin/env bash
# bbflow.sh — 統一 Bug Bounty Flow CLI
# 零 LLM 依賴。所有 subcommand 都是 bash + curl + python3 stdlib。
#
# 子命令：
#   bbflow doctor                          檢查依賴與工具路徑
#   bbflow init <target>                   建立 research/<target>/ + SCOPE.md 模板
#   bbflow recon <target> [--osmedeus]     執行 BBOT（預設）或 Osmedeus VPS recon
#   bbflow hunt <target> [--only h1,h2]    對 live_hosts.txt 跑全部 hunters
#   bbflow flow <target>                   recon + hunt + report 一條龍
#   bbflow status [<target>]               列出所有/單一 target 的進度
#   bbflow list                            列出所有 research 中的 target
#   bbflow report <target>                 重新產生 HUNTERS_REPORT.md
#   bbflow scope <target>                  顯示 SCOPE.md
#
# 設計原則：
#   1. BBOT / Osmedeus 負責 recon（asset discovery）
#   2. Hunters 負責 pattern-specific 驗證（confirmed-bounty patterns）
#   3. 狀態存在 research/<target>/，不重複執行已完成的階段
#   4. 所有輸出符合 CLAUDE.md 的 scope-first 規範（先建 SCOPE.md 才 hunt）
set -uo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$TOOLS_DIR/.." && pwd)"

# ── Dependencies ───────────────────────────────────────────────
BBOT="$(command -v bbot 2>/dev/null || echo $HOME/.local/bin/bbot)"
HTTPX="$TOOLS_DIR/httpx"; [ ! -x "$HTTPX" ] && HTTPX="$(command -v httpx 2>/dev/null || echo '')"
SUBFINDER="$TOOLS_DIR/subfinder"; [ ! -x "$SUBFINDER" ] && SUBFINDER="$(command -v subfinder 2>/dev/null || echo '')"
NUCLEI="$TOOLS_DIR/nuclei"; [ ! -x "$NUCLEI" ] && NUCLEI="$(command -v nuclei 2>/dev/null || echo '')"
NUCLEI_TEMPLATES="$TOOLS_DIR/nuclei-templates/bb-recon"
NUCLEI_COMMUNITY="${NUCLEI_COMMUNITY:-$HOME/nuclei-templates}"
NUCLEI_WORDFENCE="$TOOLS_DIR/nuclei-templates/nuclei-wordfence-cve"
export NUCLEI_COMMUNITY
KATANA="$(command -v katana 2>/dev/null || echo '')"
GAU="$(command -v gau 2>/dev/null || echo '')"
WAYBACK="$(command -v waybackurls 2>/dev/null || echo '')"
URO="$(command -v uro 2>/dev/null || echo '')"
GF="$(command -v gf 2>/dev/null || echo '')"
DALFOX="$(command -v dalfox 2>/dev/null || echo '')"
FFUF="$(command -v ffuf 2>/dev/null || echo '')"
ARJUN="$(command -v arjun 2>/dev/null || echo '')"
TRUFFLEHOG="$(command -v trufflehog 2>/dev/null || echo '')"

# ── SecLists: auto-detect across common install locations ──────
# export so hunters inherit without re-detecting
if [ -z "${SECLISTS:-}" ]; then
  for _sl in \
    "$HOME/Tools/SecLists" \
    "$(brew --prefix seclists 2>/dev/null)/share/seclists" \
    "/opt/homebrew/share/seclists" \
    "/usr/local/share/seclists" \
    "/usr/share/seclists"; do
    [ -d "$_sl/Discovery/Web-Content" ] && SECLISTS="$_sl" && break
  done
  SECLISTS="${SECLISTS:-}"
fi
export SECLISTS

# ── Colors ─────────────────────────────────────────────────────
R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[34m'; M=$'\e[35m'; C=$'\e[36m'; N=$'\e[0m'
ok(){ echo "${G}✓${N} $*"; }
err(){ echo "${R}✗${N} $*"; }
info(){ echo "${C}→${N} $*"; }
warn(){ echo "${Y}!${N} $*"; }

usage() {
  cat <<EOF
${B}bbflow${N} — Unified Bug Bounty Flow CLI (零 LLM)

${B}Usage:${N}
  bbflow doctor                    檢查依賴
  bbflow test                      對 example.com 跑 null-case regression test
  bbflow init <target>             初始化 research/<target>/ + SCOPE.md
  bbflow recon <target> [--osmedeus]
  bbflow hunt <target> [--only h1,...]
  bbflow flow <target>             recon + hunt + report 一條龍
  bbflow dedupe <target>           對比已送報告找重複
  bbflow status [<target>]
  bbflow list
  bbflow report <target>
  bbflow scope <target>
  bbflow nuclei-update             更新官方 PD templates + clone Wordfence CVE repo

${B}Examples:${N}
  bbflow doctor
  bbflow init target.example.com
  bbflow flow target.example.com
  bbflow hunt target.example.com --only cors,graphql
  OSMEDEUS_VPS=user@1.2.3.4 bbflow recon target.example.com --osmedeus

${B}Directory layout:${N}
  research/<target>/
    SCOPE.md                       ← scope 定義（必須先手寫完整）
    bbot/subdomains.txt            ← BBOT 輸出
    bbot/live_hosts.txt            ← httpx 存活結果
    hunters/<name>/<slug>.txt      ← 每個 hunter 的原始輸出
    nxdomain/nxdomain_corpus.txt   ← NXDOMAIN payload 候選
    HUNTERS_REPORT_YYYYMMDD_HHMM.md ← 彙總報告

${B}21 Hunters (對應 confirmed bounty 案例 + 高 ROI pattern):${N}
  hybris-occ       SAP Hybris OCC default creds + cart IDOR    [SAP Hybris OCC pattern]
  envdata          window.envData + AWS/Google/Sentry keys     [SPA inline window config pattern]
  sourcemap        .js.map → sourcesContent 密鑰 grep          [SPA inline config / multi-brand]
  js-secrets       live .js bundle grep (clientSecret/...)    [SPA hardcoded client secret pattern]
  cors             四層反射 + credentials:true 判斷            [public GraphQL IDOR writeup]
  graphql          無認證 + introspection + integer IDOR       [public GraphQL IDOR writeup]
  userenum         validate_email differential + rate limit   [multi-brand SSO/differential response pattern]
  git-exposure     .git probe + config/log credential grep    [nested .git CMS pattern]
  devops-unauth    Harbor/ArgoCD/Jenkins/Grafana/Prometheus/... [public DevOps console leak pattern]
  actuator-deep    /env /heapdump /httptrace /jolokia         [Spring Boot Actuator deep probe]
  mcp-oauth        MCP OAuth scope consent vs token 差異       [MCP OAuth scope pattern]
  gkey             Google API key 對多服務 validation          [multi-service Google API key pattern]
  takeover         subdomain CNAME → vendor fingerprint        [CNAME fingerprint pattern]
  open-redirect    redirect param + bypass 變體 + OAuth chain  [OAuth redirect_uri chain (public pattern)]
  jwt              decode + alg:none + weak HS256 + exp 檢查   [generic]
  nxdomain         歷史 hostname 超集 → Host-header payload    [Starbucks writeup]
  nuclei           bb-recon templates 26 個（直接可利用漏洞）    [需 nuclei binary]
                  → firebase/k8s/elastic/terraform/docker/backup/
                    php-debug/sqli/crlf/ssrf/wordpress/hashicorp
  nuclei-secrets   官方 PD tokens(123) + configs(206)          [需 ~/nuclei-templates/]
                  → AWS/GCP/GitHub/Slack/Stripe + .env/config
  nuclei-panels    官方 PD exposed-panels (DevOps/DB/Vault 面板) [需 ~/nuclei-templates/]
                  → Redis/RabbitMQ/Vault/Consul/Kibana/phpMyAdmin
  nuclei-wp        Wordfence WordPress CVE templates（1000+）   [需 bbflow nuclei-update]
                  → WP plugin/theme CVE 直接 PoC
  nuclei-ai        projectdiscovery/nuclei-templates-ai CVE     [需 bbflow nuclei-update]
  param-fuzz       URL/param discovery + nuclei DAST fuzzing    [需 katana+gau+uro+gf]
                  → katana + gau + gf 分類 → nuclei DAST
                    XSS/SQLi/SSRF/LFI/SSTI/CRLF/Open-redirect
  dalfox-xss       XSS deep scan (dalfox + gf xss filter)       [需 dalfox+katana+gf]
  arjun-params     隱藏 parameter discovery (GET/POST/JSON)      [需 arjun]
  trufflehog       git history deep secret scan (100+ detectors)[需 trufflehog]
  ffuf-dirs        Directory/file fuzzing (bug-bounty path list) [需 ffuf]
EOF
}

# ── cmd: doctor ────────────────────────────────────────────────
cmd_doctor() {
  echo "${B}== bbflow doctor ==${N}"
  for TOOL in curl python3 bash dig sort sed awk grep; do
    if command -v "$TOOL" >/dev/null 2>&1; then ok "$TOOL"; else err "$TOOL (required)"; fi
  done
  [ -x "$BBOT" ] && ok "bbot → $BBOT" || warn "bbot not found (recon will degrade to curl/crt.sh)"
  [ -n "$HTTPX" ] && ok "httpx → $HTTPX" || warn "httpx not found (live probe will use curl)"
  [ -n "$SUBFINDER" ] && ok "subfinder → $SUBFINDER" || warn "subfinder not found (will only use crt.sh+bbot)"
  command -v git-dumper >/dev/null 2>&1 && ok "git-dumper" || warn "git-dumper not found (--dump will skip)"
  command -v waymore >/dev/null 2>&1 && ok "waymore" || warn "waymore not found (nxdomain corpus will be smaller)"
  [ -n "$NUCLEI" ] && ok "nuclei → $NUCLEI" || warn "nuclei not found (nuclei/nuclei-secrets hunters will skip)"
  [ -d "$NUCLEI_TEMPLATES" ] && ok "nuclei-templates (bb-recon) → $NUCLEI_TEMPLATES ($(ls "$NUCLEI_TEMPLATES"/*.yaml 2>/dev/null | wc -l | tr -d ' ') templates)" || warn "nuclei-templates not found at $NUCLEI_TEMPLATES"
  if [ -d "$NUCLEI_COMMUNITY/http/exposures/tokens" ]; then
    local NTOK NCFG
    NTOK=$(ls "$NUCLEI_COMMUNITY/http/exposures/tokens"/*/*.yaml 2>/dev/null | wc -l | tr -d ' ')
    NCFG=$(ls "$NUCLEI_COMMUNITY/http/exposures/configs"/*.yaml 2>/dev/null | wc -l | tr -d ' ')
    ok "nuclei-community → $NUCLEI_COMMUNITY (tokens:$NTOK configs:$NCFG)"
  else
    warn "nuclei-community not found at $NUCLEI_COMMUNITY (nuclei-secrets will skip; install: nuclei -update-templates)"
  fi
  [ -f "$TOOLS_DIR/bbot_preset_bugbounty.yml" ] && ok "bbot preset" || warn "bbot preset missing"
  echo ""
  echo "${B}Param Fuzzing & XSS Tools:${N}"
  [ -n "$KATANA" ] && ok "katana → $KATANA" || warn "katana not found (brew install katana)"
  [ -n "$GAU" ] && ok "gau → $GAU" || warn "gau not found (go install github.com/lc/gau/v2/cmd/gau@latest)"
  [ -n "$WAYBACK" ] && ok "waybackurls → $WAYBACK" || warn "waybackurls not found (fallback: CDX API)"
  [ -n "$URO" ] && ok "uro → $URO" || warn "uro not found (pip3 install uro --break-system-packages)"
  [ -n "$GF" ] && ok "gf → $GF ($(ls "$HOME/.gf"/*.json 2>/dev/null | wc -l | tr -d ' ') patterns)" || warn "gf not found (go install github.com/tomnomnom/gf@latest)"
  [ -n "$DALFOX" ] && ok "dalfox → $DALFOX" || warn "dalfox not found (brew install dalfox)"
  [ -n "$FFUF" ] && ok "ffuf → $FFUF" || warn "ffuf not found (brew install ffuf)"
  [ -n "$ARJUN" ] && ok "arjun → $ARJUN" || warn "arjun not found (pip3 install arjun --break-system-packages)"
  [ -n "$TRUFFLEHOG" ] && ok "trufflehog → $TRUFFLEHOG" || warn "trufflehog not found (brew install trufflehog)"
  if [ -d "$NUCLEI_COMMUNITY/dast/vulnerabilities" ]; then
    local NDAST
    NDAST=$(find "$NUCLEI_COMMUNITY/dast/vulnerabilities" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
    ok "nuclei DAST templates → $NDAST templates"
  else
    warn "nuclei DAST templates not found (run: nuclei -update-templates)"
  fi
  if [ -n "$SECLISTS" ]; then
    local WL_COUNT
    WL_COUNT=$(find "$SECLISTS/Discovery/Web-Content" -name "*.txt" 2>/dev/null | wc -l | tr -d ' ')
    ok "SecLists → $SECLISTS ($WL_COUNT wordlists)"
  else
    warn "SecLists not found — ffuf/arjun will use built-in lists only"
    warn "  install (custom): git clone --depth=1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists.git ~/Tools/SecLists && cd ~/Tools/SecLists && git sparse-checkout set Discovery/Web-Content Fuzzing/XSS"
    warn "  install (brew):   brew install seclists"
  fi
  if [ -f "$TOOLS_DIR/payloads/xss-custom.txt" ]; then
    ok "xss-custom.txt → $TOOLS_DIR/payloads/xss-custom.txt"
  else
    warn "xss-custom.txt missing at $TOOLS_DIR/payloads/xss-custom.txt — dalfox will use SecLists fallback"
  fi
  echo ""
  echo "${B}Hunters:${N}"
  for H in "$TOOLS_DIR/hunters"/hunt-*.sh; do
    [ -x "$H" ] && ok "$(basename "$H")" || err "$(basename "$H") (not executable)"
  done
  echo ""
  echo "${B}Optional env:${N}"
  [ -n "${OSMEDEUS_VPS:-}" ] && ok "OSMEDEUS_VPS=$OSMEDEUS_VPS" || warn "OSMEDEUS_VPS not set (--osmedeus will fail)"
  [ -n "${EXISTING_EMAIL:-}" ] && ok "EXISTING_EMAIL=$EXISTING_EMAIL" || warn "EXISTING_EMAIL not set (user-enum will guess admin@domain)"
  echo ""
  echo "${B}Auth / advanced env (export before bbflow hunt):${N}"
  [ -n "${DALFOX_BLIND_URL:-}" ]  && ok "DALFOX_BLIND_URL=$DALFOX_BLIND_URL"    || warn "DALFOX_BLIND_URL  — blind XSS callback (e.g. https://xxx.oast.fun)"
  [ -n "${DALFOX_COOKIE:-}" ]     && ok "DALFOX_COOKIE set"                     || warn "DALFOX_COOKIE     — authenticated XSS scan (e.g. session=abc123)"
  [ -n "${DALFOX_HEADERS:-}" ]    && ok "DALFOX_HEADERS set"                    || warn "DALFOX_HEADERS    — extra headers for dalfox (e.g. Authorization: Bearer xxx)"
  [ -n "${FFUF_COOKIE:-}" ]       && ok "FFUF_COOKIE set"                       || warn "FFUF_COOKIE       — authenticated dir fuzzing"
  [ -n "${FFUF_HEADER:-}" ]       && ok "FFUF_HEADER set"                       || warn "FFUF_HEADER       — extra header for ffuf (e.g. Authorization: Bearer xxx)"
  [ -n "${ARJUN_HEADERS:-}" ]     && ok "ARJUN_HEADERS set"                     || warn "ARJUN_HEADERS     — authenticated param discovery"
  [ -n "${ARJUN_COOKIES:-}" ]     && ok "ARJUN_COOKIES set"                     || warn "ARJUN_COOKIES     — cookie for arjun"
}

# ── cmd: list ─────────────────────────────────────────────────
cmd_list() {
  if [ ! -d "$BASE_DIR/research" ]; then echo "(no research dir)"; return; fi
  echo "${B}Targets in research/:${N}"
  for T in "$BASE_DIR/research"/*/; do
    [ -d "$T" ] || continue
    NAME=$(basename "$T")
    SCOPE="$T/SCOPE.md"; BBOT_SUBS="$T/bbot/subdomains.txt"; LIVE="$T/bbot/live_hosts.txt"
    REPORTS=$(ls "$T"/HUNTERS_REPORT_*.md 2>/dev/null | wc -l | tr -d ' ')
    echo -n "  $NAME  "
    [ -f "$SCOPE" ] && echo -n "${G}scope${N} " || echo -n "${R}no-scope${N} "
    [ -f "$BBOT_SUBS" ] && echo -n "${G}recon${N}($(wc -l < $BBOT_SUBS | tr -d ' '))" || echo -n "${Y}no-recon${N}"
    [ -f "$LIVE" ] && echo -n " ${G}live${N}($(wc -l < $LIVE | tr -d ' '))"
    echo " ${C}reports=$REPORTS${N}"
  done
}

# ── cmd: init ─────────────────────────────────────────────────
cmd_init() {
  local T="$1"
  [ -z "$T" ] && { err "usage: bbflow init <target>"; exit 1; }
  local DIR="$BASE_DIR/research/$T"
  mkdir -p "$DIR"
  local SCOPE="$DIR/SCOPE.md"
  if [ -f "$SCOPE" ]; then
    warn "SCOPE.md exists → $SCOPE"
  else
    cat > "$SCOPE" <<EOF
# ${T} Scope

## Platform
- Platform: <HackerOne / Bugcrowd / Intigriti / Immunefi / HITCON ZeroDay / TWCERT>
- URL: https://hackerone.com/...
- Bounty: \$XXX - \$YYYY

## In-Scope
- *.${T}
- api.${T}
<-- 從 program 頁面複製完整清單，包含 wildcards -->

## Out-of-Scope (OOS)
- Rate limiting / brute force
- Email enumeration (standalone)
- Source map exposure (standalone)
- Self-XSS
- XMLRPC enabled
<-- 從 program 頁面複製完整 OOS 清單 -->

## Submission Rules
- Max reports per week: <N>
- Minimum severity: <P5 / P4>
- Language: <EN / ZH>

## Known Tech Stack (from recon)
<-- 填入 bbflow recon 之後的發現 -->

## Previous Findings / Duplicates Risk
<-- 送件前 grep disclosed hacktivity -->
EOF
    ok "initialized $SCOPE — 請先填完整 scope 再跑 recon"
  fi
}

# ── cmd: scope ────────────────────────────────────────────────
cmd_scope() {
  local T="$1"
  local SCOPE="$BASE_DIR/research/$T/SCOPE.md"
  [ -f "$SCOPE" ] || { err "no scope for $T (run: bbflow init $T)"; exit 1; }
  cat "$SCOPE"
}

# ── cmd: recon ────────────────────────────────────────────────
cmd_recon() {
  local T="$1"; shift
  local OSMEDEUS=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --osmedeus) OSMEDEUS=1; shift;;
      *) shift;;
    esac
  done

  local DIR="$BASE_DIR/research/$T"
  [ ! -d "$DIR" ] && { err "no dir for $T (run: bbflow init $T)"; exit 1; }
  [ ! -f "$DIR/SCOPE.md" ] && { err "no SCOPE.md — refusing to recon without scope"; exit 1; }

  mkdir -p "$DIR/bbot"
  local LIVE="$DIR/bbot/live_hosts.txt"
  local SUBS="$DIR/bbot/subdomains.txt"

  if [ "$OSMEDEUS" = "1" ]; then
    local VPS="${OSMEDEUS_VPS:-}"
    [ -z "$VPS" ] && { err "OSMEDEUS_VPS not set"; exit 1; }
    info "Osmedeus scan on $VPS..."
    ssh "$VPS" "osmedeus scan -f general -t $T" 2>&1 | tail -5
    scp -q "$VPS:~/.osmedeus/workspaces/$T/module/subdomain-enumeration/final-subdomain.txt" "$SUBS" 2>/dev/null || true
    scp -q "$VPS:~/.osmedeus/workspaces/$T/module/http-probing/http-probing.txt" "$LIVE.raw" 2>/dev/null || true
    [ -f "$LIVE.raw" ] && grep -oE 'https?://[^ ]+' "$LIVE.raw" | sort -u > "$LIVE"
  elif [ -x "$BBOT" ]; then
    info "BBOT passive recon (~10 min)..."
    local PRESET="$TOOLS_DIR/bbot_preset_bugbounty.yml"
    # Non-interactive: redirect stdin from /dev/null, force --yes, --no-deps
    "$BBOT" -t "$T" \
      ${PRESET:+-p "$PRESET"} \
      -f subdomain-enum,cloud-enum \
      -m httpx,badsecrets \
      -om subdomains,txt \
      -y --no-deps \
      -o "$DIR/bbot" --silent </dev/null 2>&1 | tail -10 || true

    find "$DIR/bbot" -name "subdomains.txt" -type f 2>/dev/null | head -1 | \
      xargs -I{} cp {} "$SUBS" 2>/dev/null || true
    find "$DIR/bbot" -name "output.txt" -type f 2>/dev/null | head -1 | \
      xargs -I{} grep -ohE 'https?://[a-zA-Z0-9.-]+\.'"$T"'[^ ]*' {} 2>/dev/null | \
      awk -F/ '{print $1"//"$3}' | sort -u > "$LIVE"
  else
    warn "no bbot — using crt.sh fallback"
    curl -s --max-time 30 "https://crt.sh/?q=%25.${T}&output=json" | \
      python3 -c "
import json, sys
try:
    d=json.load(sys.stdin); s=set()
    for e in d:
        for n in e.get('name_value','').split('\n'):
            n=n.strip().lstrip('*.')
            if n.endswith('.${T}') or n=='${T}': s.add(n.lower())
    for n in sorted(s): print(n)
except: pass" > "$SUBS"
  fi

  # Live probe fallback
  if [ ! -s "$LIVE" ] && [ -s "$SUBS" ]; then
    info "live probe via httpx..."
    if [ -n "$HTTPX" ]; then
      cat "$SUBS" | "$HTTPX" -silent -threads 50 -timeout 8 -o "$LIVE" 2>/dev/null || true
    else
      while read -r S; do
        C=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$S/" 2>/dev/null)
        [[ "$C" =~ ^[234] ]] && echo "https://$S" >> "$LIVE"
      done < "$SUBS"
    fi
  fi

  sort -u "$LIVE" -o "$LIVE" 2>/dev/null || true
  ok "recon: $(wc -l < $SUBS 2>/dev/null || echo 0) subs, $(wc -l < $LIVE 2>/dev/null || echo 0) live"
}

# ── cmd: hunt ────────────────────────────────────────────────
cmd_hunt() {
  local T="$1"; shift
  local ONLY=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --only) ONLY="$2"; shift 2;;
      *) shift;;
    esac
  done

  local DIR="$BASE_DIR/research/$T"
  local LIVE="$DIR/bbot/live_hosts.txt"
  [ ! -s "$LIVE" ] && { err "no live hosts (run: bbflow recon $T)"; exit 1; }
  mkdir -p "$DIR/hunters"

  local REPORT="$DIR/HUNTERS_REPORT_$(date +%Y%m%d_%H%M).md"
  local LIVE_N=$(wc -l < "$LIVE" | tr -d ' ')

  cat > "$REPORT" <<EOF
# Hunters Report — $T
Date: $(date '+%Y-%m-%d %H:%M')
Live hosts: $LIVE_N
Scope: $DIR/SCOPE.md

EOF

  want(){ [ -z "$ONLY" ] && return 0; echo ",$ONLY," | grep -q ",$1,"; }

  run_hunter() {
    local name="$1" script="$2" arg_mode="$3"
    want "$name" || return 0
    info "hunter: $name"
    local OH="$DIR/hunters/$name"
    mkdir -p "$OH"
    export OUT_DIR="$OH"
    echo "" >> "$REPORT"
    echo "## $name" >> "$REPORT"
    local N=0
    while read -r H; do
      [ -z "$H" ] && continue
      N=$((N+1))
      if [ "$arg_mode" = "url" ]; then
        "$script" "$H/" 2>/dev/null || true
      else
        "$script" "$H" 2>/dev/null || true
      fi
    done < "$LIVE"
    local HITS
    HITS=$(grep -h "^🔴" "$OH"/*.txt 2>/dev/null | sort -u || true)
    if [ -n "$HITS" ]; then
      echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done
      echo "${G}  hits:$(echo "$HITS" | wc -l | tr -d ' ')${N}"
    else
      echo "- (no hits across $N hosts)" >> "$REPORT"
    fi
  }

  run_hunter envdata       "$TOOLS_DIR/hunters/hunt-envdata.sh"              host
  run_hunter sourcemap     "$TOOLS_DIR/hunters/hunt-sourcemap-secrets.sh"    host
  run_hunter js-secrets    "$TOOLS_DIR/hunters/hunt-hardcoded-js-secrets.sh" host
  run_hunter cors          "$TOOLS_DIR/hunters/hunt-cors-reflect.sh"         url
  run_hunter graphql       "$TOOLS_DIR/hunters/hunt-graphql-idor.sh"         host
  run_hunter userenum      "$TOOLS_DIR/hunters/hunt-user-enum.sh"            host
  run_hunter hybris-occ    "$TOOLS_DIR/hunters/hunt-hybris-occ.sh"           host
  run_hunter git-exposure  "$TOOLS_DIR/hunters/hunt-git-exposure.sh"         host
  run_hunter devops-unauth "$TOOLS_DIR/hunters/hunt-devops-unauth.sh"        host
  run_hunter actuator-deep "$TOOLS_DIR/hunters/hunt-actuator-deep.sh"        host
  run_hunter mcp-oauth     "$TOOLS_DIR/hunters/hunt-mcp-oauth-scope.sh"      host
  run_hunter open-redirect "$TOOLS_DIR/hunters/hunt-open-redirect.sh"        host
  # subdomain-takeover: feed individual hostnames (dig CNAME), skip live_hosts loop
  if want takeover; then
    info "hunter: takeover (per-subdomain)"
    local OH="$DIR/hunters/takeover"
    mkdir -p "$OH"
    export OUT_DIR="$OH"
    echo "" >> "$REPORT"; echo "## takeover" >> "$REPORT"
    if [ -f "$DIR/bbot/subdomains.txt" ]; then
      "$TOOLS_DIR/hunters/hunt-subdomain-takeover.sh" -f "$DIR/bbot/subdomains.txt" 2>/dev/null || true
    else
      while read -r H; do
        [ -z "$H" ] && continue
        SUB=$(echo "$H" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
        "$TOOLS_DIR/hunters/hunt-subdomain-takeover.sh" "$SUB" 2>/dev/null || true
      done < "$LIVE"
    fi
    local HITS
    HITS=$(grep -h "^🔴" "$OH"/*.txt 2>/dev/null | sort -u || true)
    [ -n "$HITS" ] && echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done || echo "- (no takeover candidates)" >> "$REPORT"
  fi

  if want nxdomain; then
    info "hunter: nxdomain corpus"
    "$TOOLS_DIR/hunters/hunt-nxdomain-corpus.sh" "$T" 2>/dev/null || true
    local NX="$DIR/nxdomain/nxdomain_corpus.txt"
    [ -s "$NX" ] && echo "" >> "$REPORT" && \
      echo "## nxdomain corpus" >> "$REPORT" && \
      echo "- $(wc -l < $NX | tr -d ' ') NXDOMAIN candidates → $NX" >> "$REPORT"
  fi

  # ── nuclei bb-recon templates ─────────────────────────────
  if want nuclei; then
    if [ -z "$NUCLEI" ]; then
      warn "nuclei not found, skipping (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)"
    elif [ ! -d "$NUCLEI_TEMPLATES" ]; then
      warn "nuclei-templates not found at $NUCLEI_TEMPLATES, skipping"
    else
      info "hunter: nuclei (bb-recon templates, severity: medium,high,critical)"
      local NUCLEI_OH="$DIR/hunters/nuclei"
      mkdir -p "$NUCLEI_OH"
      local NUCLEI_OUT="$NUCLEI_OH/nuclei_results.txt"
      > "$NUCLEI_OUT"
      $NUCLEI -l "$LIVE" \
        -t "$NUCLEI_TEMPLATES" \
        -severity medium,high,critical \
        -etags "dos,fuzz" \
        -rate-limit 5 \
        -timeout 10 \
        -silent \
        -o "$NUCLEI_OUT" 2>/dev/null || true
      echo "" >> "$REPORT"
      echo "## nuclei" >> "$REPORT"
      if [ -s "$NUCLEI_OUT" ]; then
        local NUCLEI_COUNT
        NUCLEI_COUNT=$(wc -l < "$NUCLEI_OUT" | tr -d ' ')
        echo "- $NUCLEI_COUNT findings → $NUCLEI_OUT" >> "$REPORT"
        # Convert nuclei output to 🔴 prefixed lines for report
        while IFS= read -r line; do
          # nuclei output: [template-id] [type] [severity] URL
          local sev
          sev=$(echo "$line" | grep -oE '\[(critical|high|medium)\]' | head -1 | tr -d '[]')
          local tmpl
          tmpl=$(echo "$line" | grep -oE '^\[[^]]+\]' | head -1 | tr -d '[]')
          local url
          url=$(echo "$line" | awk '{print $NF}')
          echo "- 🔴 NUCLEI [$sev] $tmpl → $url" >> "$REPORT"
        done < "$NUCLEI_OUT"
        ok "  nuclei hits: $NUCLEI_COUNT"
      else
        echo "- (no nuclei findings)" >> "$REPORT"
      fi
    fi
  fi

  # ── nuclei-secrets: 官方 token + config exposure templates ────
  if want nuclei-secrets; then
    if [ -z "$NUCLEI" ]; then
      warn "nuclei not found, skipping nuclei-secrets"
    elif [ ! -d "$NUCLEI_COMMUNITY/http/exposures/tokens" ]; then
      warn "nuclei-community not found at $NUCLEI_COMMUNITY (run: nuclei -update-templates)"
    else
      info "hunter: nuclei-secrets (projectdiscovery tokens + configs, severity: info,medium,high,critical)"
      local NS_OH="$DIR/hunters/nuclei-secrets"
      mkdir -p "$NS_OH"
      local NS_OUT="$NS_OH/nuclei_secrets_results.txt"
      > "$NS_OUT"
      # tokens/: AWS/GCP/GitHub/Slack/Stripe/etc. API key regex in HTTP responses
      # configs/: .env, circleci, ansible, docker config file exposure
      $NUCLEI -l "$LIVE" \
        -t "$NUCLEI_COMMUNITY/http/exposures/tokens" \
        -t "$NUCLEI_COMMUNITY/http/exposures/configs" \
        -rate-limit 5 \
        -timeout 10 \
        -silent \
        -o "$NS_OUT" 2>/dev/null || true
      echo "" >> "$REPORT"
      echo "## nuclei-secrets" >> "$REPORT"
      if [ -s "$NS_OUT" ]; then
        local NS_COUNT
        NS_COUNT=$(wc -l < "$NS_OUT" | tr -d ' ')
        echo "- $NS_COUNT findings → $NS_OUT" >> "$REPORT"
        while IFS= read -r line; do
          local sev tmpl url
          sev=$(echo "$line" | grep -oE '\[(critical|high|medium|info)\]' | head -1 | tr -d '[]')
          tmpl=$(echo "$line" | grep -oE '^\[[^]]+\]' | head -1 | tr -d '[]')
          url=$(echo "$line" | awk '{print $NF}')
          echo "- 🔴 SECRET [$sev] $tmpl → $url" >> "$REPORT"
        done < "$NS_OUT"
        ok "  nuclei-secrets hits: $NS_COUNT"
      else
        echo "- (no secret findings)" >> "$REPORT"
      fi
    fi
  fi

  # ── nuclei-panels: 官方 exposed-panels (Redis/RabbitMQ/Vault/Consul/...) ──
  if want nuclei-panels; then
    if [ -z "$NUCLEI" ]; then
      warn "nuclei not found, skipping nuclei-panels"
    elif [ ! -d "$NUCLEI_COMMUNITY/http/exposed-panels" ]; then
      warn "nuclei-community not found (run: nuclei -update-templates)"
    else
      info "hunter: nuclei-panels (官方 exposed-panels — DevOps/DB/Vault/Console)"
      local NP_OH="$DIR/hunters/nuclei-panels"
      mkdir -p "$NP_OH"
      local NP_OUT="$NP_OH/panels_results.txt"
      > "$NP_OUT"
      $NUCLEI -l "$LIVE" \
        -t "$NUCLEI_COMMUNITY/http/exposed-panels" \
        -rate-limit 5 \
        -timeout 10 \
        -silent \
        -o "$NP_OUT" 2>/dev/null || true
      echo "" >> "$REPORT"
      echo "## nuclei-panels" >> "$REPORT"
      if [ -s "$NP_OUT" ]; then
        local NP_COUNT
        NP_COUNT=$(wc -l < "$NP_OUT" | tr -d ' ')
        echo "- $NP_COUNT findings → $NP_OUT" >> "$REPORT"
        while IFS= read -r line; do
          local sev tmpl url
          sev=$(echo "$line" | grep -oE '\[(critical|high|medium|info)\]' | head -1 | tr -d '[]')
          tmpl=$(echo "$line" | grep -oE '^\[[^]]+\]' | head -1 | tr -d '[]')
          url=$(echo "$line" | awk '{print $NF}')
          echo "- 🔴 PANEL [$sev] $tmpl → $url" >> "$REPORT"
        done < "$NP_OUT"
        ok "  nuclei-panels hits: $NP_COUNT"
      else
        echo "- (no panel findings)" >> "$REPORT"
      fi
    fi
  fi

  # ── nuclei-wp: Wordfence WordPress CVE templates ──────────────
  if want nuclei-wp; then
    if [ -z "$NUCLEI" ]; then
      warn "nuclei not found, skipping nuclei-wp"
    elif [ ! -d "$NUCLEI_WORDFENCE" ]; then
      warn "nuclei-wordfence not found at $NUCLEI_WORDFENCE (run: bbflow nuclei-update)"
    else
      info "hunter: nuclei-wp (Wordfence WordPress CVE templates)"
      local NW_OH="$DIR/hunters/nuclei-wp"
      mkdir -p "$NW_OH"
      local NW_OUT="$NW_OH/wp_results.txt"
      > "$NW_OUT"
      $NUCLEI -l "$LIVE" \
        -t "$NUCLEI_WORDFENCE" \
        -rate-limit 3 \
        -timeout 15 \
        -silent \
        -o "$NW_OUT" 2>/dev/null || true
      echo "" >> "$REPORT"
      echo "## nuclei-wp (Wordfence CVE)" >> "$REPORT"
      if [ -s "$NW_OUT" ]; then
        local NW_COUNT
        NW_COUNT=$(wc -l < "$NW_OUT" | tr -d ' ')
        echo "- $NW_COUNT findings → $NW_OUT" >> "$REPORT"
        while IFS= read -r line; do
          local sev tmpl url
          sev=$(echo "$line" | grep -oE '\[(critical|high|medium)\]' | head -1 | tr -d '[]')
          tmpl=$(echo "$line" | grep -oE '^\[[^]]+\]' | head -1 | tr -d '[]')
          url=$(echo "$line" | awk '{print $NF}')
          echo "- 🔴 WP-CVE [$sev] $tmpl → $url" >> "$REPORT"
        done < "$NW_OUT"
        ok "  nuclei-wp hits: $NW_COUNT"
      else
        echo "- (no WordPress CVE findings)" >> "$REPORT"
      fi
    fi
  fi

  # ── param-fuzz: URL/param discovery + nuclei DAST ─────────────
  if want param-fuzz; then
    info "hunter: param-fuzz (katana + gau + uro → nuclei DAST XSS/SQLi/SSRF/LFI/SSTI)"
    local PF_OH="$DIR/hunters/param-fuzz"
    mkdir -p "$PF_OH"
    export OUT_DIR="$PF_OH"
    echo "" >> "$REPORT"
    echo "## param-fuzz" >> "$REPORT"
    # run against each live host individually (katana crawl needs a base URL)
    local PF_ALL_HITS="$PF_OH/all_hits.txt"
    > "$PF_ALL_HITS"
    while IFS= read -r HOST; do
      [ -z "$HOST" ] && continue
      local SLUG
      SLUG=$(echo "$HOST" | sed -E 's|^https?://||' | tr '/:.' '_')
      local PF_SUBDIR="$PF_OH/$SLUG"
      mkdir -p "$PF_SUBDIR"
      export OUT_DIR="$PF_SUBDIR"
      "$TOOLS_DIR/hunters/hunt-param-fuzz.sh" "$HOST" 2>/dev/null \
        | grep "^🔴" >> "$PF_ALL_HITS" || true
    done < "$LIVE"
    if [ -s "$PF_ALL_HITS" ]; then
      local PF_COUNT
      PF_COUNT=$(wc -l < "$PF_ALL_HITS" | tr -d ' ')
      echo "- $PF_COUNT DAST findings → $PF_ALL_HITS" >> "$REPORT"
      while IFS= read -r line; do
        echo "- $line" >> "$REPORT"
      done < "$PF_ALL_HITS"
      ok "  param-fuzz hits: $PF_COUNT"
    else
      # aggregate param counts from sub-dirs
      local TOTAL_PARAMS
      TOTAL_PARAMS=$(cat "$PF_OH"/*/param_urls.txt 2>/dev/null | wc -l | tr -d ' ')
      echo "- 0 DAST findings ($TOTAL_PARAMS parameterized URLs crawled)" >> "$REPORT"
    fi
  fi

  # ── dalfox-xss: XSS deep scan ───────────────────────────────
  if want dalfox-xss; then
    info "hunter: dalfox-xss (XSS + gf filter)"
    local DFX_OH="$DIR/hunters/dalfox-xss"; mkdir -p "$DFX_OH"
    echo "" >> "$REPORT"; echo "## dalfox-xss" >> "$REPORT"
    while IFS= read -r HOST; do
      [ -z "$HOST" ] && continue
      local SLUG; SLUG=$(echo "$HOST" | sed -E 's|^https?://||' | tr '/:.' '_')
      export OUT_DIR="$DFX_OH/$SLUG"; mkdir -p "$OUT_DIR"
      "$TOOLS_DIR/hunters/hunt-dalfox-xss.sh" "$HOST" 2>/dev/null \
        | grep "^🔴" >> "$DFX_OH/dalfox_hits.txt" || true
    done < "$LIVE"
    if [ -s "$DFX_OH/dalfox_hits.txt" ]; then
      local DFX_COUNT; DFX_COUNT=$(wc -l < "$DFX_OH/dalfox_hits.txt" | tr -d ' ')
      echo "- $DFX_COUNT XSS findings → $DFX_OH/dalfox_hits.txt" >> "$REPORT"
      while read L; do echo "- $L" >> "$REPORT"; done < "$DFX_OH/dalfox_hits.txt"
      ok "  dalfox-xss hits: $DFX_COUNT"
    else
      echo "- (no XSS found)" >> "$REPORT"
    fi
  fi

  # ── arjun-params: hidden param discovery ─────────────────────
  if want arjun-params; then
    info "hunter: arjun-params (hidden GET/POST/JSON params)"
    local AJ_OH="$DIR/hunters/arjun-params"; mkdir -p "$AJ_OH"
    echo "" >> "$REPORT"; echo "## arjun-params" >> "$REPORT"
    while IFS= read -r HOST; do
      [ -z "$HOST" ] && continue
      local SLUG; SLUG=$(echo "$HOST" | sed -E 's|^https?://||' | tr '/:.' '_')
      export OUT_DIR="$AJ_OH/$SLUG"; mkdir -p "$OUT_DIR"
      "$TOOLS_DIR/hunters/hunt-arjun-params.sh" "$HOST" 2>/dev/null \
        | grep "^🔴" >> "$AJ_OH/arjun_hits.txt" || true
    done < "$LIVE"
    if [ -s "$AJ_OH/arjun_hits.txt" ]; then
      local AJ_COUNT; AJ_COUNT=$(wc -l < "$AJ_OH/arjun_hits.txt" | tr -d ' ')
      echo "- $AJ_COUNT endpoints with hidden params → $AJ_OH/arjun_hits.txt" >> "$REPORT"
      while read L; do echo "- $L" >> "$REPORT"; done < "$AJ_OH/arjun_hits.txt"
      ok "  arjun-params hits: $AJ_COUNT"
    else
      echo "- (no hidden params found)" >> "$REPORT"
    fi
  fi

  # ── trufflehog: git history deep secret scan ─────────────────
  if want trufflehog; then
    info "hunter: trufflehog (git history 100+ secret detectors)"
    local TFH_OH="$DIR/hunters/trufflehog"; mkdir -p "$TFH_OH"
    echo "" >> "$REPORT"; echo "## trufflehog" >> "$REPORT"
    while IFS= read -r HOST; do
      [ -z "$HOST" ] && continue
      local SLUG; SLUG=$(echo "$HOST" | sed -E 's|^https?://||' | tr '/:.' '_')
      export OUT_DIR="$TFH_OH/$SLUG"; mkdir -p "$OUT_DIR"
      "$TOOLS_DIR/hunters/hunt-trufflehog-secrets.sh" "$HOST" 2>/dev/null \
        | grep "^🔴" >> "$TFH_OH/trufflehog_hits.txt" || true
    done < "$LIVE"
    if [ -s "$TFH_OH/trufflehog_hits.txt" ]; then
      local TFH_COUNT; TFH_COUNT=$(wc -l < "$TFH_OH/trufflehog_hits.txt" | tr -d ' ')
      echo "- $TFH_COUNT secrets found → $TFH_OH/trufflehog_hits.txt" >> "$REPORT"
      while read L; do echo "- $L" >> "$REPORT"; done < "$TFH_OH/trufflehog_hits.txt"
      ok "  trufflehog hits: $TFH_COUNT"
    else
      echo "- (no verified secrets found)" >> "$REPORT"
    fi
  fi

  # ── ffuf-dirs: directory/file fuzzing ─────────────────────────
  if want ffuf-dirs; then
    info "hunter: ffuf-dirs (BB high-ROI path list)"
    local FF_OH="$DIR/hunters/ffuf-dirs"; mkdir -p "$FF_OH"
    echo "" >> "$REPORT"; echo "## ffuf-dirs" >> "$REPORT"
    while IFS= read -r HOST; do
      [ -z "$HOST" ] && continue
      local SLUG; SLUG=$(echo "$HOST" | sed -E 's|^https?://||' | tr '/:.' '_')
      export OUT_DIR="$FF_OH/$SLUG"; mkdir -p "$OUT_DIR"
      "$TOOLS_DIR/hunters/hunt-ffuf-dirs.sh" "$HOST" 2>/dev/null \
        | grep "^[🔴🟡]" >> "$FF_OH/ffuf_hits.txt" || true
    done < "$LIVE"
    if [ -s "$FF_OH/ffuf_hits.txt" ]; then
      local FF_COUNT; FF_COUNT=$(grep -c "^🔴" "$FF_OH/ffuf_hits.txt" 2>/dev/null || echo 0)
      local FF_TOTAL; FF_TOTAL=$(wc -l < "$FF_OH/ffuf_hits.txt" | tr -d ' ')
      echo "- $FF_TOTAL paths found ($FF_COUNT critical) → $FF_OH/ffuf_hits.txt" >> "$REPORT"
      while read L; do echo "- $L" >> "$REPORT"; done < "$FF_OH/ffuf_hits.txt"
      ok "  ffuf-dirs hits: $FF_TOTAL (critical: $FF_COUNT)"
    else
      echo "- (no interesting paths found)" >> "$REPORT"
    fi
  fi

  ok "report → $REPORT"
  echo ""
  grep "^- 🔴" "$REPORT" 2>/dev/null | head -20 || true
}

# ── cmd: nuclei-update ────────────────────────────────────────
cmd_nuclei_update() {
  echo "${B}== bbflow nuclei-update ==${N}"

  # 1. 更新官方 projectdiscovery nuclei-templates
  if [ -n "$NUCLEI" ]; then
    info "updating official nuclei-templates..."
    $NUCLEI -update-templates 2>&1 | tail -3
    ok "official templates updated → $NUCLEI_COMMUNITY"
  else
    warn "nuclei not found, skipping official update"
  fi

  # 2. Clone/update topscoder/nuclei-wordfence-cve
  if [ -d "$NUCLEI_WORDFENCE/.git" ]; then
    info "updating nuclei-wordfence-cve..."
    git -C "$NUCLEI_WORDFENCE" pull --quiet 2>&1 | tail -2
    WF_COUNT=$(find "$NUCLEI_WORDFENCE" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
    ok "wordfence templates updated → $WF_COUNT templates"
  elif command -v git >/dev/null 2>&1; then
    info "cloning nuclei-wordfence-cve..."
    git clone --quiet --depth=1 https://github.com/topscoder/nuclei-wordfence-cve.git "$NUCLEI_WORDFENCE" 2>&1 | tail -2
    WF_COUNT=$(find "$NUCLEI_WORDFENCE" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
    ok "wordfence cloned → $WF_COUNT templates at $NUCLEI_WORDFENCE"
  else
    warn "git not found, cannot clone wordfence templates"
  fi

  echo ""
  echo "${B}Template inventory:${N}"
  [ -d "$NUCLEI_TEMPLATES" ] && ok "bb-recon custom → $(ls "$NUCLEI_TEMPLATES"/*.yaml 2>/dev/null | wc -l | tr -d ' ') templates"
  [ -d "$NUCLEI_COMMUNITY/http/exposures/tokens" ] && ok "PD tokens → $(ls "$NUCLEI_COMMUNITY/http/exposures/tokens"/*/*.yaml 2>/dev/null | wc -l | tr -d ' ')"
  [ -d "$NUCLEI_COMMUNITY/http/exposures/configs" ] && ok "PD configs → $(ls "$NUCLEI_COMMUNITY/http/exposures/configs"/*.yaml 2>/dev/null | wc -l | tr -d ' ')"
  [ -d "$NUCLEI_COMMUNITY/http/exposed-panels" ] && ok "PD panels → $(ls "$NUCLEI_COMMUNITY/http/exposed-panels"/*.yaml "$NUCLEI_COMMUNITY/http/exposed-panels"/*/*.yaml 2>/dev/null | wc -l | tr -d ' ')"
  [ -d "$NUCLEI_WORDFENCE" ] && ok "Wordfence WP CVE → $(find "$NUCLEI_WORDFENCE" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')"
}

# ── cmd: flow ────────────────────────────────────────────────
cmd_flow() {
  local T="$1"
  cmd_init "$T"
  cmd_recon "$T"
  cmd_hunt "$T"
}

# ── cmd: status ──────────────────────────────────────────────
cmd_status() {
  local T="${1:-}"
  if [ -z "$T" ]; then cmd_list; return; fi
  local DIR="$BASE_DIR/research/$T"
  [ ! -d "$DIR" ] && { err "no such target"; exit 1; }
  echo "${B}$T${N}"
  [ -f "$DIR/SCOPE.md" ] && ok "SCOPE.md ($(wc -l < $DIR/SCOPE.md | tr -d ' ') lines)" || err "SCOPE.md missing"
  [ -s "$DIR/bbot/subdomains.txt" ] && ok "subdomains: $(wc -l < $DIR/bbot/subdomains.txt | tr -d ' ')" || warn "no subdomains"
  [ -s "$DIR/bbot/live_hosts.txt" ] && ok "live hosts: $(wc -l < $DIR/bbot/live_hosts.txt | tr -d ' ')" || warn "no live hosts"
  if [ -d "$DIR/hunters" ]; then
    for H in "$DIR/hunters"/*/; do
      [ -d "$H" ] || continue
      local NAME=$(basename "$H")
      local HITS=$(grep -h "^🔴" "$H"/*.txt 2>/dev/null | wc -l | tr -d ' ')
      [ "$HITS" != "0" ] && ok "$NAME: ${HITS} hits" || echo "    $NAME: 0 hits"
    done
  fi
  local LATEST=$(ls -t "$DIR"/HUNTERS_REPORT_*.md 2>/dev/null | head -1)
  [ -n "$LATEST" ] && info "latest report: $LATEST"
}

cmd_report() { cmd_hunt "$@"; }

# ── cmd: test (regression smoke on example.com) ───────────────
cmd_test() {
  echo "${B}== bbflow regression test (example.com) ==${N}"
  local FAIL=0
  local TMP="/tmp/bbflow_test_$$"
  mkdir -p "$TMP"
  test_h() {
    local name="$1" script="$2" arg="$3"
    export OUT_DIR="$TMP/$name"
    mkdir -p "$OUT_DIR"
    if "$script" "$arg" >/dev/null 2>&1; then
      local HITS
      HITS=$(grep -c "^🔴" "$OUT_DIR"/*.txt 2>/dev/null | head -1 | tr -d ' \n')
      [ -z "$HITS" ] && HITS=0
      if [ "$HITS" = "0" ]; then
        ok "$name  (null case: 0 FP)"
      else
        err "$name  ($HITS unexpected hits — possible FP on example.com!)"
        FAIL=$((FAIL+1))
      fi
    else
      err "$name  (script error)"
      FAIL=$((FAIL+1))
    fi
  }
  test_h envdata       "$TOOLS_DIR/hunters/hunt-envdata.sh"               "https://example.com"
  test_h sourcemap     "$TOOLS_DIR/hunters/hunt-sourcemap-secrets.sh"     "https://example.com"
  test_h js-secrets    "$TOOLS_DIR/hunters/hunt-hardcoded-js-secrets.sh"  "https://example.com"
  test_h cors          "$TOOLS_DIR/hunters/hunt-cors-reflect.sh"          "https://example.com/"
  test_h graphql       "$TOOLS_DIR/hunters/hunt-graphql-idor.sh"          "https://example.com"
  test_h userenum      "$TOOLS_DIR/hunters/hunt-user-enum.sh"             "https://example.com"
  test_h hybris-occ    "$TOOLS_DIR/hunters/hunt-hybris-occ.sh"            "https://example.com"
  test_h git-exposure  "$TOOLS_DIR/hunters/hunt-git-exposure.sh"          "https://example.com"
  test_h devops-unauth "$TOOLS_DIR/hunters/hunt-devops-unauth.sh"         "https://example.com"
  test_h actuator-deep "$TOOLS_DIR/hunters/hunt-actuator-deep.sh"         "https://example.com"
  test_h mcp-oauth     "$TOOLS_DIR/hunters/hunt-mcp-oauth-scope.sh"       "https://example.com"
  test_h open-redirect "$TOOLS_DIR/hunters/hunt-open-redirect.sh"         "https://example.com"
  test_h takeover      "$TOOLS_DIR/hunters/hunt-subdomain-takeover.sh"    "nonexistent-subdomain.example.com"
  test_h gkey          "$TOOLS_DIR/hunters/hunt-google-api-key.sh"        "AIzaSyFAKEKEY_ForSmokeTest_AAAAAAAAAAAAA"
  rm -rf "$TMP"
  echo ""
  if [ "$FAIL" = "0" ]; then
    ok "all 14 null-case hunters passed"
  else
    err "$FAIL hunter(s) produced unexpected hits — investigate"
    exit 1
  fi
}

# ── cmd: dedupe (compare hits against prior submitted reports) ──
cmd_dedupe() {
  local T="$1"
  [ -z "$T" ] && { err "usage: bbflow dedupe <target>"; exit 1; }
  local DIR="$BASE_DIR/research/$T"
  [ ! -d "$DIR/hunters" ] && { err "no hunters output for $T (run: bbflow hunt $T)"; exit 1; }

  echo "${B}== dedupe check: $T ==${N}"
  local ALL_HITS
  ALL_HITS=$(grep -h "^🔴" "$DIR/hunters"/*/*.txt 2>/dev/null | sort -u)
  if [ -z "$ALL_HITS" ]; then
    info "no hits to dedupe"; return
  fi

  # Sources to compare against: HITCON_ZeroDay_Reports/submited/, research/*/submited/, research/*/reports/
  local COMPARE_PATHS=(
    "$BASE_DIR/HITCON_ZeroDay_Reports/submited"
    "$BASE_DIR/HITCON_ZeroDay_Reports/fixed"
    "$DIR/submited"
    "$DIR/reports"
  )

  local DUP=0 NEW=0
  echo "$ALL_HITS" | while read -r HIT; do
    # Extract distinguishing token from each hit (URL / endpoint / cred name)
    local KEY
    KEY=$(echo "$HIT" | grep -oE 'https?://[^ ]+|/[a-z/_-]+|AIza[A-Za-z0-9_-]{10}' | head -1)
    [ -z "$KEY" ] && continue
    local FOUND=""
    for P in "${COMPARE_PATHS[@]}"; do
      [ ! -d "$P" ] && continue
      if grep -rlq --include="*.md" --include="*.txt" -F "$KEY" "$P" 2>/dev/null; then
        FOUND="$P"
        break
      fi
    done
    if [ -n "$FOUND" ]; then
      echo "  ${Y}DUP${N} $HIT"
      echo "     match in: $FOUND"
    else
      echo "  ${G}NEW${N} $HIT"
    fi
  done
}

# ── Main dispatch ────────────────────────────────────────────
SUB="${1:-help}"; shift 2>/dev/null || true
case "$SUB" in
  doctor)         cmd_doctor;;
  init)           cmd_init "$@";;
  recon)          cmd_recon "$@";;
  hunt)           cmd_hunt "$@";;
  flow)           cmd_flow "$@";;
  status)         cmd_status "$@";;
  list)           cmd_list;;
  report)         cmd_report "$@";;
  scope)          cmd_scope "$@";;
  test)           cmd_test;;
  dedupe)         cmd_dedupe "$@";;
  nuclei-update)  cmd_nuclei_update;;
  help|-h|--help|"") usage;;
  *) err "unknown subcommand: $SUB"; usage; exit 1;;
esac
