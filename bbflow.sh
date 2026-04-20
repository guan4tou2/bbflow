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
NUCLEI_COMMUNITY="$HOME/nuclei-templates"

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

${B}18 Hunters (對應 confirmed bounty 案例 + 高 ROI pattern):${N}
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
  nuclei           bb-recon templates (直接可利用漏洞)          [需 nuclei binary]
                  → default-creds / jwt-none / s3-listable /
                    git-exposure / devops-unauth / oauth-redirect /
                    graphql-introspection / subdomain-takeover
  nuclei-secrets   官方 projectdiscovery 123 token + 206 config templates [需 ~/nuclei-templates/]
                  → AWS/GCP/GitHub/Slack/Stripe keys + .env/.git/config 洩漏
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
  echo "${B}Hunters:${N}"
  for H in "$TOOLS_DIR/hunters"/hunt-*.sh; do
    [ -x "$H" ] && ok "$(basename "$H")" || err "$(basename "$H") (not executable)"
  done
  echo ""
  echo "${B}Optional env:${N}"
  [ -n "${OSMEDEUS_VPS:-}" ] && ok "OSMEDEUS_VPS=$OSMEDEUS_VPS" || warn "OSMEDEUS_VPS not set (--osmedeus will fail)"
  [ -n "${EXISTING_EMAIL:-}" ] && ok "EXISTING_EMAIL=$EXISTING_EMAIL" || warn "EXISTING_EMAIL not set (user-enum will guess admin@domain)"
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

  ok "report → $REPORT"
  echo ""
  grep "^- 🔴" "$REPORT" 2>/dev/null | head -20 || true
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
  doctor)  cmd_doctor;;
  init)    cmd_init "$@";;
  recon)   cmd_recon "$@";;
  hunt)    cmd_hunt "$@";;
  flow)    cmd_flow "$@";;
  status)  cmd_status "$@";;
  list)    cmd_list;;
  report)  cmd_report "$@";;
  scope)   cmd_scope "$@";;
  test)    cmd_test;;
  dedupe)  cmd_dedupe "$@";;
  help|-h|--help|"") usage;;
  *) err "unknown subcommand: $SUB"; usage; exit 1;;
esac
