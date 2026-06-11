#!/usr/bin/env bash
# bbflow.sh — 統一 Bug Bounty Flow CLI  v1.5.0
# 零 LLM 依賴。所有 subcommand 都是 bash + curl + python3 stdlib。
#
# v1.5.0 (2026-04-30): workshop/ path fix + 3 new hunters + init delegates to init_target.sh
#   - research/ → workshop/ (全域路徑修正，配合 workspace rename)
#   - bbflow init 改委派 automation/init_target.sh（建 RECON_DB.md + SCOPE.md + FINDINGS_QUICK_REF.md）
#   - 新 hunter: monitor-bypass (TP-S35/38 pattern — admin auth bypass)
#   - 新 hunter: sms-static-cred (TP-S45 pattern — SMS gateway static credential probe)
#   - 新 hunter: git-deep (TP-S47 pattern — .git object zlib extraction for credentials)
#
# 子命令：
#   bbflow doctor                          檢查依賴與工具路徑
#   bbflow init <target>                   建立 workshop/<target>/ + SCOPE.md 模板
#   bbflow recon <target> [--osmedeus]     執行 BBOT（預設）或 Osmedeus VPS recon
#   bbflow hunt <target> [--only h1,h2]    對 live_hosts.txt 跑全部 hunters
#   bbflow flow <target>                   recon + hunt + report 一條龍
#   bbflow status [<target>]               列出所有/單一 target 的進度
#   bbflow list                            列出所有 research 中的 target
#   bbflow report <target>                 重新產生 HUNTERS_REPORT.md
#   bbflow scope <target>                  顯示 SCOPE.md
#   bbflow submit-checklist <platform>     輸出送件前檢查清單（hitcon / twcert）
#
# 設計原則：
#   1. BBOT / Osmedeus 負責 recon（asset discovery）
#   2. Hunters 負責 pattern-specific 驗證（confirmed-bounty patterns）
#   3. 狀態存在 workshop/<target>/，不重複執行已完成的階段
#   4. 所有掃描命令 scope-first；先建 SCOPE.md 或傳入 --scope-file 才 hunt/recon/flow
set -uo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Workspace: where workshop/, reports/, etc. are stored ──────
# Override with: export BBFLOW_WORKSPACE=/your/path
# Default: current working directory ($PWD), so `cd ~/work && bbflow hunt t`
# stores research at ~/work/workshop/
BASE_DIR="${BBFLOW_WORKSPACE:-$(pwd)}"
export BBFLOW_WORKSPACE="$BASE_DIR"

# ── Prepend tools/bin to PATH so bundled binaries take priority ─
# Place BBOT / Osmedeus wrappers in tools/bin/ to ship with repo
export PATH="$TOOLS_DIR/bin:$PATH"

# ── Dependencies ───────────────────────────────────────────────
# Bundled binaries (tools/bin/ or tools/) take priority over system PATH
BBOT="$(command -v bbot 2>/dev/null || echo "$HOME/.local/bin/bbot")"
HTTPX="$TOOLS_DIR/httpx";      [ ! -x "$HTTPX" ]     && HTTPX="$(command -v httpx 2>/dev/null || echo '')"
SUBFINDER="$TOOLS_DIR/subfinder"; [ ! -x "$SUBFINDER" ] && SUBFINDER="$(command -v subfinder 2>/dev/null || echo '')"
NUCLEI="$TOOLS_DIR/nuclei";    [ ! -x "$NUCLEI" ]    && NUCLEI="$(command -v nuclei 2>/dev/null || echo '')"
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
FEROX="$(command -v feroxbuster 2>/dev/null || echo '')"
ARJUN="$(command -v arjun 2>/dev/null || echo '')"
TRUFFLEHOG="$(command -v trufflehog 2>/dev/null || echo '')"
NMAP="$(command -v nmap 2>/dev/null || echo '')"
RUSTSCAN="$(command -v rustscan 2>/dev/null || echo '')"
PARAMSPIDER="$(command -v paramspider 2>/dev/null || echo '')"
HAKRAWLER="$(command -v hakrawler 2>/dev/null || echo '')"

# ── gau config：若 tools/configs/gau.toml 存在，export 給 hunter 用 ──
if [ -z "${GAU_CONFIG:-}" ] && [ -f "$TOOLS_DIR/configs/gau.toml" ]; then
  export GAU_CONFIG="$TOOLS_DIR/configs/gau.toml"
fi

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
  local HUNTER_COUNT
  HUNTER_COUNT=$(find "$TOOLS_DIR/hunters" -maxdepth 1 -name 'hunt-*.sh' 2>/dev/null | wc -l | tr -d ' ')
  cat <<EOF
${B}bbflow${N} — Unified Bug Bounty Flow CLI (零 LLM)

${B}Usage:${N}
  bbflow doctor                    檢查依賴
  bbflow test                      對 example.com 跑 null-case regression test
  bbflow init <target>             初始化 workshop/<target>/ + SCOPE.md
  bbflow recon <target> [--scope-file SCOPE.md] [--osmedeus]
  bbflow hunt <target> [--scope-file SCOPE.md] [--only h1,...]
  bbflow hunt --list <file> --scope-file SCOPE.md [--name <slug>] [--probe] [--only h1,...]
  bbflow flow <target> [--scope-file SCOPE.md]   recon + hunt + report 一條龍
  bbflow flow --list <file> --scope-file SCOPE.md [--name <slug>] [--probe]
  bbflow dedupe <target>           對比已送報告找重複
  bbflow status [<target>]
  bbflow list
  bbflow report <target>
  bbflow scope <target>
  bbflow submit-checklist <hitcon|twcert>
  bbflow nuclei-update             更新官方 PD templates + clone Wordfence CVE repo

${B}Examples:${N}
  bbflow doctor
  bbflow init target.example.com
  bbflow flow target.example.com --scope-file scope.yaml
  bbflow hunt target.example.com --scope-file scope.yaml --only cors,graphql
  bbflow hunt --list hosts.txt --scope-file scope.yaml --name my-prog --probe
  OSMEDEUS_VPS=user@1.2.3.4 bbflow recon target.example.com --osmedeus
  bbflow submit-checklist hitcon

${B}Scope guard:${N}
  recon/hunt/flow refuse to run without workshop/<target>/SCOPE.md.
  External automation should pass --scope-file scope.yaml or scope.json (schema_version: 1).
  Use --allow-no-scope only for explicitly authorized internal runs.

${B}Workspace:${N}
  預設 workshop/ 建在執行 bbflow 的目錄（\$PWD）
  覆蓋: export BBFLOW_WORKSPACE=/custom/path
  Bundled tools (nuclei/httpx/subfinder): tools/
  BBOT/Osmedeus wrappers: tools/bin/（放在 repo 裡即可）

${B}Directory layout:${N}
  workshop/<target>/
    SCOPE.md                       ← scope 定義（必須先手寫完整）
    bbot/subdomains.txt            ← BBOT 輸出
    bbot/live_hosts.txt            ← httpx 存活結果
    hunters/<name>/<slug>.txt      ← 每個 hunter 的原始輸出
    nxdomain/nxdomain_corpus.txt   ← NXDOMAIN payload 候選
    HUNTERS_REPORT_YYYYMMDD_HHMM.md ← 彙總報告

${B}${HUNTER_COUNT} hunter scripts${N} (對應 confirmed bounty 案例 + 高 ROI pattern + WAF-friendly low-noise；完整清單見 tools/hunters/README.md):
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
  config-leak      xray-inspired config 洩漏探測（.git/.env/actuator/swagger/100+ paths）
                   → 1 GET + content-match；FAST=1 只跑 P1/P2 [low-noise，WAF 友善]
  weak-login       常見管理介面 default creds 單次探測 [low-noise，WAF 友善]
                   → nacos/druid/grafana/jenkins/tomcat/phpmyadmin/zabbix/...
  backup-files     備份 / dump 檔（zip/tar.gz/sql/bak） [low-noise，WAF 友善]
                   → 41 靜態 + hostname 衍生 + magic bytes 驗證 + Index-of fallback
  crawl-chain      katana+gau+paramspider → uro+gf → arjun → nuclei DAST → dalfox
                   → 10 階段全鏈 URL/param discovery + fuzzing
                   → DEPTH=5 更深 crawl, FAST=1 略 arjun+dalfox
  nuclei-deep      擴充 nuclei 攻擊面（18 類別：XSS/SQLi/SSRF/LFI/RCE/...）
                   → CATEGORY=xss,sqli 單跑；FAST=1 只跑 high/critical
                   → xss, sqli, ssrf, lfi, rce, redirect, ssti, xxe, takeover,
                     cors, info, debug, panel, weak-login, cve, misconfig, cloud, oast
  waf-bypass       15+ 自動化 WAF 繞過測試（header/path/method/origin）
                   → ORIGIN_IP=1.2.3.4 直連 origin
                   → PATHS=/admin,/api/v1 自訂測試路徑
                   → 自動測：X-Original-URL, XFF-127, 大小寫, //, ;, %00,
                     OPTIONS method, HTTP/2, localhost Host header
  version-json     環境對映 JSON 洩漏（/json/version.json, /version.json, /json/config.json 等）
                   → 揭露 dev/test/UAT/staging 主機名稱（EVERY8D TP-S18 pattern）
                   → 標記含 .cc/.dev/.local 或內網 IP 的 value
  cert-bypass      SSO /cert 端點無密碼 token 發行探測（EVERY8D TP-S32 pattern）
                   → /login/cert, /auth/cert, /sso/cert, /api/cert 等端點
                   → POST fake account → 偵測 token 發行 → verify on authenticated API
                   → P1-CRIT if token works on real API endpoints
  monitor-bypass   監控 / 管理後台 Auth Bypass 探測（TP-S35/38 pattern）
                   → 目標：monitor.*/admin.*/manage.*/dashboard.* + Spring Boot /actuator
                   → 測試：空帳密(aid=&pwd=)、admin/PASSWORD、admin/admin、admin/空白
                   → 偵測：302 redirect to adminMain / 200 with dashboard content
                   → P1-CRIT if authenticated content accessible
  sms-static-cred  SMS Gateway 靜態憑證探測（TP-S45 pattern）
                   → 目標：/sms, /api/sms, /sms/send, /send-sms 等端點
                   → 測試：act=e8d 類型的固定 act 參數 + MD5 格式密碼（32 char hex）
                   → 偵測：resp_status 成功 / HTTP 200 非 3xx redirect
                   → 資訊洩漏點：.git config / JS bundle / 回應 body
  git-deep         .git 物件深層提取（TP-S47 pattern，git-exposure 延伸）
                   → git-exposure 確認 .git 暴露後繼續：HEAD → commit → tree → blob
                   → zlib decompression：curl .git/objects/xx/yy → python3 zlib.decompress
                   → 目標 blob：config.ini / .env / credentials / settings
                   → P1-CRIT if production credentials extracted
EOF
}

# ── cmd: doctor ────────────────────────────────────────────────
cmd_doctor() {
  echo "${B}== bbflow doctor ==${N}"
  ok  "TOOLS_DIR     → $TOOLS_DIR"
  ok  "BBFLOW_WORKSPACE → $BASE_DIR  (workshop/ + reports/ live here)"
  [ -d "$TOOLS_DIR/bin" ] && ok "tools/bin/    → $(ls "$TOOLS_DIR/bin" | tr '\n' ' ')" \
                          || info "tools/bin/    not found (create to bundle bbot/osmedeus wrappers)"
  echo ""
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
  if [ -n "$FFUF" ]; then
    ok "ffuf → $FFUF"
  elif [ -n "$FEROX" ]; then
    ok "ffuf not found — feroxbuster fallback → $FEROX"
  else
    warn "ffuf not found (go install github.com/ffuf/ffuf/v2@latest)"
    warn "feroxbuster not found (curl -sL .../install-nix.sh | sudo bash)"
  fi
  [ -n "$NMAP" ] && ok "nmap → $NMAP" || warn "nmap not found (sudo apt install nmap)"
  [ -n "$RUSTSCAN" ] && ok "rustscan → $RUSTSCAN" || warn "rustscan not found (fast port scan; nmap-only fallback active)"
  [ -n "$ARJUN" ] && ok "arjun → $ARJUN" || warn "arjun not found (pip3 install arjun --break-system-packages)"
  [ -n "$TRUFFLEHOG" ] && ok "trufflehog → $TRUFFLEHOG" || warn "trufflehog not found (brew install trufflehog)"
  [ -n "$PARAMSPIDER" ] && ok "paramspider → $PARAMSPIDER" || warn "paramspider not found (pip3 install paramspider --break-system-packages)"
  [ -n "$HAKRAWLER" ] && ok "hakrawler → $HAKRAWLER" || warn "hakrawler not found (go install github.com/hakluke/hakrawler@latest)"
  if [ -n "${GAU_CONFIG:-}" ] && [ -f "$GAU_CONFIG" ]; then
    ok "GAU_CONFIG → $GAU_CONFIG"
  else
    warn "GAU_CONFIG not set (tools/configs/gau.toml 缺失，gau 會用內建預設)"
  fi
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
  echo ""
  echo "${B}Pinned tool versions (tools.lock):${N}"
  if [ -f "$TOOLS_DIR/scripts/check_tool_versions.sh" ]; then
    bash "$TOOLS_DIR/scripts/check_tool_versions.sh" || warn "工具版本與 tools.lock 不一致 — 對齊: scripts/setup_pinned_tools.sh"
  else
    warn "scripts/check_tool_versions.sh missing (版本漂移無法偵測)"
  fi
}

# ── cmd: list ─────────────────────────────────────────────────
cmd_list() {
  if [ ! -d "$BASE_DIR/workshop" ]; then echo "(no workshop dir)"; return; fi
  echo "${B}Targets in workshop/:${N}"
  for T in "$BASE_DIR/workshop"/*/; do
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
  # Delegate to automation/init_target.sh (creates RECON_DB.md + SCOPE.md + FINDINGS_QUICK_REF.md)
  local SCRIPT_DIR
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  local INIT_SCRIPT="$SCRIPT_DIR/automation/init_target.sh"
  if [ -f "$INIT_SCRIPT" ]; then
    bash "$INIT_SCRIPT" "$T"
  else
    # Fallback: just create the directory + SCOPE.md
    local DIR="$BASE_DIR/workshop/$T"
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
<-- 從 program 頁面複製完整清單 -->

## Out-of-Scope (OOS)
<-- 從 program 頁面複製完整 OOS 清單 -->
EOF
      ok "initialized $SCOPE — 請先填完整 scope 再跑 recon"
    fi
  fi
}

# ── cmd: scope ────────────────────────────────────────────────
cmd_scope() {
  local T="$1"
  local SCOPE="$BASE_DIR/workshop/$T/SCOPE.md"
  [ -f "$SCOPE" ] || { err "no scope for $T (run: bbflow init $T)"; exit 1; }
  cat "$SCOPE"
}

scope_has_placeholders() {
  local SCOPE="$1"
  grep -Eq '<--|<HackerOne|<Bugcrowd|<Intigriti|<Immunefi|<target>|填完整|TODO' "$SCOPE" 2>/dev/null
}

write_legacy_scope_contract() {
  local T="$1" DIR="$2"
  python3 - "$T" "$DIR/scope_contract.json" <<'PY'
import json
import sys
from pathlib import Path

target, contract_path = sys.argv[1:]
payload = {
    "format": "markdown",
    "schema_version": None,
    "source_file": "SCOPE.md",
    "target": target,
    "program": None,
    "scan_level": None,
    "rate_limit": None,
    "in_scope": [],
    "out_of_scope": [],
    "allowed_tools": [],
}
Path(contract_path).write_text(
    json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
}

import_scope_file() {
  local T="$1" DIR="$2" SCOPE_FILE="$3"
  local LOWER CANONICAL FORMAT
  LOWER="$(echo "$SCOPE_FILE" | tr '[:upper:]' '[:lower:]')"

  case "$LOWER" in
    *.yaml|*.yml)
      FORMAT="yaml"
      CANONICAL="$DIR/scope.yaml"
      ;;
    *.json)
      FORMAT="json"
      CANONICAL="$DIR/scope.json"
      ;;
    *)
      cp "$SCOPE_FILE" "$DIR/SCOPE.md"
      write_legacy_scope_contract "$T" "$DIR"
      ok "scope-file copied → $DIR/SCOPE.md"
      return 0
      ;;
  esac

  cp "$SCOPE_FILE" "$CANONICAL"
  python3 - "$T" "$FORMAT" "$CANONICAL" "$DIR/SCOPE.md" "$DIR/scope_contract.json" <<'PY'
import json
import sys
from pathlib import Path


def parse_scalar(value):
    value = value.strip()
    if not value:
        return ""
    if (value[0], value[-1]) in {("'", "'"), ('"', '"')}:
        value = value[1:-1]
    if value.isdigit():
        return int(value)
    return value


def parse_simple_yaml(text):
    data = {}
    current_list = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        stripped = raw.strip()
        if not raw.startswith((" ", "\t")) and ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value:
                data[key] = parse_scalar(value)
                current_list = None
            else:
                data[key] = []
                current_list = key
            continue
        if current_list and stripped.startswith("- "):
            data[current_list].append(parse_scalar(stripped[2:]))
    return data


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


target, fmt, source, scope_md, contract_json = sys.argv[1:]
source_path = Path(source)
if fmt == "json":
    data = json.loads(source_path.read_text(encoding="utf-8"))
else:
    data = parse_simple_yaml(source_path.read_text(encoding="utf-8"))

required = ["schema_version", "target", "scan_level", "rate_limit", "in_scope", "out_of_scope"]
for field in required:
    if field not in data:
        fail(f"scope.{fmt} missing required field: {field}")

if int(data["schema_version"]) != 1:
    fail(f"scope.{fmt} unsupported schema_version: {data['schema_version']}")

in_scope = as_list(data.get("in_scope"))
out_of_scope = as_list(data.get("out_of_scope"))
allowed_tools = as_list(data.get("allowed_tools"))
if not in_scope:
    fail(f"scope.{fmt} missing required field: in_scope")

contract = {
    "format": fmt,
    "schema_version": 1,
    "source_file": source_path.name,
    "target": str(data.get("target")),
    "program": data.get("program"),
    "scan_level": str(data.get("scan_level")),
    "rate_limit": data.get("rate_limit"),
    "in_scope": in_scope,
    "out_of_scope": out_of_scope,
    "allowed_tools": allowed_tools,
}

lines = [
    f"# {target} Scope",
    "",
    f"Source: {source_path.name}",
    "schema_version: 1",
]
if contract["program"]:
    lines.append(f"program: {contract['program']}")
lines.extend(
    [
        f"scope_target: {contract['target']}",
        f"scan_level: {contract['scan_level']}",
        f"rate_limit: {contract['rate_limit']}",
        "",
        "## In-Scope",
    ]
)
lines.extend(f"- {item}" for item in in_scope)
lines.extend(["", "## Out-of-Scope (OOS)"])
if out_of_scope:
    lines.extend(f"- {item}" for item in out_of_scope)
else:
    lines.append("- (none specified)")
if allowed_tools:
    lines.extend(["", "## Allowed Tools"])
    lines.extend(f"- {item}" for item in allowed_tools)
lines.append("")

Path(scope_md).write_text("\n".join(lines), encoding="utf-8")
Path(contract_json).write_text(
    json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
  ok "scope-file imported ($FORMAT v1) → $DIR/SCOPE.md"
}

ensure_scope() {
  local T="$1" DIR="$2" SCOPE_FILE="$3" ALLOW_NO_SCOPE="$4" ACTION="$5"
  mkdir -p "$DIR"

  if [ -n "$SCOPE_FILE" ]; then
    [ -f "$SCOPE_FILE" ] || { err "--scope-file not found: $SCOPE_FILE"; exit 1; }
    import_scope_file "$T" "$DIR" "$SCOPE_FILE"
  fi

  if [ ! -f "$DIR/SCOPE.md" ]; then
    if [ "$ALLOW_NO_SCOPE" = "1" ]; then
      warn "no SCOPE.md — proceeding only because --allow-no-scope was set"
      return 0
    fi
    err "no SCOPE.md — refusing to $ACTION without scope"
    err "run: bbflow init $T  OR pass: --scope-file SCOPE.md"
    err "authorized external automation may use --allow-no-scope explicitly"
    exit 1
  fi

  if scope_has_placeholders "$DIR/SCOPE.md" && [ "$ALLOW_NO_SCOPE" != "1" ]; then
    err "SCOPE.md still contains placeholders — fill it before $ACTION"
    err "or pass a reviewed external scope with --scope-file SCOPE.md"
    exit 1
  fi

  [ -f "$DIR/scope_contract.json" ] || write_legacy_scope_contract "$T" "$DIR"
}

write_candidates_jsonl() {
  local T="$1" REPORT="$2" CANDIDATES="$3"
  python3 - "$T" "$REPORT" "$CANDIDATES" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

target, report_path, candidates_path = sys.argv[1:]
report = Path(report_path)
candidates = Path(candidates_path)
candidates.parent.mkdir(parents=True, exist_ok=True)

def infer_vuln_class(hunter, text):
    base = hunter.split()[0].strip().lower()
    mapping = {
        "cors": "cors",
        "graphql": "graphql",
        "userenum": "user-enumeration",
        "git-exposure": "source-disclosure",
        "git-deep": "source-disclosure",
        "js-secrets": "secret-exposure",
        "envdata": "secret-exposure",
        "sourcemap": "source-map-disclosure",
        "nuclei": "template-finding",
        "nuclei-secrets": "secret-exposure",
        "nuclei-panels": "exposed-panel",
        "nuclei-wp": "known-vulnerability",
        "param-fuzz": "dast",
        "dalfox-xss": "xss",
        "ffuf-dirs": "content-discovery",
        "portscan": "exposed-service",
    }
    if "secret" in text.lower():
        return "secret-exposure"
    return mapping.get(base, "unknown")


rows = []
if report.exists():
    hunter = "report"
    for line in report.read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.strip()
        if text.startswith("## "):
            hunter = text[3:].strip()
            continue
        if text.startswith("- 🔴"):
            clean = text[2:].strip()
            url = re.search(r"https?://[^\\s)]+", clean)
            url_value = url.group(0).rstrip(".,") if url else None
            dedupe_basis = "|".join([target, hunter, url_value or "", clean]).lower()
            dedupe_key = hashlib.sha256(dedupe_basis.encode("utf-8")).hexdigest()
            severity_match = re.search(r"\[(critical|high|medium|low|info)\]", clean, re.I)
            row = {
                "schema_version": 1,
                "candidate_id": f"bbflow-{dedupe_key[:16]}",
                "target": target,
                "hunter": hunter,
                "vuln_class": infer_vuln_class(hunter, clean),
                "confidence": "candidate",
                "severity": severity_match.group(1).lower() if severity_match else "unknown",
                "source": "hunters_report",
                "text": clean,
                "url": url_value,
                "dedupe_key": dedupe_key,
                "evidence_path": str(report),
                "artifact_refs": [str(report)],
                "triage_status": "candidate",
            }
            rows.append(row)

with candidates.open("w", encoding="utf-8") as fh:
    for row in rows:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
PY
}

write_run_manifest() {
  local T="$1" COMMAND="$2" DIR="$3" REPORT="$4" LIVE="$5" SCOPE="$6" ALLOW_NO_SCOPE="$7"
  local CANDIDATES="$DIR/candidates.jsonl"
  local MANIFEST="$DIR/run_manifest.json"
  write_candidates_jsonl "$T" "$REPORT" "$CANDIDATES"
  python3 - "$T" "$COMMAND" "$DIR" "$REPORT" "$LIVE" "$SCOPE" "$ALLOW_NO_SCOPE" "$CANDIDATES" "$MANIFEST" <<'PY'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

target, command, target_dir, report, live, scope, allow_no_scope, candidates, manifest = sys.argv[1:]
live_path = Path(live)
live_hosts_count = 0
if live_path.exists():
    live_hosts_count = sum(1 for line in live_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())

candidate_path = Path(candidates)
candidate_count = 0
if candidate_path.exists():
    candidate_count = sum(1 for line in candidate_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())

contract_path = Path(target_dir) / "scope_contract.json"
if contract_path.exists():
    scope_contract = json.loads(contract_path.read_text(encoding="utf-8"))
elif scope:
    scope_contract = {
        "format": "markdown",
        "schema_version": None,
        "source_file": Path(scope).name,
        "target": target,
        "program": None,
        "scan_level": None,
        "rate_limit": None,
        "in_scope": [],
        "out_of_scope": [],
        "allowed_tools": [],
    }
else:
    scope_contract = {
        "format": "none",
        "schema_version": None,
        "source_file": None,
        "target": target,
        "program": None,
        "scan_level": None,
        "rate_limit": None,
        "in_scope": [],
        "out_of_scope": [],
        "allowed_tools": [],
    }

payload = {
    "schema_version": 1,
    "candidate_schema_version": 1,
    "candidate_schema_fields": [
        "schema_version",
        "candidate_id",
        "target",
        "hunter",
        "vuln_class",
        "confidence",
        "severity",
        "source",
        "text",
        "url",
        "dedupe_key",
        "evidence_path",
        "artifact_refs",
        "triage_status",
    ],
    "target": target,
    "command": command,
    "created_at": datetime.now(timezone.utc).isoformat(),
    "target_dir": target_dir,
    "scope_file": scope,
    "scope_contract": scope_contract,
    "allow_no_scope": allow_no_scope == "1",
    "live_hosts_count": live_hosts_count,
    "candidate_count": candidate_count,
    "artifacts": {
        "hunters_report": report,
        "candidates_jsonl": candidates,
    },
}

Path(manifest).write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

# ── cmd: submit-checklist ──────────────────────────────────────
cmd_submit_checklist() {
  local PLATFORM="${1:-}"
  [ -z "$PLATFORM" ] && { err "usage: bbflow submit-checklist <hitcon|twcert>"; exit 1; }
  PLATFORM=$(echo "$PLATFORM" | tr '[:upper:]' '[:lower:]')

  case "$PLATFORM" in
    hitcon|zd|zeroday)
      cat <<'EOF'
== HITCON ZeroDay 送件前檢查 ==

[欄位與格式]
- 標題需用 {組織名稱} 包起來（平台會遮蔽）。
- 只有「敘述(detail)」欄位支援 Markdown；其他欄位用純文字。
- 類型/風險請按已驗證證據填，不用理論最壞情境硬拉高。

[敘述內容]
- 建議結構：漏洞概述 / 重現步驟 / 已驗證影響(Verified) / 潛在影響(Potential) / 修補建議。
- 重現步驟要可直接執行（含完整 curl/URL/參數）。
- 未 live verify 的內容需明確標示為條件式（若...則...）。

[圖片與附件]
- 平台實務上常要求上傳圖片，建議至少 1 張（最多 10 張，並符合大小限制）。
- 在敘述內用 {{IMG#1}}、{{IMG#2}} 引用對應圖片。
- README/清單提到的檔案必須都存在，避免 triager 找不到。

[內容清理]
- 外送版本禁止內部追蹤代碼（例如 TP-001、內部 advisory 編號）。
- 避免貼出可直接濫用的有效帳密；必要時遮蔽敏感值。
- 送前先做 duplicate/prior-art 比對，避免重複回報。
EOF
      ;;
    twcert|cve)
      cat <<'EOF'
== TWCERT/CVE 送件前檢查 ==

[是否適合申請 CVE]
- 優先確認受影響版本為「使用者可控制」產品（client/firmware/on-prem）。
- 純 SaaS 且使用者無法自行修補/緩解，通常不符合 CVE 發放條件。

[欄位完整性]
- 產品名稱、版本、廠商、官網、發現日期、CWE、CVSS 向量必填。
- 漏洞描述要寫清楚：觸發條件、觸發方法、所需權限、C/I/A 影響。
- 明確標記驗證日期與測試平台（如 Windows/macOS 差異）。

[Rule 3 拆分原則]
- 若 Bug A 修補時會一起修掉 Bug B，傾向合併為同一漏洞。
- 可獨立修補、獨立觸發的路徑，再考慮拆成多筆。
- 不確定是否可獨立修補時，先按同一漏洞處理並在說明註記。

[內容清理]
- 外送附件禁止內部追蹤代碼（TP-xxx、內部 pipeline ID）。
- 附件清單與 ZIP 實際內容逐一比對，避免引用不存在檔案。
- 影響描述維持可驗證事實，推測場景要用條件式描述。
EOF
      ;;
    *)
      err "unknown platform: $PLATFORM (use: hitcon or twcert)"
      exit 1
      ;;
  esac
}

# ── cmd: recon ────────────────────────────────────────────────
cmd_recon() {
  local T="$1"; shift
  local OSMEDEUS=0 SCOPE_FILE="" ALLOW_NO_SCOPE=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --osmedeus) OSMEDEUS=1; shift;;
      --scope-file|--scope) SCOPE_FILE="$2"; shift 2;;
      --allow-no-scope) ALLOW_NO_SCOPE=1; shift;;
      *) shift;;
    esac
  done

  local DIR="$BASE_DIR/workshop/$T"
  ensure_scope "$T" "$DIR" "$SCOPE_FILE" "$ALLOW_NO_SCOPE" "recon"

  mkdir -p "$DIR/bbot"
  local LIVE="$DIR/bbot/live_hosts.txt"
  local SUBS="$DIR/bbot/subdomains.txt"

  if [ "$OSMEDEUS" = "1" ]; then
    local VPS="${OSMEDEUS_VPS:-}"
    [ -z "$VPS" ] && { err "OSMEDEUS_VPS not set"; exit 1; }
    local QT
    QT="$(printf '%q' "$T")"
    local REMOTE_ROOT="${BBFLOW_REMOTE_ROOT:-~/bbflow}"
    case "$REMOTE_ROOT" in
      *[!A-Za-z0-9_./~+-]*)
        err "unsafe BBFLOW_REMOTE_ROOT: $REMOTE_ROOT"
        exit 1
        ;;
    esac
    info "Osmedeus bbflow-safe scan on $VPS ($REMOTE_ROOT)..."
    ssh "$VPS" "cd $REMOTE_ROOT && if [ -x tools/vps/bbflow-vps.sh ]; then tools/vps/bbflow-vps.sh standard $QT; else osmedeus run -f bbflow-safe -t $QT --timeout 2h; fi" 2>&1 | tail -5
    scp -q "$VPS:~/workspaces-osmedeus/$T/subdomain/subdomain-$T.txt" "$SUBS" 2>/dev/null || \
      scp -q "$VPS:~/.osmedeus/workspaces/$T/module/subdomain-enumeration/final-subdomain.txt" "$SUBS" 2>/dev/null || true
    scp -q "$VPS:~/workspaces-osmedeus/$T/probing/http-$T.txt" "$LIVE.raw" 2>/dev/null || \
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
  # First positional arg is target name — unless it starts with '--'
  local T=""
  if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
    T="$1"; shift
  fi

  local ONLY="" LIST_FILE="" SCOPE_FILE="" ALLOW_NO_SCOPE=0 PROBE=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --only)      ONLY="$2";      shift 2;;
      --list|-l)   LIST_FILE="$2"; shift 2;;
      --name|-n)   T="$2";         shift 2;;
      --scope-file|--scope) SCOPE_FILE="$2"; shift 2;;
      --allow-no-scope) ALLOW_NO_SCOPE=1; shift;;
      --probe)     PROBE=1;        shift;;
      *)           shift;;
    esac
  done

  if [ -n "$LIST_FILE" ] && [ -z "$T" ]; then
    T="list_$(basename "$LIST_FILE" .txt | tr ' /' '__')"
  fi
  [ -z "$T" ] && { err "usage: bbflow hunt <target> [--scope-file SCOPE.md] [--only h1,...]  OR  bbflow hunt --list <file> --scope-file SCOPE.md [--name <slug>] [--probe]"; exit 1; }

  local DIR="$BASE_DIR/workshop/$T"
  local LIVE="$DIR/bbot/live_hosts.txt"
  ensure_scope "$T" "$DIR" "$SCOPE_FILE" "$ALLOW_NO_SCOPE" "hunt"

  # ── --list mode: normalize input → live_hosts.txt ─────────────
  if [ -n "$LIST_FILE" ]; then
    [ ! -f "$LIST_FILE" ] && { err "--list: file not found: $LIST_FILE"; exit 1; }
    local ABS_LIST
    ABS_LIST="$(cd "$(dirname "$LIST_FILE")" && pwd)/$(basename "$LIST_FILE")"

    mkdir -p "$BASE_DIR/workshop/$T/bbot" "$BASE_DIR/workshop/$T/hunters"

    # Normalise: bare domain/IP → https://; strip trailing slash; dedup
    python3 - "$ABS_LIST" > "$BASE_DIR/workshop/$T/bbot/live_hosts.txt" <<'NORM'
import re, sys
path = sys.argv[1]
seen = set()
for raw in open(path):
    h = raw.strip()
    if not h or h.startswith('#'):
        continue
    if not re.match(r'^https?://', h):
        h = 'https://' + h
    h = h.rstrip('/')
    if h not in seen:
        seen.add(h)
        print(h)
NORM

    local NORM_COUNT
    NORM_COUNT=$(wc -l < "$BASE_DIR/workshop/$T/bbot/live_hosts.txt" | tr -d ' ')
    info "list: $NORM_COUNT hosts normalised from $ABS_LIST → workshop/$T/bbot/live_hosts.txt"

    # Optional live probe (httpx / curl fallback)
    if [ "$PROBE" = "1" ]; then
      info "probing $NORM_COUNT hosts for live HTTP..."
      local PROBE_IN="$BASE_DIR/workshop/$T/bbot/live_hosts.txt"
      local PROBE_OUT="$BASE_DIR/workshop/$T/bbot/live_hosts_probed.txt"
      if [ -n "$HTTPX" ]; then
        "$HTTPX" -l "$PROBE_IN" -silent -threads 50 -timeout 8 -o "$PROBE_OUT" 2>/dev/null || true
      else
        while read -r H; do
          local C
          C=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$H/" 2>/dev/null)
          [[ "$C" =~ ^[234] ]] && echo "$H" >> "$PROBE_OUT"
        done < "$PROBE_IN"
      fi
      if [ -s "$PROBE_OUT" ]; then
        mv "$PROBE_OUT" "$PROBE_IN"
        ok "probe: $(wc -l < "$PROBE_IN" | tr -d ' ') live hosts after probing"
      else
        warn "probe: no live hosts found — keeping original $NORM_COUNT entries"
      fi
    fi
  fi

  # Auto-seed live_hosts.txt from target name when no recon / --list was run
  if [ ! -s "$LIVE" ] && [ -z "$LIST_FILE" ]; then
    mkdir -p "$DIR/bbot"
    local SEED
    [[ "$T" =~ ^https?:// ]] && SEED="$T" || SEED="https://$T"
    echo "$SEED" > "$LIVE"
    info "no recon data — hunting single host: $SEED"
  fi

  [ ! -s "$LIVE" ] && { err "no live hosts — this should not happen"; exit 1; }
  mkdir -p "$DIR/hunters"

  local REPORT="$DIR/HUNTERS_REPORT_$(date +%Y%m%d_%H%M).md"
  local LIVE_N=$(wc -l < "$LIVE" | tr -d ' ')

  local SCOPE_LINE=""
  [ -f "$DIR/SCOPE.md" ] && SCOPE_LINE="Scope: $DIR/SCOPE.md"

  cat > "$REPORT" <<EOF
# Hunters Report — $T
Date: $(date '+%Y-%m-%d %H:%M')
Live hosts: $LIVE_N
${SCOPE_LINE}

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
  run_hunter jwt           "$TOOLS_DIR/hunters/hunt-jwt.sh"                  host
  run_hunter open-redirect "$TOOLS_DIR/hunters/hunt-open-redirect.sh"        host
  run_hunter config-leak   "$TOOLS_DIR/hunters/hunt-config-leak.sh"          host
  run_hunter weak-login    "$TOOLS_DIR/hunters/hunt-weak-login.sh"           host
  run_hunter backup-files  "$TOOLS_DIR/hunters/hunt-backup-files.sh"         host
  run_hunter nuclei-deep   "$TOOLS_DIR/hunters/hunt-nuclei-deep.sh"          host
  run_hunter waf-bypass    "$TOOLS_DIR/hunters/hunt-waf-bypass.sh"           host
  run_hunter version-json  "$TOOLS_DIR/hunters/hunt-version-json.sh"         host
  run_hunter cert-bypass   "$TOOLS_DIR/hunters/hunt-cert-bypass.sh"          host
  run_hunter monitor-bypass "$TOOLS_DIR/hunters/hunt-monitor-bypass.sh"      host
  run_hunter sms-static-cred "$TOOLS_DIR/hunters/hunt-sms-static-cred.sh"   host
  run_hunter git-deep      "$TOOLS_DIR/hunters/hunt-git-deep.sh"             host
  run_hunter swagger       "$TOOLS_DIR/hunters/hunt-swagger.sh"              host
  run_hunter shodan-ip     "$TOOLS_DIR/hunters/hunt-shodan-ip.sh"            host
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

  # ── domain-level hunters（ROOT_DOMAIN 推斷，不走 live_hosts 迴圈）─────────────
  # ROOT_DOMAIN: 從 live_hosts.txt 第一行 URL 取出 eTLD+1
  local ROOT_DOMAIN
  ROOT_DOMAIN=$(head -1 "$LIVE" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | \
    sed 's/^www\.//' | rev | cut -d. -f1-2 | rev)

  if want subdomain-prefix; then
    info "hunter: subdomain-prefix (active prefix sweep for $ROOT_DOMAIN)"
    local OH="$DIR/hunters/subdomain-prefix"
    mkdir -p "$OH"
    export OUT_DIR="$OH"
    KNOWN_SUBS_FILE=""
    [ -f "$DIR/bbot/subdomains.txt" ] && KNOWN_SUBS_FILE="$DIR/bbot/subdomains.txt"
    "$TOOLS_DIR/hunters/hunt-subdomain-prefix.sh" "$ROOT_DOMAIN" "$KNOWN_SUBS_FILE" 2>/dev/null || true
    local HITS
    HITS=$(grep -h "^🔴" "$OH"/*.txt 2>/dev/null | sort -u || true)
    echo "" >> "$REPORT"; echo "## subdomain-prefix" >> "$REPORT"
    [ -n "$HITS" ] && echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done || \
      echo "- (no new subdomains found)" >> "$REPORT"
    unset OUT_DIR
  fi

  if want hudson-rock; then
    info "hunter: hudson-rock (breach corpus for $ROOT_DOMAIN)"
    local OH="$DIR/hunters/hudson-rock"
    mkdir -p "$OH"
    export OUT_DIR="$OH"
    "$TOOLS_DIR/hunters/hunt-hudson-rock.sh" "$ROOT_DOMAIN" 2>/dev/null || true
    local HITS
    HITS=$(grep -h "^🔴\|^🟠" "$OH"/*.txt 2>/dev/null | sort -u || true)
    echo "" >> "$REPORT"; echo "## hudson-rock" >> "$REPORT"
    [ -n "$HITS" ] && echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done || \
      echo "- (no breach records found)" >> "$REPORT"
    unset OUT_DIR
  fi

  if want email-security; then
    info "hunter: email-security (SPF/DMARC/DKIM audit for $ROOT_DOMAIN)"
    local OH="$DIR/hunters/email-security"
    mkdir -p "$OH"
    export OUT_DIR="$OH"
    "$TOOLS_DIR/hunters/hunt-email-security.sh" "$ROOT_DOMAIN" 2>/dev/null || true
    local HITS
    HITS=$(grep -h "^🔴\|^🟠\|^🟡" "$OH"/*.txt 2>/dev/null | sort -u || true)
    echo "" >> "$REPORT"; echo "## email-security" >> "$REPORT"
    [ -n "$HITS" ] && echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done || \
      echo "- (no email security issues found)" >> "$REPORT"
    unset OUT_DIR
  fi

  if want cloud-bucket; then
    info "hunter: cloud-bucket (S3/GCS/Azure for $ROOT_DOMAIN)"
    local OH="$DIR/hunters/cloud-bucket"
    mkdir -p "$OH"
    export OUT_DIR="$OH"
    "$TOOLS_DIR/hunters/hunt-cloud-bucket.sh" "$ROOT_DOMAIN" 2>/dev/null || true
    local HITS
    HITS=$(grep -h "^🔴\|^🟠" "$OH"/*.txt 2>/dev/null | sort -u || true)
    echo "" >> "$REPORT"; echo "## cloud-bucket" >> "$REPORT"
    [ -n "$HITS" ] && echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done || \
      echo "- (no exposed buckets found)" >> "$REPORT"
    unset OUT_DIR
  fi

  if want wayback; then
    info "hunter: wayback-endpoints (CDX historical paths for $ROOT_DOMAIN)"
    local OH="$DIR/hunters/wayback"
    mkdir -p "$OH"
    export OUT_DIR="$OH"
    KNOWN_PATHS_FILE=""
    [ -f "$DIR/RECON_DB.md" ] && KNOWN_PATHS_FILE="$DIR/RECON_DB.md"
    "$TOOLS_DIR/hunters/hunt-wayback-endpoints.sh" "$ROOT_DOMAIN" 2>/dev/null || true
    local HITS
    HITS=$(grep -h "^🔴\|^🟡" "$OH"/*.txt 2>/dev/null | sort -u || true)
    echo "" >> "$REPORT"; echo "## wayback-endpoints" >> "$REPORT"
    [ -n "$HITS" ] && echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done || \
      echo "- (no high-value historical paths found)" >> "$REPORT"
    unset OUT_DIR
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

  # ── crawl-chain: 完整 URL/param discovery + fuzzing (10 stages) ──
  if want crawl-chain; then
    info "hunter: crawl-chain (katana+gau+paramspider → uro+gf → arjun → nuclei DAST → dalfox)"
    local CC_OH="$DIR/hunters/crawl-chain"
    mkdir -p "$CC_OH"
    echo "" >> "$REPORT"
    echo "## crawl-chain" >> "$REPORT"
    local CC_ALL_HITS="$CC_OH/all_hits.txt"
    > "$CC_ALL_HITS"
    while IFS= read -r HOST; do
      [ -z "$HOST" ] && continue
      local SLUG
      SLUG=$(echo "$HOST" | sed -E 's|^https?://||' | tr '/:.' '_')
      local CC_SUBDIR="$CC_OH/$SLUG"
      mkdir -p "$CC_SUBDIR"
      export OUT_DIR="$CC_SUBDIR"
      "$TOOLS_DIR/hunters/hunt-crawl-chain.sh" "$HOST" 2>/dev/null \
        | grep "^🔴" >> "$CC_ALL_HITS" || true
    done < "$LIVE"
    if [ -s "$CC_ALL_HITS" ]; then
      local CC_COUNT
      CC_COUNT=$(wc -l < "$CC_ALL_HITS" | tr -d ' ')
      echo "- $CC_COUNT hits → $CC_ALL_HITS" >> "$REPORT"
      while IFS= read -r L; do echo "- $L" >> "$REPORT"; done < "$CC_ALL_HITS"
      ok "  crawl-chain hits: $CC_COUNT"
    else
      local TOTAL_PU
      TOTAL_PU=$(cat "$CC_OH"/*/param_urls.txt 2>/dev/null | wc -l | tr -d ' ')
      echo "- 0 hits ($TOTAL_PU parameterized URLs collected)" >> "$REPORT"
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
  if want portscan; then
    info "hunter: portscan (rustscan → nmap service detection)"
    local OH="$DIR/hunters/portscan"
    mkdir -p "$OH"
    echo "" >> "$REPORT"; echo "## portscan" >> "$REPORT"
    while IFS= read -r HOST; do
      [ -z "$HOST" ] && continue
      export OUT_DIR="$OH"
      "$TOOLS_DIR/hunters/hunt-portscan.sh" "$HOST" 2>/dev/null || true
    done < "$LIVE"
    local HITS
    HITS=$(grep -h "^🔴\|^🟡" "$OH"/*.txt 2>/dev/null | sort -u || true)
    if [ -n "$HITS" ]; then
      echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done
      echo "${G}  hits:$(echo "$HITS" | wc -l | tr -d ' ')${N}"
    else
      echo "- (no open ports / nmap not installed)" >> "$REPORT"
    fi
  fi

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

  local SCOPE_PATH=""
  [ -f "$DIR/SCOPE.md" ] && SCOPE_PATH="$DIR/SCOPE.md"
  write_run_manifest "$T" "hunt" "$DIR" "$REPORT" "$LIVE" "$SCOPE_PATH" "$ALLOW_NO_SCOPE"
  ok "report → $REPORT"
  ok "manifest → $DIR/run_manifest.json"
  ok "candidates → $DIR/candidates.jsonl"
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
  # --list mode: skip recon, go straight to hunt
  if [[ "${1:-}" == --list ]] || [[ "${2:-}" == --list ]]; then
    cmd_hunt "$@"
    return
  fi
  local T="$1"
  cmd_init "$T"
  cmd_recon "$@"
  cmd_hunt "$@"
}

# ── cmd: status ──────────────────────────────────────────────
cmd_status() {
  local T="${1:-}"
  if [ -z "$T" ]; then cmd_list; return; fi
  local DIR="$BASE_DIR/workshop/$T"
  [ ! -d "$DIR" ] && { err "no such target"; exit 1; }
  echo "${B}$T${N}"
  [ -f "$DIR/SCOPE.md" ] && ok "SCOPE.md ($(wc -l < $DIR/SCOPE.md | tr -d ' ') lines)" || warn "SCOPE.md not set (optional for hunt)"
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
  test_h jwt           "$TOOLS_DIR/hunters/hunt-jwt.sh"                   "https://example.com"
  test_h open-redirect "$TOOLS_DIR/hunters/hunt-open-redirect.sh"         "https://example.com"
  test_h takeover      "$TOOLS_DIR/hunters/hunt-subdomain-takeover.sh"    "nonexistent-subdomain.example.com"
  test_h nxdomain      "$TOOLS_DIR/hunters/hunt-nxdomain-corpus.sh"       "example.com"
  test_h gkey          "$TOOLS_DIR/hunters/hunt-google-api-key.sh"        "AIzaSyFAKEKEY_ForSmokeTest_AAAAAAAAAAAAA"
  test_h arjun-params  "$TOOLS_DIR/hunters/hunt-arjun-params.sh"          "https://example.com"
  test_h config-leak   "$TOOLS_DIR/hunters/hunt-config-leak.sh"           "https://example.com"
  test_h weak-login    "$TOOLS_DIR/hunters/hunt-weak-login.sh"            "https://example.com"
  test_h backup-files  "$TOOLS_DIR/hunters/hunt-backup-files.sh"          "https://example.com"
  # param-fuzz / dalfox-xss / trufflehog / portscan: require external tools or network access
  # — skipped in null-case regression; run manually: bbflow hunt --only param-fuzz,portscan target
  rm -rf "$TMP"
  local TOTAL=20
  echo ""
  if [ "$FAIL" = "0" ]; then
    ok "all $TOTAL null-case hunters passed (0 FP on example.com)"
  else
    err "$FAIL/$TOTAL hunter(s) produced unexpected hits — investigate"
    exit 1
  fi
}

# ── cmd: dedupe (compare hits against prior submitted reports) ──
cmd_dedupe() {
  local T="$1"
  [ -z "$T" ] && { err "usage: bbflow dedupe <target>"; exit 1; }
  local DIR="$BASE_DIR/workshop/$T"
  [ ! -d "$DIR/hunters" ] && { err "no hunters output for $T (run: bbflow hunt $T)"; exit 1; }

  echo "${B}== dedupe check: $T ==${N}"
  local ALL_HITS
  ALL_HITS=$(grep -h "^🔴" "$DIR/hunters"/*/*.txt 2>/dev/null | sort -u)
  if [ -z "$ALL_HITS" ]; then
    info "no hits to dedupe"; return
  fi

  # Sources to compare against: HITCON_ZeroDay_Reports/submited/, workshop/*/submited/, workshop/*/reports/
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
  submit-checklist) cmd_submit_checklist "$@";;
  test)           cmd_test;;
  dedupe)         cmd_dedupe "$@";;
  nuclei-update)  cmd_nuclei_update;;
  help|-h|--help|"") usage;;
  *) err "unknown subcommand: $SUB"; usage; exit 1;;
esac
