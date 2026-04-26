# Changelog

All notable changes to bbflow will be documented in this file.

Format loosely follows [Keep a Changelog](https://keepachangelog.com/),
versioning follows [Semantic Versioning](https://semver.org/).

## [1.4.0] — 2026-04-25

### Added — WAF-friendly low-noise wave (+6 hunters → 28 total)

For government / firewall-protected targets where bursts trigger blocks. Each
new hunter tuned for **single-shot validation** (1 request / path) and
content-based confirmation (no "HTTP 200 = hit").

- `hunt-config-leak.sh` — 100+ static config paths (.git/.env/Actuator/Swagger/
  WEB-INF/SCM/IDE/debug consoles); each path single GET + content match;
  `FAST=1` mode runs only 24 P1/P2 high-confidence paths
- `hunt-weak-login.sh` — Default credential validation for 25+ vendor panels
  (Nacos/Druid/Grafana/Jenkins/phpMyAdmin/Tomcat Manager/Solr Admin/RabbitMQ/
  Kibana/Jeecg/Jeesite/SpringBoot Admin/Apollo/GitLab/Gitea/Portainer/Rancher/
  Harbor/Nexus/SonarQube/Weblogic/Zabbix/Shiro/Airflow/Superset/Metabase/
  Couchbase). Each vendor 1–3 login requests; HEAD/GET pre-check; differential
  body pattern match (not just 2xx)
- `hunt-backup-files.sh` — 40 static backup names + dynamic candidates from
  hostname (target.com.zip / target.tar.gz / target.sql) + Index-of fallback
  (/backup/, /backups/, /bak/, /db/, /upload/); content-type + size dual
  verification (avoids SPA HTML 200 false positives)
- `hunt-nuclei-deep.sh` — Per-category nuclei scans (XSS/SQLi/SSRF/LFI/RCE/
  Path Traversal/Info Leak/Debug/Weak login/Default cred/Exposed panels/
  Misconfig/CVE/Takeover/CORS/Open Redirect/SSTI/XXE). `CATEGORY=` env var
  to scope to one class. Auto-integrates `bb-recon` custom templates if present
- `hunt-waf-bypass.sh` — wafw00f fingerprint + 15+ bypass techniques (path
  case mutation / nullbyte / unicode / chunked encoding / Origin header /
  X-Forwarded-For); records bypass paths for downstream hunters; `ORIGIN_IP=`
  env for direct-origin bypass
- `hunt-crawl-chain.sh` — 10-stage URL discovery and DAST chain
  (katana → gau → waybackurls → paramspider → hakrawler → uro dedup →
  gf classify → arjun hidden params → nuclei DAST per gf class → dalfox
  XSS deep). End-to-end fuzz pipeline for SPAs / API endpoints

### Changed
- bbflow.sh `hunt` loop now dispatches 19 base hunters via `run_hunter` +
  9 special-handling hunters (subdomain-takeover with file fallback,
  nxdomain-corpus, param-fuzz, crawl-chain, dalfox-xss, arjun-params,
  trufflehog-secrets, portscan, ffuf-dirs)
- README.md hunter count: 22 → 28
- `hunters/README.md` extended with 6 new sections + decision rules

### Lessons learned baked into hunters
- WAF-protected gov sites burn doctor commands → noise budget matters
- 200 OK ≠ vulnerable hit (every new hunter validates body content)
- Index-of fallback catches what static-name probing misses

## [1.3.0] — 2026-04-23

### Added
- `hunt-param-fuzz.sh` — Standalone parameter-fuzzing pipeline (katana JS-aware
  crawl depth 3 → gau / waybackurls / Wayback CDX → uro dedup → nuclei --dast
  XSS/SQLi/SSRF/LFI/SSTI/Open-redirect)
- bbflow.sh hunt loop now special-cases param-fuzz (per-host iteration)

## [1.2.0] — 2026-04-21

### Added
- `hunt-portscan.sh` — rustscan (fast SYN) → nmap (service/version on open
  ports). Falls back to nmap-only if rustscan not installed
- bbflow.sh hunt loop now invokes portscan per host
- Fix: `hunt-jwt.sh` was missing from default hunt loop (now included)

## [1.1.0] — 2026-04-19

### Added — Modern fuzzing stack integration (+4 hunters → 21 total)

- `hunt-dalfox-xss.sh` — katana + gau URL collection → gf xss filter →
  dalfox pipe scan (Reflected + Blind via DALFOX_BLIND_URL/interactsh +
  custom DALFOX_PAYLOADS file). Authenticated via DALFOX_COOKIE env
- `hunt-arjun-params.sh` — Hidden GET/POST/JSON parameter discovery using
  SecLists `burp-parameter-names.txt` (>6000 params). JSON output for
  structured parsing. `ARJUN_HEADERS` / `ARJUN_COOKIES` for authenticated
  scanning; passive mode (history-only) supported
- `hunt-trufflehog-secrets.sh` — Deep .git history scan (100+ detectors:
  AWS/GCP/GitHub/Stripe/SendGrid/...) on already-dumped git-dumper output.
  `--only-verified` filter for high-confidence secrets only
- `hunt-ffuf-dirs.sh` — 3-tier directory scanning (BB-high-ROI list →
  SecLists raft-medium → API endpoints). Auto 404-size detection (`-fs`),
  word-count filter (`-fw`), recursion on interesting paths.
  `FFUF_COOKIE` / `FFUF_HEADERS` for authenticated dirs
- `gf` pattern integration for downstream classification

### Changed
- bbflow.sh hunt loop now dispatches modern fuzzing tools per host
- `WORKFLOW.md` updated with crawl-chain integration examples

## [1.0.0] — 2026-04-15

### Initial release

**Core CLI** (`bbflow.sh`)
- `doctor` — 依賴 + hunter 路徑檢查
- `test` — regression null-case smoke test（14 hunters × example.com）
- `init <target>` — scope-first 強制建立 SCOPE.md 模板
- `recon <target> [--osmedeus]` — BBOT passive 或 Osmedeus VPS recon
- `hunt <target> [--only h1,...]` — 對 live_hosts.txt 批次跑 hunters
- `flow <target>` — init + recon + hunt 一條龍
- `dedupe <target>` — 對比已送報告找重複
- `list` / `status` / `scope` / `report`

**16 Pattern hunters** (`hunters/`)
- `hunt-hybris-occ.sh` — SAP Hybris OCC default OAuth creds + baseSites + anonymous cart + GUID IDOR + configParam API keys
- `hunt-envdata.sh` — `window.envData` / `defineProperty` / `__INITIAL_STATE__` / `ssInlineConfig` 提取 + AWS/Google/Sentry/Mapbox 密鑰 grep
- `hunt-sourcemap-secrets.sh` — `.js.map` 暴露 + `sourcesContent` 內 API key/Bearer/Stripe/JWT grep
- `hunt-hardcoded-js-secrets.sh` — live `.js` bundle 19 種硬編碼密鑰 pattern（AWS/AIza/GitHub/Stripe/Slack/JWT/Sentry/Mapbox/Twilio/clientSecret）
- `hunt-cors-reflect.sh` — 四層反射 CORS：arbitrary / null / regex prefix bypass / suffix bypass + credentials:true 判斷
- `hunt-graphql-idor.sh` — 無認證 `__typename` + introspection + field suggestion + list query + integer ID IDOR 序列探測
- `hunt-user-enum.sh` — GET/POST validate_email differential + password reset + 20-req rate limit
- `hunt-git-exposure.sh` — `.git/HEAD` 多路徑探測（root + robots.txt + common CMS subpaths）+ `.git/config` remote URL + `--dump` 三工具 pipeline + credential grep
- `hunt-subdomain-takeover.sh` — CNAME lookup + 20+ vendor fingerprint（S3/GitHub Pages/Heroku/Shopify/Fastly/Azure/...）+ claimability 判斷
- `hunt-open-redirect.sh` — 20 redirect param × 9 bypass 變體 + 常見 OAuth/logout 路徑
- `hunt-jwt.sh` — JWT decode + `alg:none` 端點測試 + HS256 weak secret brute + exp 檢查 + kid/jku/x5u injection surface
- `hunt-devops-unauth.sh` — 40+ DevOps 工具無認證路徑（Harbor/ArgoCD/Jenkins/Grafana/Prometheus/Kibana/Consul/etcd/K8s/Docker Registry/Gitea/GitLab/SonarQube/Nexus/Artifactory/Rancher/Portainer/Vault/Traefik/Rundeck）
- `hunt-actuator-deep.sh` — Spring Boot Actuator 深度：`/env` propertySources + `/configprops` + `/mappings` + `/beans` + `/httptrace` + `/loggers` + `/jolokia` + `--heapdump` + strings grep
- `hunt-mcp-oauth-scope.sh` — RFC 8414 OAuth discovery + MCP JSON-RPC probe + `MCP_TOKEN` 認證後比對 consent screen vs 實際 write-level tool 差異
- `hunt-google-api-key.sh` — 對 `AIza*` key 測 16 個 Google 服務可用性（Maps/Places/Vision/Translate/YouTube/Firebase/Identity Toolkit/FCM）+ 自動 severity hint
- `hunt-nxdomain-corpus.sh` — BBOT passive + crt.sh + waymore 歷史 hostname 超集 → 反向 NXDOMAIN 過濾 → Host-header payload 候選

**Tooling**
- `install.sh` — 跨平台依賴安裝器（macOS brew / Debian apt / RHEL dnf / Arch pacman / Alpine apk）
- `ci.sh` — 本地 CI：bash syntax / python heredoc / doctor / test / file permissions / docs alignment / secret scan / 選用 target-fingerprint scan（via `.ci-fingerprints`）
- `bbot_preset_bugbounty.yml` — BBOT preset（subdomain-enum + cloud-enum + baddns + badsecrets）
- `.git/hooks/pre-push` — 可用 `./ci.sh --install-hook` 自動安裝

**Documentation**
- `README.md` — 專案總覽 + 16 hunter 對照表 + 目錄結構
- `WORKFLOW.md` — 完整工作流程文件
- `hunters/README.md` — 每個 hunter 的範例輸出 + P1–P5 決策規則 + 失敗模式
- `CONVENTIONS.md` — 貢獻規範（禁止進入 repo 的內容 + 撰寫流程 + 違規處理）
- `CONTRIBUTING.md` — 貢獻流程
- `LICENSE` — MIT + legal disclaimer
- `CHANGELOG.md` — 本檔案

### Design principles

1. **Zero LLM dependency** — 純 `bash + curl + python3 stdlib + dig`，可 cron / VPS / offline 跑
2. **Pattern hunters, not target-specific** — hunter 的邏輯對任何目標都適用
3. **Scope-first enforcement** — `bbflow recon` 沒 SCOPE.md 會拒絕
4. **Differential / state-based validation** — 不做盲 fuzzing，只做條件判斷
5. **Target-agnostic open source** — repo 不含任何真實 credential / target-specific info
