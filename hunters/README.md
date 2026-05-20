# Hunters — Pattern-Specific Vulnerability Probes

零 LLM 依賴的漏洞驗證腳本。每個 hunter 對應過往成功案例的完整驗證鏈，純 `curl + python3 stdlib + bash`。

## 設計原則

1. **BBOT / Osmedeus 做 recon**（子域名、存活、技術指紋、cloud bucket、badsecrets）
2. **Hunters 消費 workshop 輸出**（`workshop/<target>/bbot/live_hosts.txt`）
3. **每個 hunter 對應一個確認有 bounty 的 pattern**
4. **沒有猜測、沒有 LLM — 只有 curl + 條件判斷 + differential**

## Safety / VPS Gate

完整規範見 [`../BBFLOW_OPERATIONS.md`](../BBFLOW_OPERATIONS.md)。

- `bbflow recon` / `bbflow hunt` / `bbflow flow` 預設 **VPS required**。
- `osmedeus` 一律 **VPS required**；本機只設定 `OSMEDEUS_VPS` 讓 wrapper 透過 SSH 在 VPS 執行。
- Local OK 僅限 `bbflow doctor/status/list/scope/report/dedupe/init`、讀既有 `workshop/<target>` 輸出、寫報告。
- 自動化掃描不用逐條記每個 request，但要在 `workshop/<target>/RECON_DB.md ## 📋 Operation Log` 記錄掃描開始/結束、來源 VPS IP、命令與輸出路徑。

## Hunter 對照表

| Hunter | 來源案例 | 驗證什麼 |
|--------|---------|---------|
| `hunt-hybris-occ.sh` | **SAP Hybris OCC pattern**（workshop/target-example） | SAP Hybris OCC default OAuth creds + anonymous baseSites + anonymous cart create + GUID IDOR + configParam API keys |
| `hunt-envdata.sh` | **SPA inline window config pattern** | `window.envData` / `__INITIAL_STATE__` / `ssInlineConfig` 提取 + AWS/Google/Sentry/Mapbox 密鑰 grep |
| `hunt-sourcemap-secrets.sh` | **multi-brand SSO / disclosed source map cases** | `.js.map` 暴露 + `sourcesContent` 內 API key / Bearer / Stripe / JWT grep |
| `hunt-cors-reflect.sh` | **reflective CORS pattern** (public writeup) | 四層反射 CORS：arbitrary / null / regex prefix bypass / suffix bypass + credentials:true 判斷 |
| `hunt-graphql-idor.sh` | **public GraphQL IDOR writeup** | 無認證 `__typename` + introspection + field suggestion + 常見 list query + integer ID IDOR 序列探測 |
| `hunt-user-enum.sh` | **multi-brand SSO + differential response pattern** | GET/POST validate_email + password reset differential + 大小寫測試 + 20req 無 rate limit 確認 |
| `hunt-git-exposure.sh` | **nested .git exposure via CMS subpaths** | `.git/HEAD` 多路徑探測（root + robots.txt disallow + 常見 CMS subpath）+ `.git/config` remote URL → 供應鏈分析 + `--dump` 三工具 pipeline + credential grep |
| `hunt-subdomain-takeover.sh` | **CNAME → vendor fingerprint** | CNAME lookup + 20+ vendor fingerprint（S3/GitHub Pages/Heroku/Shopify/Fastly/Azure/Bitbucket/...）+ claimability 判斷 |
| `hunt-open-redirect.sh` | **OAuth redirect_uri chain (public pattern)**（OAuth token theft chain）| 20 個 redirect param name × 9 種 bypass 變體（arbitrary/protocol-relative/backslash/ampersand/subdomain/userinfo...）+ 對常見 OAuth/logout 路徑測試 |
| `hunt-jwt.sh` | **generic** | JWT decode + alg:none / empty sig endpoint 測試 + HS256 weak secret brute + exp 狀態 + kid/jku/x5u injection surface + alg confusion |
| `hunt-devops-unauth.sh` | **public DevOps console leak pattern** | 40+ DevOps 工具無認證路徑：Harbor/ArgoCD/Jenkins/Grafana/Prometheus/Kibana/Consul/etcd/K8s/Docker Registry/Gitea/GitLab/SonarQube/Nexus/Artifactory/Rancher/Portainer/Vault/Traefik/Rundeck |
| `hunt-google-api-key.sh` | **multi-service Google API key pattern** | 對 `AIza*` key 測 16 個 Google 服務可用性（Maps/Geocoding/Places/Directions/Vision/Translate/YouTube/Safe Browsing/Identity Toolkit/FCM...）+ 依類別自動 severity hint |
| `hunt-actuator-deep.sh` | **Spring Boot Actuator deep probe** | Spring Boot Actuator 深度：`/env` propertySources 提取 + `/configprops` + `/mappings` + `/beans` + `/httptrace`（洩漏 cookie/auth header）+ `/loggers` + `/jolokia` JMX + `--heapdump` 下載 + strings grep credentials |
| `hunt-mcp-oauth-scope.sh` | **MCP OAuth scope mismatch pattern** | RFC 8414 OAuth discovery + MCP endpoint probe + JSON-RPC initialize + tools/list + `MCP_TOKEN` 認證後比對 consent screen 宣稱 scope vs 實際 write-level tool 差異 |
| `hunt-hardcoded-js-secrets.sh` | **SPA hardcoded client secret pattern** | 對 live `.js` bundle grep 硬編碼密鑰（和 sourcemap hunter 互補，不需 .map）：AWS/AIza/GitHub/Stripe/Slack/JWT/Sentry/Mapbox/Twilio/clientSecret 等 19 種 pattern |
| `hunt-ssrf-oracle-probe.sh` | **digiwin #76/#121/#122-124 K8s topology mapping**（[[Pattern - Blind SSRF Oracle Technique]]）| 對 SSRF endpoint 跑 5-baseline probe（HTTP_OK / REFUSED / AUTH_TCP / DNS_FAIL / TIMEOUT）+ 比對回應 unique signature → FULL/PARTIAL/WEAK/NONE oracle 分級 + cloud metadata（AWS/GCP/Azure）+ K8s cluster fingerprint。需用戶指定 endpoint（不會 auto-find） |
| `hunt-sourcemap-endpoint-family.sh` | **openfind OF-014 #102 AICS Source Map cascade**（[[Pattern - SourceMap Endpoint Family Disclosure]]）| 與 sourcemap-secrets 互補：抽 **API endpoint family** + baseURL + auth flow clues（localStorage / cookie / Bearer）+ 前端路由 + build-time env；自動 severity hint：≥10 endpoint = P3-P2 / Bearer auth → 配 CORS ACAC pattern 引用 |
| `hunt-cors-reflect.sh` (升級) | **+ auth-mechanism aware**（[[Pattern - CORS ACAC True with Bearer Auth]]）| 在原 4 層反射測試外，自動偵測 Set-Cookie / WWW-Authenticate Bearer / JWT 提示，**Bearer + ACAC:true 自動降級為 misconfig (P4/P5)** 並引用對應 Pattern，避免送高 severity 後被 N/A |
| `hunt-zpush-version.sh` | **openfind OF-015 Z-Push mass-host**（[[Pattern - Vendor Product Multi-Host Enumeration]]）| 對 `/Microsoft-Server-ActiveSync` 抽 X-Zpush-Version header + 解析版本 < 2.7.6 自動標記 CVE-2025-8264 prerequisite；fallback：WWW-Authenticate realm 命中 |
| `hunt-mail2000-pre-cmd.sh` | **openfind OF-013 Mail2000 XSS 22 hosts**（[[Pattern - Vendor Product Multi-Host Enumeration]]）| 對 3 個 M2K CGI 路徑（/cgi-bin/login / /cgi-bin/mbase/mblogin / ?index=1）跑 pre_cmd + job_id 反射測試；≥3 反射 = vuln confirmed；2026-05-13 已對 vip-chief-web.mailcloud.com.tw 獨立 re-confirm 5/5 反射 |
| `hunt-vite-spa-json-config.sh` | **TeamPlus TP-S15 Nan Shan Vite config leak**（[[Pattern - Vite SPA JSON Config Leak]]）| Vite SPA signature 偵測 + 20 種常見 `/json/*.json` `/config/*.json` `/env/*.json` 路徑 probe + Python 後處理：hostname / API endpoint / hardcoded key / env dispatcher map 抽取 |
| `hunt-gitlab-anon.sh` | **TeamPlus rd-gitlab + rd3-gitlab**（[[Pattern - GitLab Anonymous Fingerprinting]]）| `/-/graphql-explorer` 抓 gon.revision exact commit → /api/v4/version + /help fallback；/users/sign_up 開放偵測；7 個 anon info-disclosure endpoint（/help/instance_configuration / /-/jwks / /explore/projects 語言 leak / /api/v4/projects?visibility=internal / /api/v4/users / /api/graphql introspection） |
| `hunt-nxdomain-corpus.sh` | **Starbucks NXDOMAIN**（External Writeups 2026） | 建立歷史 hostname 超集 → 過濾出 NXDOMAIN 候選 → 待遇到 Host-controllable proxy 時當 payload |
| `hunt-param-fuzz.sh` | **DAST fuzzing pattern** | katana + gau + waybackurls URL 收集 → gf filter XSS/SQLi/SSRF → nuclei DAST templates 驗證 |
| `hunt-dalfox-xss.sh` | **Reflected/Blind XSS pattern** | gf xss filter → dalfox 掃描（支援 blind XSS callback + cookie auth）+ payloads/xss-custom.txt |
| `hunt-arjun-params.sh` | **Hidden parameter discovery** | arjun GET/POST/JSON 隱藏參數探索 + SecLists burp-parameter-names（支援認證 header）|
| `hunt-trufflehog-secrets.sh` | **Git history secret scan** | trufflehog git 模式（`--only-verified`）掃 100+ detector：AWS/GitHub/Stripe/GCP/Azure key + config |
| `hunt-ffuf-dirs.sh` | **Directory & file fuzzing** | ffuf 三層 dir fuzzing：raft-medium + BB-ROI wordlist + 副檔名（.bak/.sql/.env/.git）（支援 cookie auth；無 ffuf 自動 fallback 到 feroxbuster）|
| `hunt-portscan.sh` | **Port scan + service detection** | rustscan（快速 port 發現）→ nmap（service/version）；高風險服務：Docker API / Redis / Elasticsearch / MongoDB / Consul 等自動標 🔴 |
| `hunt-config-leak.sh` | **xray rules / 100+ path config 洩漏** | `.git`/`.env`/`actuator`/`swagger`/`phpinfo` 等 100+ 靜態 path + content-match（magic bytes），WAF-friendly，單 GET；`FAST=1` 只跑 P1/P2 |
| `hunt-weak-login.sh` | **管理面板 default creds** | nacos/druid/grafana/jenkins/tomcat/phpmyadmin/zabbix/solr/kibana/cas/harbor/argocd 等管理介面單次 default creds 探測（低噪音） |
| `hunt-backup-files.sh` | **Backup / DB dump 檔** | 41 靜態候選（`backup.zip`/`db.sql`/`.tar.gz`/`.bak`）+ hostname 衍生（`<host>.zip`）+ magic bytes 驗證（PK/GZ/MySQL/BZ2）+ Index-of fallback |
| `hunt-crawl-chain.sh` | **10 階段 URL/param discovery + DAST** | katana + gau + waybackurls + paramspider → uro 去重 → gf 分類（xss/sqli/ssrf/lfi/ssti/redirect）→ arjun 隱藏 param → nuclei DAST → dalfox XSS；`FAST=1` 略 arjun+dalfox |
| `hunt-nuclei-deep.sh` | **擴充 nuclei 攻擊面（18 類別）** | XSS/SQLi/SSRF/LFI/RCE/Redirect/SSTI/XXE/Takeover/CORS/Info/Debug/Panel/WeakLogin/CVE/Misconfig/Cloud/OAST；`CATEGORY=xss,sqli` 指定類別；`FAST=1` 只跑 high/critical |
| `hunt-waf-bypass.sh` | **WAF 繞過自動化測試** | 15+ 技巧自動測：大小寫、`//`、`;`、`%00`、`X-Original-URL`、XFF-127、X-Real-IP、Host localhost、OPTIONS method、HTTP/2、Origin IP 直連；`ORIGIN_IP=1.2.3.4` 自訂 origin，`PATHS=/admin` 自訂路徑 |
| `hunt-version-json.sh` | **環境對映 JSON 洩漏**（EVERY8D TP-S18 pattern） | 9 候選路徑（`/json/version.json`、`/version.json`、`/json/config.json` 等）→ 解析 JSON → 標記 dev/test/UAT key 或 `.cc`/`.local`/RFC1918 value |
| `hunt-cert-bypass.sh` | **SSO /cert 端點無密碼 token 發行**（EVERY8D TP-S32 pattern） | 10 個 cert/token 端點 → POST 假帳號（無密碼）→ 偵測 token 發行 → 二層驗證（token 打 `/announce`/`/isKYC` 等，確認 P1） |

## 使用方式

### 單一 host 驗證

```bash
./tools/hunters/hunt-hybris-occ.sh https://api-example.hashed-staging-s1-public.model-t.cc.commerce.ondemand.com
./tools/hunters/hunt-envdata.sh https://insight.example.com
./tools/hunters/hunt-cors-reflect.sh https://cloudaccess.svc.example.com/devices
```

每個 hunter 輸出 `./[name]_out/<slug>.txt`，`🔴` 開頭的是高信心命中。

### 批次（從 BBOT 輸出）

```bash
cat workshop/<target>/bbot/live_hosts.txt | while read h; do
  ./tools/hunters/hunt-envdata.sh "$h"
done
```

### 全套 orchestration（推薦）

使用 `bbflow` 主 CLI（詳見 [../README.md](../README.md)）：

```bash
bbflow hunt target.com                     # VPS required：對 live hosts 跑全部 hunters → HUNTERS_REPORT.md
bbflow flow target.com                     # VPS required：init + recon + hunt 一條龍
bbflow hunt target.com --only cors,graphql # VPS required：指定 hunters
bbflow hunt --list hosts.txt --probe       # VPS required：清單模式 + live probing
```

## 環境需求

```bash
# 必需
which curl python3 bash dig

# 推薦（有的話 recon 會更完整）
pipx install bbot
which httpx subfinder waymore gau
```

Osmedeus VPS 模式（VPS required）：

```bash
export OSMEDEUS_VPS="user@167.71.x.x"
bbflow recon target.com --osmedeus
```

## 輸出結構

```
workshop/<target>/
├── bbot/
│   ├── subdomains.txt
│   └── live_hosts.txt
├── hunters/
│   ├── envdata/*.txt
│   ├── sourcemap/*.txt
│   ├── cors/*.txt
│   ├── graphql/*.txt
│   ├── userenum/*.txt
│   └── hybris-occ/*.txt
├── nxdomain/
│   ├── historical_all.txt
│   └── nxdomain_corpus.txt
└── HUNTERS_REPORT_YYYYMMDD_HHMM.md
```

## 範例輸出 + 決策規則

每個 hunter 有三種可能結果：
- **🔴 = 高信心命中**（可送件候選）— 經過 differential 或內容驗證
- **🟡 = 需人工確認**（可能假陽性）
- **(空白) = 沒發現**（目標對此 pattern 免疫或 hunter 不適用）

---

### hunt-hybris-occ.sh

**範例輸出（真實命中）:**
```
[14:05:22] === Hybris OCC hunt: https://target-api... ===
   authorizationserver endpoint present: HTTP 400
🔴 F1 default OAuth creds: mobile_android:secret → token acquired
🔴 F2 anonymous baseSites (/api/v2/basesites): site1,site2,site3,site4,site5,site6,site7,...
🔴 F3 anonymous cart created on <site1>: guid=<CART_GUID>
🔴 F4 GUID-only cart IDOR: .../carts/<CART_GUID> → 200
🔴 F5 Google API keys in configParam/global:
     AIza[REDACTED_demo_google_key_0000000]
```

**範例輸出（無 Hybris）:**
```
[14:06:12] not hybris (token endpoint 404) — skip
```

**決策規則：**
- F1 + F2 同時命中 → **P3 最低**（known Hybris pattern）
- F1 + F2 + F3 + F4 全中 → **P2**（跨 market + IDOR，有實質商業影響）
- 加上 F5 可量化財務影響的 API key → **P2/High**
- 只有 F2（無 F1）→ P4 info disclosure，大廠可能 N/A
- **重要**：production tenant 必須先確認一樣壞（`curl -X POST .../prod-host/token`），只在 staging 有效是 severity 砍半的 config gap

---

### hunt-envdata.sh

**範例輸出（disclosed SPA case output）:**
```
[14:10:01] === envData hunt: https://insight.example.com ===
✓ extracted window.envData (4832 bytes)
🔴 AWS Location key (v1.public): v1.public.[REDACTED_aws_location_key]...
🔴 AWS account ID: AWS_ACCOUNT_ID_1
🔴 AWS principal ID: AWS_ACCOUNT_ID_2
🔴 Okta clientId: 0oaXXXXXXXXXXXXXXXXX
```

**範例輸出（無 inline config）:**
```
no inline config found
```

**決策規則：**
- **AWS Location v1.public key** → 必須 curl 驗證可實際查 map tile，否則 P4
- **Google `AIza*` key** → 必須測 Vision/Maps/Firebase 實際可用才算 bounty（大廠對 public client key 已不收）
- **Sentry DSN** → 單獨 informational，不要送
- **Okta/Auth0 clientId** → public identifier，不要當 secret 報
- **AWS account ID** → 單獨不是漏洞，但可串 IAM policy audit / S3 bucket 猜測

---

### hunt-sourcemap-secrets.sh

**範例輸出（真實命中）:**
```
[14:15:44] === sourcemap hunt: https://passport.example.com ===
✓ MAP https://passport.example.com/webpack.stats.json.map — 2002 sources, 387 own
🔴 Bearer: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...  (in src/config/NA/shopify.ts)
🔴 Shopify storefront: a1b2c3d4...  (in src/config/NA/shopify.ts)
🔴 Sentry DSN: https://de73dba95aab41c699869bbaa820ce92@o80279.ingest.us.sentry.io/1290158  (in src/monitoring.ts)
```

**範例輸出（.map 存在但沒密鑰）:**
```
✓ MAP https://target/_next/main.js.map — 1234 sources, 89 own
(空白 — 沒有 🔴 行)
```

**決策規則：**
- 看 `own` 那欄，`node_modules` 不是漏洞
- **Bearer / password= / clientSecret** → 必須驗證 token 仍有效才算 P2+
- **Stripe sk_live** → 直接 P1（永遠有效）
- **Firebase apiKey** → 必須確認 realtime DB / storage 有開 public 才有 impact
- Source map 本身在大廠是 N/A（見 vault `Pattern - Source Map Exposure`），**必須從中找到可 exploit 的內容才能送**

---

### hunt-cors-reflect.sh

**範例輸出（真實命中）:**
```
[14:20:15] === CORS hunt: https://cloudaccess.svc.example.com/devices (tld=example.com) ===
🔴 A arbitrary: ACAO=https://attacker-random-1681234567.com  ACAC=true  ← browser-exploitable
🔴 B null: ACAO=null  ACAC=true  ← browser-exploitable
🔴 C prefix bypass (attackexample.com): ACAO=https://attackui.com  ACAC=true  ← browser-exploitable
   preflight OPTIONS → HTTP 200
```

**範例輸出（token auth，不可 exploit）:**
```
🟡 A arbitrary: ACAO=https://attacker-random-*.com  ACAC=none
   preflight OPTIONS → HTTP 200
```

**決策規則：**
- **ACAC=true 才算 exploit**，沒 credentials 的反射 CORS 只是資訊洩漏
- **目標必須用 cookie auth**（browser 送 credentials），Bearer token 的 API ACAC=true 也還是 N/A（token 不會跟 CORS 一起送）
- **ACAC=true + arbitrary 反射** → P3（public GraphQL IDOR writeup 級）
- **ACAC=true + 需要子域名接管** → N/A（prerequisite 未滿足，見 CNAME fingerprint pattern 教訓）
- 只命中 regex prefix bypass，未命中 arbitrary → 表示有部分防禦，P3→P4 降級

---

### hunt-graphql-idor.sh

**範例輸出（真實命中）:**
```
[14:25:33] === GraphQL hunt: https://api.example.com ===
🔴 GraphQL endpoint unauth: https://api.example.com/
🔴 introspection ON
   root: shipment
   root: companies
   root: ticket
🔴 unauth list query { companies }: N records
🔴 integer IDOR candidate: { shipment(id: 1) } resolved unauth
     shipment(id: 100) → resolved
     shipment(id: 1000) → resolved
     shipment(id: 10000) → resolved
```

**範例輸出（introspection off 但有漏洞）:**
```
🔴 GraphQL endpoint unauth: https://target/graphql
🔴 field suggestion enabled (schema leak via typo)
```

**決策規則：**
- **integer IDOR 命中後必須看多個 ID 的時間戳是否連續** — 如果全部是 `id:1` 測試 data 就不算 IDOR
- **unauth list query 大量 records** → P2/Critical（public GraphQL IDOR 家公司級）
- **只有 introspection ON** → P4，不要單獨送
- **field suggestion** → P5 informational，必須串到 IDOR 才有價值
- 測 `users`/`orders`/`tickets` 的無認證 list → 看回傳是不是真的有敏感資料還是空 array

---

### hunt-user-enum.sh

**範例輸出（真實命中）:**
```
[14:30:12] === User enum hunt: https://passport.example.com (existing=admin@example.com, none=zz-noexist-*) ===
POST /identity/users/validate_email:
  existing → {"status":200,"data":{"result":false,"status":"unactivated"}}
  nonexist → {"status":200,"data":{"result":true,"status":"unregistered"}}
🔴 POST /identity/users/validate_email: response differential → user enumeration
🔴 no rate limit on /identity/users/validate_email (20 reqs →  200 200 200 200 200 ...)
```

**決策規則：**
- **只有 differential 沒 no-rate-limit** → P5 informational（大廠通常拒）
- **differential + 無 rate limit + 無 CAPTCHA** → P4，送件 50/50
- **上面全中 + 可串 credential stuffing / password reset token 洩漏** → P3
- **大小寫不敏感** 是加分，不是單獨 bug
- 大廠的 user enum 幾乎一定會被退，除非能串 ATO chain（見 differential response pattern P5 教訓）

---

### hunt-git-exposure.sh

**範例輸出（cms.example.com 真實重現 — 對應 HITCON 已送案例）:**
```
[20:10:04] === .git exposure hunt: https://cms.example.com ===
🟡 robots.txt disallow paths:
     /going/
     /branch-a/
     /branch-b/
     /branch-c/
🔴 .git exposure: https://cms.example.com/branch-a/.git/HEAD → ref: refs/heads/master
🔴 .git exposure: https://cms.example.com/branch-c/.git/HEAD → ref: refs/heads/master
🔴 /branch-c/.git/config remote: git@github.com:example-org/project-backend.git
🔴 supply chain org: <org> (search github.com/<org> for other clients)
```

**範例輸出（無 .git）:**
```
no .git exposure across 11 candidate paths
```

**決策規則：**
- 候選路徑 = 根目錄 + robots.txt disallow + 常見 CMS subpath（/admin/、/backend/、/api/、/web/、/wp-content/、/application/、/src/）— 不要只測根
- **直接 hit 就 P3 起跳** — `.git/HEAD` HTTP 200 + `ref:` 內容驗證已是 confirmed exposure
- **加 GitHub remote URL** → 供應鏈倍數效應，找開發商再 grep `github.com/<org>` 可能找到別的客戶站（供應鏈 pattern 常見來源）
- **加 `--dump` 還原後 grep credential** → 找到金流 HashKey / Line Notify token / DB 密碼 → P2-P1 (nested .git + credential grep case)
- **送件前必跑**：HITCON ZeroDay 過往報告搜尋 + Google dork 確認該站沒被別人報過
- **危險訊號**：HTTP 200 但內容是 HTML（CDN 自訂 404 頁），需檢查 `ref:` 字串才算真命中

---

### hunt-subdomain-takeover.sh

**範例輸出（真實命中）:**
```
old-app.target.com → CNAME: target-app.herokuapp.com
🔴 old-app.target.com TAKEOVER candidate: vendor=Heroku  CNAME=target-app.herokuapp.com  body matches fingerprint
```

**範例輸出（dangling CNAME 無 fingerprint）:**
```
staging.target.com → CNAME: d-xxx.cloudfront.net
🟡 staging.target.com dangling CNAME to Fastly  (no A record, no fingerprint match — needs manual verify)
```

**範例輸出（正常 CNAME）:**
```
www.target.com → CNAME: cdn.target.com
(空白 — 沒 🔴 / 🟡)
```

**決策規則：**
- **`claimable: yes` vendor 有 fingerprint match** → **P2 直接註冊 claim**（S3/GitHub Pages/Heroku/Shopify/Tumblr/Pantheon 等）
- **`claimable: maybe` (Fastly)** → **HOLD**，需註冊 Fastly account 實測才算 confirmed（CNAME fingerprint pattern 經驗：can-i-take-over-xyz 官方分類 Fastly = Not Vulnerable 除非邊緣條件）
- **`claimable: no` (Zendesk/Netlify)** → informational only，vendor 不讓外人 claim
- **Dangling CNAME 無 fingerprint** → manual verify（vendor 可能改了 error 頁面，或 CNAME 指向私有資源）
- **必跑**：搭配 BBOT baddns module 互相驗證
- **送件必做**：實際註冊 claim 拿到 control 之前不算 confirmed，報告必須附 screenshot 證明 ownership
- **危險訊號**：CNAME fingerprint pattern 經驗 — CORS 報告若 prerequisite subdomain takeover 未驗證就是 theoretical，大廠不收

---

### hunt-open-redirect.sh

**範例輸出（真實命中）:**
```
[15:10:15] === open redirect hunt: https://target.com ===
🔴 open redirect: https://target.com/login?next=//evil-1681234567.example.org → Location: //evil-1681234567.example.org/
🔴 open redirect: https://target.com/oauth/authorize?redirect_uri=https://target.com.evil-*.example.org → Location: https://target.com.evil-*.example.org
[15:10:45] === done → ... (probed 180 combos) ===
```

**範例輸出（無 open redirect）:**
```
[15:10:15] === open redirect hunt: https://example.com ===
[15:10:30] === done → ... (probed 0 combos) ===
(example.com 沒有 /login /oauth 等路徑 → skip)
```

**決策規則：**
- **單獨 open redirect** → P4–P5（大廠多數認為是 informational，Bugcrowd 常常直接 rate=None）
- **open redirect on `/oauth/authorize` `redirect_uri`** → **P2-P3**（可偷 OAuth token/code，這是 OAuth redirect_uri chain 原 pattern）
- **open redirect on `/logout` + `return_url`** → P4（釣魚 vector）
- **bypass 變體命中但 arbitrary domain 被擋** → 表示有部分白名單，還有串鏈空間（改測 suffix bypass）
- **送件必做**：附 HTTP request/response header 證明 `Location:` header 含 attacker domain
- **危險訊號**：報告前 grep program disclosed reports — 熱門 program 的 open redirect 幾乎一定被報過
- **串鏈價值**：open redirect × XSS host whitelist bypass → 提升 XSS severity；open redirect × OAuth → ATO
- **FP 常見**：JavaScript-level redirect（window.location = ...）不會產生 Location header，hunter 會漏；需手動 curl 看 response body

---

### hunt-jwt.sh

**範例輸出（真實命中 — weak secret）:**
```
[15:20:01] === JWT hunt: eyJhbGciOiJIUzI1NiI... ===
header:  {"alg":"HS256","typ":"JWT"}
payload: {"sub":"1234","name":"John","iat":1516239022,"exp":9999999999}
  alg=HS256  kid=  typ=JWT
  iss=  sub=1234  aud=
🔴 EXP far future: 62136 days → long-lived token
🟡 HS256/384/512 uses shared secret — test weak secret brute
  wordlist probe (10 common secrets)...
🔴 HS256 WEAK SECRET: 'secret'
```

**範例輸出（alg:none 被接受）:**
```
[15:25:01] testing alg:none acceptance at https://api.target.com/me...
  original → HTTP 200
  alg:none → HTTP 200
🔴 alg:none ACCEPTED at https://api.target.com/me → total auth bypass
```

**範例輸出（jku header injection surface）:**
```
header:  {"alg":"RS256","typ":"JWT","jku":"https://target.com/.well-known/jwks.json"}
🔴 jku header present: https://target.com/.well-known/jwks.json → if attacker-controllable URL accepted → full forge
```

**決策規則：**
- **`alg:none` 或 empty signature 接受** → **P1**（total auth bypass，直接偽造任何 user）
- **HS256 weak secret brute 成功** → **P1**（可偽造任何 claim，等同 private key 洩漏）
- **`jku` 或 `x5u` header 可被 attacker 控制 URL** → **P1**（attacker 主機自己的 key → forge 任何 token）
- **`kid` header 可 SQLi/LFI/command injection** → P1–P2（要實測 payload）
- **EXP 永遠或 >1 年** → P3（long-lived token 不可撤銷 = 實質永久）
- **無 EXP claim** → P2–P3（token 無法過期）
- **RS256/ES256 但後端接受 HS256** → **P1**（alg confusion，public key 當 HS256 secret）
- **送件必做**：`--endpoint` 驗證，光 decode 看出問題 vs 實際打到 production 是兩碼事
- **危險訊號**：測試 token 必須是自己產的或已公開的，**不要**在 bug bounty 拿到他人 token 就去 brute secret（scope 問題）

---

### hunt-devops-unauth.sh

**範例輸出（真實命中 — public DevOps console leak pattern Harbor 重現）:**
```
[14:40:01] === DevOps unauth hunt: https://mirror.example.com ===
🔴 Harbor projects: https://mirror.example.com/api/v2.0/projects [200]
🔴 Harbor repositories: https://mirror.example.com/api/v2.0/repositories [200]
🔴 Harbor statistics: https://mirror.example.com/api/v2.0/statistics [200]
🔴 ArgoCD version: https://argocd.example.com/api/version [200]
🔴 ArgoCD settings: https://argocd.example.com/api/v1/settings [200]
🔴 Prometheus metrics: https://metrics.example.com/metrics [200]
```

**範例輸出（無 DevOps 暴露）:**
```
[14:40:01] === DevOps unauth hunt: https://example.com ===
[14:40:05] === done → ./devops_out/https___example.com.txt ===
(空白 — 沒有 🔴 行)
```

**決策規則：**
- **Harbor `/api/v2.0/projects` 回 2xx + `"project_id"` 欄位** → P3 起跳（鏡像內 image 可讀取，可能含 secret in Dockerfile）
- **ArgoCD `/api/v1/settings` 含 `execEnabled: true`** → P2/P1（配合 cluster deploy 可 RCE）
- **Jenkins `/script`** → P1（直接 Groovy RCE）
- **K8s `/api/v1/pods`** 能列出 → P1（cluster access）
- **Consul `/v1/kv/?recurse` 有值** → P2（配置洩漏，常含 secret）
- **etcd `/v2/keys?recursive=true` 有值** → P1（K8s etcd 等同 full cluster access）
- **Prometheus `/metrics` 單獨** → P4/P5（很多公司認為是正常暴露）
- **Grafana `/api/admin/stats`** → P3（表示 admin API 無認證）
- **Docker Registry `/v2/_catalog`** → P3–P2（image tag 可直接 pull，可能含 secret）
- **Vault `/v1/sys/health`** 單獨 → P5 (預期暴露)，但若 `sealed: false` 則配合其他 leak
- **危險訊號**：很多公司的 `/metrics` 是白名單內的 "informational"，送件前查 disclosed reports

---

### hunt-google-api-key.sh

**範例輸出（真實命中 — example Google API key 重現）:**
```
[14:45:12] === Google API key validation: AIza[REDACTED]... ===
   Maps Static: denied (403)
   Geocoding: denied (200)
   Places Nearby: denied (200)
🔴 Vision (label+face+safe): UNRESTRICTED [200]
     evidence: {"responses":[{"labelAnnotations":[{"mid":"/m/0dx1j","description":"Logo"...
🔴 Translate: UNRESTRICTED [200]
     evidence: {"data":{"translations":[{"translatedText":"你好"}]}}
🟡 Identity Toolkit signupNewUser: key invalid/expired

🔴 SUMMARY: 2 services unrestricted → potential financial abuse

Severity hint:
  Maps Static/JS unrestricted → P4 (mapped quota abuse)
  Vision/Translate/Places unrestricted → P3 (per-call cost)
  Identity Toolkit signupNewUser unrestricted → P2 (creates real users)
  FCM send unrestricted → P2 (spoofed push notifications)
```

**範例輸出（fake key）:**
```
🟡 Identity Toolkit signupNewUser: key invalid/expired
(其他全 denied — 0 🔴 行)
```

**決策規則：**
- **Maps Static / JS / Geocoding / Directions unrestricted** → P4（$5–$30/1000 calls，可量化但小額）
- **Places / Vision / Translate unrestricted** → P3（$1.5–$15/1000 calls，高成本）
- **YouTube Data / Custom Search unrestricted** → P3（quota-based，搶 quota 影響業務）
- **Identity Toolkit `signupNewUser` 可呼叫** → **P2**（能在對方 Firebase project 建真實使用者）
- **FCM `/fcm/send` 可呼叫** → **P2**（可冒充 app 發 push notification）
- **Firebase RTDB `.json` 可讀** → P2–P1（看資料）
- **送件必做**：算出每日 abuse 成本上限 + attacker cost basis（越不對稱越高 severity）
- **失敗訊號**：回 `403 referer restriction` → 要加 Referer header 測試，可能 HTTP Referer 綁定可繞過

---

### hunt-actuator-deep.sh

**範例輸出（真實命中）:**
```
[14:50:01] === Actuator deep hunt: https://api.example.com ===
🔴 actuator base: https://api.example.com/actuator [200]
     endpoint: env → https://api.example.com/actuator/env
     endpoint: heapdump → https://api.example.com/actuator/heapdump
     endpoint: threaddump → https://api.example.com/actuator/threaddump
     endpoint: mappings → https://api.example.com/actuator/mappings
🔴 /env propertySources exposed → ./actuator_out/api_env.json
     🔴 spring.datasource.password = redis_prod_xYk8j9Pd
     🔴 jwt.secret = eyJhbGciOiJIUzI1NiJ9...
     🟡 spring.datasource.url = ****** (masked but may leak via /configprops)
🔴 /configprops exposed → ./actuator_out/api_configprops.json
     🔴 datasource.password = redis_prod_xYk8j9Pd (mask bypass)
🔴 /mappings exposed: 142 endpoint patterns
🔴 /httptrace exposed: recent requests (may leak Authorization/Cookie headers)
🔴 /heapdump exposed [200] — can download memory dump
  (re-run with --heapdump to download + grep credentials)
```

**範例輸出（無 actuator）:**
```
[14:50:01] no actuator base found — skip
```

**決策規則：**
- **`/env` propertySources 回傳真值（非 `******`）** → P2–P1（直接拿到 DB / JWT / AWS credential）
- **`/env` 都是 `******` 但 `/configprops` 洩漏** → P2（mask bypass，Spring 2.x 常見 mis-config）
- **`/httptrace` 含最近請求的 `Authorization:` header** → P1（直接偷 session token）
- **`/heapdump` 可下載** → P1（memory dump → JWT / session / DB password / private key）
- **`/jolokia` JMX endpoint** → P1（MBean 呼叫可執行 code）
- **`/mappings` 單獨** → P4（endpoint 列表，attack surface 洩漏）
- **必跑 `--heapdump`** 模式收集 strings grep 證據，但 heap dump 可能很大（>100MB）
- **危險訊號**：若 `/env` 回 401 表示有 Spring Security，但 `/configprops` 可能仍 open（常見 misconfig）
- **送件格式**：列出 propertySource 的完整 key 名稱而非 value（避免洩漏到 report），value 只給 first/last 4 字元

---

### hunt-mcp-oauth-scope.sh

**範例輸出（真實命中 — MCP OAuth scope pattern）:**
```
[14:55:01] === MCP OAuth scope hunt: https://mcp.example.com ===
🔴 OAuth discovery: https://mcp.example.com/.well-known/oauth-authorization-server
     issuer: https://mcp.example.com
     authorization_endpoint: https://mcp.example.com/oauth/authorize
     token_endpoint: https://mcp.example.com/oauth/token
     scopes_supported: ['read', 'write', 'view_articles', 'create_articles', ...]
     pkce_methods: ['S256']
🔴 MCP endpoint candidate: https://mcp.example.com/mcp [200] (content-type: text/event-stream)
🔴 MCP initialize responded unauth
🔴 MCP tools/list exposed unauth
     tool: get_article  Get an article by ID
     tool: create_article  Create a new article
     tool: update_article  Update an existing article
     tool: delete_article  Delete an article
(若有 MCP_TOKEN):
🔴 authed token has WRITE-level tools:
     create_article
     update_article
     delete_article
🔴 ❗ scope mismatch candidate: 比對 consent screen 是否有 ALL of these scopes
   若 consent 只顯示 read/view，但 token 可 create/update/delete → P3 confirmed
```

**決策規則：**
- **OAuth discovery 只是 discovery** — 不是漏洞，但揭露 scope 清單是後續比對基礎
- **MCP `tools/list` 無認證可讀** → P4–P3（attack surface 洩漏，但 tool 呼叫仍需 auth）
- **consent screen 只要求 `view_X` scope，但 token 實際含 `create_X` / `delete_X`** → **P3 (confirmed)**（MCP OAuth scope pattern）— 必須有截圖證明 consent UI 的文字
- **consent screen + token 一致** → 無 finding
- **MCP tool 的 `get_*` 回傳含可被 LLM 解析的 attacker content** → 串 prompt injection chain，P2 可能
- **判定 write-level**：tool name 含 `create|update|delete|write|execute|send|post|modify|edit|remove`
- **手動補充**：截圖 consent screen 是必要證據 — hunter 抓不到截圖
- **危險訊號**：MCP 規格新，triager 可能不熟。報告要包含 MCP spec 連結 + OAuth scope RFC 連結

---

### hunt-hardcoded-js-secrets.sh

**範例輸出（真實命中 — SPA hardcoded client secret pattern）:**
```
[15:00:01] === hardcoded JS secrets hunt: https://developer-api-console.example.com ===
▶ https://.../main.abc123.js (482KB)
🔴 clientSecret (SPA hardcoded client secret pattern): 7KX9mZ2qP8vN5jL3hF4bR6tY  (in https://.../main.abc123.js)
🔴 Stripe pk_live: pk_live_51H8xYZaBcDef...  (in https://.../checkout.def456.js)
🔴 GitHub token (ghp/gho/ghs): ghp_AbCdEf1234567890...  (in https://.../api.789.js)
▶ https://.../vendor.xyz.js (1.2MB)
  (skipped: vendor bundle)
```

**範例輸出（0 FP — obfuscated SPA bundle）:**
```
[15:00:01] === hardcoded JS secrets hunt: https://insight.example.com ===
[15:00:19] === done → ... (0 hits across 21 js files) ===
```

**決策規則：**
- **Stripe `sk_live`** → **P1**（總是可用，直接轉帳）
- **Stripe `pk_live`** → P4（public key，單獨無害）
- **AWS `AKIA*`** → P1–P2（必測 `aws sts get-caller-identity`，有效 + 權限高 = P1）
- **GitHub `ghp_*` / `ghs_*`** → P2–P1（必測 `curl https://api.github.com/user` 確認仍有效）
- **Slack `xoxb-*`** → P2（能讀 workspace）
- **`clientSecret` quoted literal（SPA hardcoded client secret pattern）** → P3–P2（若能配合 OAuth flow 拿 token）
- **JWT 硬編碼** → 要測是否仍有效 + 看 claims（`exp` 過期 = informational）
- **Sentry DSN** → 單獨 informational，但大廠已經說不收
- **Mapbox `pk.*`** → P4（可能 URL-restricted）
- **FP 風險**：min 16–30 字元長度 + JUNK_VALS filter + 排除 `${...}`/`{{...}}` 佔位符 + password 要求 entropy ≥ 4 unique chars
- **必跑時機**：`sourcemap-secrets` 沒命中時（目標關了 source map 但 bundle 還是 readable）

---

### hunt-nxdomain-corpus.sh

**範例輸出:**
```
[14:35:01] === NXDOMAIN corpus: starbucks.com ===
[14:35:02] merged 1847 from bbot
[14:35:03] crt.sh...
[14:35:15] waymore...
[14:36:22] historical superset: 3421 hostnames
[14:36:22] filtering NXDOMAIN via @1.1.1.1 (A + AAAA)...
[14:38:44] === NXDOMAIN candidates: 892 → recon/starbucks.com/nxdomain/nxdomain_corpus.txt ===
```

**決策規則：**
- **這個 hunter 本身不找漏洞** — 只建立 payload corpus
- **只有在找到 Host-controllable proxy 時才有用**（edge gateway、reverse proxy、sidecar）
- 候選數 > 500 才值得保留，< 100 代表來源不足
- 每個目標保存一份 `nxdomain_corpus.txt`，下次找到 proxy 直接灌進 Burp Intruder Host header 位置
- **禁止**：對候選做 DNS brute force 或公網 probe，那只會產生噪音且不在 scope

---

---

### hunt-config-leak.sh

**目標**：政府站 / 防火牆後標的 — 100+ 路徑單發驗證，**WAF 極低觸發率**

**機制**
- 每個路徑只送 1 次 GET（不爆破）
- 100+ 路徑全部用 content-match 驗證（不是 HTTP 200 就算 hit）
- 涵蓋 xray 最穩的 PoC-none 規則：SCM、IDE、.env、backup、WEB-INF、Swagger、debug console
- `FAST=1` 模式只跑 24 個 P1/P2 高信心路徑

**範例輸出**
```
🔴 https://target/.env (size=412, content-match: AWS_ACCESS_KEY_ID=AKIA...)
🟡 https://target/.git/config (size=98, content-match: [remote])
✅ https://target/swagger-ui.html (size=2891, content-match: <title>Swagger UI</title>)
```

**用法**
- `./hunt-config-leak.sh https://target` — 全 100+ 路徑
- `FAST=1 ./hunt-config-leak.sh https://target` — 只 P1/P2

---

### hunt-weak-login.sh

**目標**：25+ vendor 預設帳密驗證 — **不是爆破**，是 default creds 確認

**機制**
- 每個 vendor 只送 1–3 次 login request
- 先 HEAD/GET 確認 vendor 面板存在才發 login
- 差異判斷（login 成功 vs 失敗的 HTTP/body signature）
- Fail-safe：2xx login response 仍要配 body pattern 才算 hit

**覆蓋 vendor**：Nacos / Druid / Grafana / Jenkins / phpMyAdmin / Tomcat Manager / Solr Admin / RabbitMQ / Kibana / Jeecg / Jeesite / SpringBoot Admin / Apollo / GitLab / Gitea / Portainer / Rancher / Harbor / Nexus / SonarQube / Weblogic / Zabbix / Shiro / Airflow / Superset / Metabase / Couchbase

**範例輸出**
```
🔴 Nacos default creds: nacos:nacos → 200 OK + accessToken (https://target:8848/nacos/v1/auth/login)
🔴 phpMyAdmin: root:root → server_status.php accessible
✅ Grafana: admin:admin → 401 (不是 default)
```

---

### hunt-backup-files.sh

**目標**：洩漏的 backup 檔案 — 多層命名 + Index-of fallback

**機制**
1. 靜態候選：常見 backup.zip / www.tar.gz / db.sql 等 40 個命名
2. 動態候選：從 target hostname 衍生（target.com.zip / target.tar.gz / target.sql）
3. Index-of 列表 fallback：/backup/、/backups/、/bak/、/db/、/upload/
4. Content-type + size 雙驗證（避免 SPA 200 HTML 當 hit）

**範例輸出**
```
🔴 https://target/db.sql (Content-Type: application/sql, size=2.4MB)
🔴 https://target/backups/ (Index-of listed: prod_2024.tar.gz, dev.sql)
🟡 https://target/target.com.zip (200, Content-Type: text/html — likely false positive)
```

**用法**
- `./hunt-backup-files.sh https://target` — 預設 40 候選
- `./hunt-backup-files.sh https://target extra1 extra2` — 附加自訂候選

---

### hunt-nuclei-deep.sh

**目標**：分類 nuclei scan — 比預設 template miss 少

**覆蓋分類**：XSS / SQLi / SSRF / LFI / RCE / Path Traversal / Info Leak / Debug / Weak login / Default cred / Exposed panels / Misconfig / CVE / Takeover / CORS / Open Redirect / SSTI / XXE

**機制**
- 每個類別獨立可關 (`CATEGORY=xss tools/hunters/hunt-nuclei-deep.sh ...`)
- 自動整合 `bb-recon` 自訂 template（若存在）
- 對 deep surface 比預設 template 命中率高（用更精準 tag）

**範例輸出**
```
🔴 [XSS][high] /login?next=javascript:alert(1)
🔴 [Misconfig][medium] /actuator/env exposed
🟡 [Info-Leak][low] X-Powered-By: Express in headers
```

---

### hunt-waf-bypass.sh

**目標**：找 WAF 可繞的路徑 — 為後續 hunter 鋪路

**機制**
1. wafw00f 識別 WAF 廠商（Cloudflare / AWS / Akamai / Imperva / F5 / ...）
2. 對 /admin、/login、/api 等常被擋路徑試 15+ bypass 技巧
3. 記錄能通過的 bypass 手法 → 給後續 hunter 套用

**Bypass 技巧**：path case mutation / nullbyte / unicode / chunked encoding / Origin header spoof / X-Forwarded-For / Host header / extra dots / parameter pollution / etc.

**範例輸出**
```
🔴 WAF: Cloudflare detected
🔴 Bypass: /Admin (case mutation) → 200 OK (vs /admin 403)
🔴 Bypass: X-Forwarded-For: 127.0.0.1 → /api/internal accessible
✅ /login: no bypass works (all variants 403)
```

**用法**
- `./hunt-waf-bypass.sh https://target` — 預設路徑
- `PATHS='/admin,/api/users' ./hunt-waf-bypass.sh https://target` — 自訂路徑
- `ORIGIN_IP=1.2.3.4 ./hunt-waf-bypass.sh https://target` — 直連 origin（繞 CDN）

---

### hunt-crawl-chain.sh

**目標**：完整 URL discovery + DAST 一條龍

**10 階段流水線**
1. **katana** — 動態 JS-aware crawl（深度 3，headless）
2. **gau** — wayback + otx + commoncrawl + urlscan 歷史 URL
3. **waybackurls** — gau fallback
4. **paramspider** — 從 Wayback 抽 param-only URLs
5. **hakrawler** (optional) — SPA 快速 crawl
6. **uro** — 合併去重（相同 param pattern 只留一筆）
7. **gf** 分類 — xss / sqli / ssrf / lfi / ssti / redirect / idor
8. **arjun** — 對每個 endpoint 找隱藏 param
9. **nuclei DAST** — 按 gf 分類跑對應漏洞 templates
10. **dalfox** — xss.txt 的 URL 深度 XSS scan

**範例輸出**
```
[1] katana: 1247 URLs crawled
[2] gau: 8932 historical URLs
[6] uro: 2103 unique param patterns
[7] gf classified: xss=87, sqli=12, ssrf=34, lfi=21
[8] arjun: 47 hidden params discovered
[9] nuclei DAST hits: XSS=3, SQLi=1, SSRF=2
🔴 Reflected XSS: /search?q=<svg/onload=alert(1)>
```

**用法**
- `tools/hunters/hunt-crawl-chain.sh https://target.com`
- `DEPTH=5 tools/hunters/hunt-crawl-chain.sh https://target.com` — 更深 crawl

---

### hunt-dalfox-xss.sh

**目標**：深度 XSS scan（reflected + blind + custom payload）

**機制**
- katana + gau 收集 URL
- gf xss pattern filter（只打 xss-prone params）
- dalfox pipe scan：reflected XSS + blind XSS（需 `DALFOX_BLIND_URL`） + 自訂 `DALFOX_PAYLOADS` file

**用法**
- `OUT_DIR=/path DALFOX_BLIND_URL=https://your.oast.fun ./hunt-dalfox-xss.sh <url>`
- `OUT_DIR=/path DALFOX_COOKIE="session=xxx" ./hunt-dalfox-xss.sh <url>` — authenticated

---

### hunt-arjun-params.sh

**目標**：發現隱藏 GET/POST/JSON parameter

**改進**
- 使用 SecLists `burp-parameter-names.txt`（>6000 params）
- JSON output for structured parsing
- GET + POST + JSON 三種方法
- 支援 authenticated 掃描（`ARJUN_HEADERS` / `ARJUN_COOKIES`）
- Passive mode（只查歷史資料，不主動掃描）

**範例輸出**
```
🔴 GET /api/users: hidden param `admin=true` → 200 OK with extra fields
🔴 POST /login: hidden param `_method=PUT` → bypass auth
🟡 JSON /api/v2/data: 3 candidate params (debug, raw, internal) — needs manual verify
```

**用法**
- `OUT_DIR=/path ARJUN_HEADERS="Authorization: Bearer xxx" ./hunt-arjun-params.sh <url>`

---

### hunt-trufflehog-secrets.sh

**目標**：對 dump 過的 .git repo 做深度 secret scan

**vs hunt-git-exposure 的 grep 差異**
- 掃所有 commit history（含已刪除的 secrets）
- 100+ 種 detector（AWS/GCP/GitHub/Stripe/SendGrid/Twilio/Slack/...）
- 只報驗證成功的（`--only-verified`）— 高信心，無 FP

**範例輸出**
```
🔴 AWS Access Key (verified): AKIAIOSFODNN7EXAMPLE in commit a1b2c3d (2 years ago)
🔴 GitHub Token (verified): ghp_xxxxx in commit f4e5d6 (delete-then-leaked)
✅ Stripe key found but unverified (revoked)
```

**用法**：必須先跑 `hunt-git-exposure.sh` dump 完成
- `OUT_DIR=/path ./hunt-trufflehog-secrets.sh <url>`

---

### hunt-ffuf-dirs.sh

**目標**：3 層目錄/檔案 fuzzing

**機制**
- 自動偵測 404 response size → `-fs` 過濾（減少 FP）
- 三層掃描：BB-high-ROI list → SecLists raft-medium → API endpoints
- `-recursion` 對有趣路徑深入
- `-fw` 過濾 word count
- 支援 `FFUF_COOKIE` / `FFUF_HEADERS` 做 authenticated 掃描

**範例輸出**
```
🔴 /admin (200, size=2891)
🔴 /api/internal/v2 (200, size=487, no auth required)
🟡 /backup (403, size=12) — 檔案存在但被擋
```

**用法**
- `OUT_DIR=/path FFUF_COOKIE="session=xxx" ./hunt-ffuf-dirs.sh <url>`

---

### hunt-portscan.sh

**目標**：Port scan + service detection

**Pipeline**
- rustscan (fast SYN) → nmap (service/version on open ports)
- Falls back to nmap-only if rustscan not installed

**自動標 🔴 的 service**：Docker API（2375/2376）、Redis（6379）、Elasticsearch（9200）、Mongo（27017）、Consul（8500）、etcd（2379）、K8s API（6443/8443）

**範例輸出**
```
🔴 Open: 2375/tcp Docker API (no TLS, no auth)
🔴 Open: 6379/tcp Redis 6.0.16 (no auth)
🟡 Open: 22/tcp OpenSSH 8.4 (default port)
✅ Open: 443/tcp nginx 1.18.0 (TLS, expected)
```

**用法**
- `OUT_DIR=/path ./hunt-portscan.sh <url-or-ip>`

---

### hunt-param-fuzz.sh

**目標**：parameter fuzzing pipeline（站點層 DAST）

**流程**
1. katana 爬頁面（JS-aware，depth 3）
2. gau / waybackurls / Wayback CDX API 抓歷史 URL
3. uro 去重（相同 param pattern 的 URL 只保留一個）
4. 過濾出有 query param 的 URL
5. nuclei `--dast` 跑 XSS / SQLi / SSRF / LFI / SSTI / Open-redirect

**用法**
- `OUT_DIR=/path/to/out ./hunt-param-fuzz.sh <url>`

---

### hunt-version-json.sh

**目標**：揭露 dev/test/UAT/staging 環境主機名稱的 JSON 對映檔案

**機制**
- 探測 9 候選路徑：`/json/version.json`、`/json/version_pmo.json`、`/json/config.json`、
  `/version.json`、`/config.json`、`/api/version`、`/api/config`、
  `/app/version.json`、`/static/version.json`
- HTTP 200 + JSON body 才進入解析（避免 SPA HTML FP）
- Python3 解析 JSON，走訪所有 key-value 對
- 標記含 `develop`/`test`/`uat`/`staging`/`qa`/`sandbox`/`beta` 的 key 或 value
- 額外標記 `.cc`/`.dev`/`.local`/`.internal` TLD 或 RFC 1918 IP（`10./192.168./172.16-31.`）

**範例輸出（真實命中 — EVERY8D TP-S18）:**
```
[10:01:23] === version-json hunt: https://hs.e8d.tw ===
🔴 version-json https://hs.e8d.tw/json/version.json key='develop' → value='dev-portalite.e8d.cc' [ENV MAPPING]
🔴 version-json https://hs.e8d.tw/json/version.json key='test' → value='test-portalite.e8d.cc' [ENV MAPPING]
🔴 version-json https://hs.e8d.tw/json/version.json key='localhost' → value='localhost' [ENV MAPPING]
[10:01:25] === done → ./version_json_out/hs_e8d_tw.txt ===
```

**範例輸出（JSON 存在但無環境鍵）:**
```
🟡 version-json https://target/version.json → JSON exposed (no obvious env keys, manual review)
     content: {"version":"1.2.3","build":"2026-04-01"}
```

**決策規則：**
- **`.cc`/`.dev`/`.local` 主機名稱** → P3（洩漏內部基礎設施地圖，可橫向 pivot 到 dev/test 環境）
- **`dev-*`/`test-*` 公開可訪問** → 立刻對 dev 主機跑 hunt-actuator-deep + hunt-git-exposure
- **只含版本號（`"version":"1.2.3"`）** → P4 info disclosure，通常不送件
- **內網 IP（10.x.x.x）** → P3（後端拓撲洩漏，可配合 SSRF 利用）
- **常見於** PHP/Fat-Free Framework 應用（`hs.e8d.tw` 確認 pattern）
- **後續**：把發現的 dev/test hostname 加進 BBOT recon 清單，往往能找到更多未加固的面板

---

### hunt-cert-bypass.sh

**目標**：SSO multi-step 流程中間端點跳過密碼驗證（token 任意發行）

**機制**
1. HEAD 預檢（404 快速跳過，減少流量）
2. POST fake 帳號（無密碼） → 偵測回應含 `token`/`session`/`jwt` 欄位且狀態 2xx 或 `"status":"200"`
3. 用 Python3 走訪 JSON 找 token 值（支援巢狀 key）
4. **Layer 2**：用取得的 token 打 7 個常見認證 API endpoint
5. 若 API 回 200 且有實際資料（非 MSSQL error 397 等錯誤碼）→ 確認 P1-CRIT

**探測端點**：`/login/cert`、`/auth/cert`、`/sso/cert`、`/api/cert`、`/token/cert`、
`/oauth/cert`、`/user/cert`、`/session/cert`、`/api/v1/cert`、`/api/login/cert`

**驗證端點**：`/isKYC`、`/announce`、`/api/announce`、`/e8d/announce`、
`/api/user`、`/api/me`、`/api/profile`、`/user/info`

**範例輸出（P1 確認 — EVERY8D TP-S32）:**
```
[10:05:11] === cert-bypass hunt: https://ext-api.e8d.tw ===
🟡 cert endpoint responded with token-like data: https://ext-api.e8d.tw/login/cert [HTTP 200]
[10:05:11]   body preview: {"status":"200","token":"eyJhbGciOiJIUzI1NiJ9..."}
[10:05:11]   extracted token: eyJhbGciOiJIUzI1NiJ9... (len=142)
🔴 [P1-CRIT] cert-bypass CONFIRMED: https://ext-api.e8d.tw/login/cert → token issued + /e8d/announce returned HTTP 200 with data
[10:05:12]   issuance body: {"status":"200","token":"eyJ...","expire":3600}
[10:05:12]   verify body (/e8d/announce): {"announcements":[{"id":1,"title":"公告內容..."}]}
[10:05:12] === done → ./cert_bypass_out/ext-api_e8d_tw.txt ===
```

**範例輸出（token 發行但無法驗證）:**
```
🟡 [P3] cert endpoint issued token but verify endpoints rejected it or returned errors → token may be for real accounts only
🟡   endpoint: https://target/login/cert  token: eyJhbGciOiJIUzI1...
🟡   manual: try with a known real account to confirm bypass
```

**範例輸出（無 cert 端點）:**
```
[10:05:11] === cert-bypass hunt: https://target.example.com ===
[10:05:15] === done → ./cert_bypass_out/target_example_com.txt ===
(空白 — HEAD 全 404，快速跳過)
```

**決策規則：**
- **Layer 2 確認（token 打 authenticated API 回 200 + 資料）** → **P1-CRIT**（任意帳號獲 session → 完整繞過認證）
- **token 發行但 verify endpoints 全拒** → P3（token 格式合法但後端可能只接受真實帳號，需手動測試）
  - 手動：用一個已知真實帳號的名稱（不需密碼）重試
- **MSSQL error 397 on verify** → 帳號不存在（EVERY8D 特有 user-enum differential），真實帳號會回資料
- **cert endpoint 只接受 POST JSON** → 若 HEAD 回 405 仍值得 POST 測試（HEAD 可能不支援）
- **含 SSO 的 B2B / 企業入口** → cert bypass pattern 出現率高，優先測試
- **送件格式**：附 issuance request/response + verify request/response 兩組完整 curl

---

## 失敗模式 / 注意事項

| 現象 | 原因 | 修正 |
|------|------|-----|
| hunt-envdata 找不到 envData | SPA 用 hash router，config 在 API response | 改跑 hunt-sourcemap-secrets |
| hunt-hybris-occ 全部 skip | 目標不是 Hybris（`/authorizationserver/oauth/token` 回 404） | 預期行為，不是 bug |
| hunt-cors-reflect 無命中但肉眼看得到 | token-based auth，沒 cookie → 即使 ACAO 反射也不可利用 | 先確認目標用 cookie auth，不然就是 N/A |
| hunt-graphql-idor integer IDOR 命中但內容是 demo data | Schema 預設塞 id:1 的測試資料，不代表真 IDOR | 試 1000/10000 確認是連續序列 |
| hunt-user-enum 無差異回應 | 目標正確把 exist / nonexist 歸一化 | 該目標對 user enum 免疫 |

## 不包含什麼（故意排除）

- **LLM-based payload generation** — 零 LLM 依賴
- **盲目 fuzzing** — 只做 differential / state-based 驗證
- **DoS / rate-limit bypass** — 不碰
- **Auth bypass 猜測** — 只測 default creds（`mobile_android:secret` 等公開已知）
- **Payloads against OOS rules** — 每個 hunter 只做送件可接受的檢測

## 對應的 Vault 筆記

- [[Playbook - BBOT vs Osmedeus Recon Flow]] — 10 Step recon flow
- [[Playbook - Osmedeus VPS Setup]] — VPS 架構
- [[External Writeups - 2026 Collection]] — Starbucks NXDOMAIN / IDOR per-verb / minimalist stack
- [[Pattern - Git Exposure]] / [[Pattern - Source Map Exposure]] / [[Pattern - CORS Misconfiguration]] — 對應的 pattern 筆記
