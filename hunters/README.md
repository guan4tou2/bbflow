# Hunters — Pattern-Specific Vulnerability Probes

零 LLM 依賴的漏洞驗證腳本。每個 hunter 對應過往成功案例的完整驗證鏈，純 `curl + python3 stdlib + bash`。

## 設計原則

1. **BBOT / Osmedeus 做 recon**（子域名、存活、技術指紋、cloud bucket、badsecrets）
2. **Hunters 消費 recon 輸出**（`recon/<target>/bbot/live_hosts.txt`）
3. **每個 hunter 對應一個確認有 bounty 的 pattern**
4. **沒有猜測、沒有 LLM — 只有 curl + 條件判斷 + differential**

## Hunter 對照表

| Hunter | 來源案例 | 驗證什麼 |
|--------|---------|---------|
| `hunt-hybris-occ.sh` | **SAP Hybris OCC pattern**（research/target-example） | SAP Hybris OCC default OAuth creds + anonymous baseSites + anonymous cart create + GUID IDOR + configParam API keys |
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
| `hunt-nxdomain-corpus.sh` | **Starbucks NXDOMAIN**（External Writeups 2026） | 建立歷史 hostname 超集 → 過濾出 NXDOMAIN 候選 → 待遇到 Host-controllable proxy 時當 payload |
| `hunt-param-fuzz.sh` | **DAST fuzzing pattern** | katana + gau + waybackurls URL 收集 → gf filter XSS/SQLi/SSRF → nuclei DAST templates 驗證 |
| `hunt-dalfox-xss.sh` | **Reflected/Blind XSS pattern** | gf xss filter → dalfox 掃描（支援 blind XSS callback + cookie auth）+ payloads/xss-custom.txt |
| `hunt-arjun-params.sh` | **Hidden parameter discovery** | arjun GET/POST/JSON 隱藏參數探索 + SecLists burp-parameter-names（支援認證 header）|
| `hunt-trufflehog-secrets.sh` | **Git history secret scan** | trufflehog git 模式（`--only-verified`）掃 100+ detector：AWS/GitHub/Stripe/GCP/Azure key + config |
| `hunt-ffuf-dirs.sh` | **Directory & file fuzzing** | ffuf 三層 dir fuzzing：raft-medium + BB-ROI wordlist + 副檔名（.bak/.sql/.env/.git）（支援 cookie auth）|

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
cat recon/<target>/bbot/live_hosts.txt | while read h; do
  ./tools/hunters/hunt-envdata.sh "$h"
done
```

### 全套 orchestration（推薦）

```bash
./tools/hunt_all.sh target.com
# 自動：BBOT recon → 對 live hosts 跑全部 hunters → HUNTERS_REPORT.md

./tools/hunt_all.sh target.com --from-osmedeus   # 從 VPS 拉 Osmedeus 結果
./tools/hunt_all.sh target.com --only cors,graphql
./tools/hunt_all.sh target.com --mode quick      # 跳過 BBOT，用現有 recon
```

## 環境需求

```bash
# 必需
which curl python3 bash dig

# 推薦（有的話 recon 會更完整）
pipx install bbot
which httpx subfinder waymore gau
```

Osmedeus VPS 模式：

```bash
export OSMEDEUS_VPS="user@167.71.x.x"
./tools/hunt_all.sh target.com --from-osmedeus
```

## 輸出結構

```
recon/<target>/
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
