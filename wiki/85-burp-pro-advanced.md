---
type: wiki
category: tool
tool: burp-pro
status: active
last-updated: 2026-04-21
---

# Burp Pro 進階用法（2026 版）

> **用途：** 從「攔截基礎」升級到「Collaborator + Logger++ + BCheck + Turbo Intruder + Bambda」等進階工作流。熟這些 = 打洞效率 10x。

## 0. 基礎設定

```
Project options → TLS → 自動信任 cert（loopback 用）
Project options → Sessions → 建 cookie jar
User options → Extender → 讀 Jython / Jruby
User options → Connections → Upstream proxy（公司 proxy / tor）
Target scope → 精確設 in-scope domain（避免打到 OOS）
```

## 1. Collaborator（OOB 必備）

### 1.1 基本

```
Burp → Collaborator → Copy to clipboard → 給一個 FQDN
任何地方塞 → DNS / HTTP request 會回 Burp
```

### 1.2 用途

- **Blind XSS / SSTI / SSRF / XXE / RCE** 驗證
- **Log4Shell** DNS query
- **Blind SQLi** load_file UNC (Windows) / UTL_HTTP (Oracle)

### 1.3 Private instance

```
# 起自架 collaborator（避免公共 IP ratelimit）
burp-collaborator-server --config=config.yaml
# 配公用 domain / ACM cert / NS record 指向 VPS
```

### 1.4 Burp Professional vs Community

Community 版本的 Collaborator 是共享的（有 ratelimit），Pro 版本可用 private instance。

## 2. Intruder 模式

### 2.1 Sniper

```
單點攻擊，每個 position 輪流送 payload
```

### 2.2 Battering ram

```
所有 position 同時用同一個 payload
（如 login username=password=admin）
```

### 2.3 Pitchfork

```
多 wordlist 對應（同 index）
```

### 2.4 Cluster bomb

```
多 wordlist 笛卡爾積（username × password 全組合）
```

### 2.5 Payload processing

```
Encoding / Hashing / Custom Jython script
```

## 3. Turbo Intruder（快 10x）

Burp extension，每秒可發 10,000 requests。

### 3.1 安裝

```
BApp Store → Turbo Intruder
```

### 3.2 Script 範本

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        requestsPerConnection=100,
        pipeline=False
    )
    for word in open('/usr/share/wordlists/rockyou.txt'):
        engine.queue(target.req, word.rstrip())

def handleResponse(req, interesting):
    if req.status != 401:
        table.add(req)
```

### 3.3 Race condition

```python
engine.queue(target.req, gate='race1')
engine.queue(target.req, gate='race1')
engine.openGate('race1')    # 同時放
```

### 3.4 Single-packet attack (HTTP/2)

```python
engine = RequestEngine(
    endpoint=target.endpoint,
    engine=Engine.BURP2
)
# 把多個 req 塞進同一個 TCP packet → 微秒級別同時處理
```

見 James Kettle 2023 research https://portswigger.net/research/smashing-the-state-machine

## 4. Logger++

```
BApp Store → Logger++
```

功能：

- 全站 request/response log
- 複雜 filter（regex / field / size）
- Export CSV / JSON
- 找「歷史請求中有 reflect XSS」
- 找「某 header 出現過」

### 4.1 Filter syntax

```
Request.Body CONTAINS "password"
Response.Headers CONTAINS "X-Powered-By: PHP"
Request.Method IN ["POST","PUT","DELETE"]
Response.BodyLength > 5000 AND Response.MimeType == "JSON"
```

### 4.2 Colorize

針對特定 pattern 高亮，快速視覺辨識。

## 5. BCheck（Burp 自訂 scan rule）

2023 新功能。用 BCheck DSL 寫 rule，丟進 Scanner → auto scan。

### 5.1 範本

```
metadata:
  language: v2-beta
  name: "Test for X-Debug header"
  description: "Check if X-Debug header leaks data"
  author: "me"
  tags: "debug,info-disclosure"

run for each:
  potential_header = "X-Debug"

given host then
  send request called check:
    method: "GET"
    path: {BaseRequest.path}
    headers:
      - {potential_header}: "1"
  
  if {check.response.body} matches "DEBUG MODE ON" then
    report issue:
      severity: medium
      confidence: firm
      detail: "X-Debug header activates debug mode"
```

### 5.2 Library

- https://github.com/PortSwigger/BChecks
- https://github.com/BC-Security/BChecks

## 6. Match & Replace（進階）

```
User options → Connections → Match and Replace
```

### 6.1 場景

```
Header: Origin:.* → Origin: attacker.com
Header: User-Agent:.* → User-Agent: <script>alert(1)</script>
Body regex: "role":"user" → "role":"admin"
Response: Content-Security-Policy: .* → (empty)
```

### 6.2 只對特定 host

```
Type: Request body
Match: "userId":"\d+"
Replace: "userId":"999"
Comment: only in-scope
# 勾「Only in-scope」
```

## 7. Session handling rules

```
Project options → Sessions → Session handling rules
```

### 7.1 Auto-refresh token

```
Rule: 偵測 response 含 "token expired" → 重新跑 login macro → 取新 token → 塞 Authorization header
```

### 7.2 Macro

```
Sessions → Macros → New → 錄製 login 步驟
Rule 引用 macro
```

### 7.3 CSRF token 自動替換

```
Macro 抓 CSRF token（regex）
Rule 把每個 POST 中的 token 替換為最新
```

## 8. Extender 擴充

### 8.1 必裝

```
[ ] Autorize             — IDOR 自動測
[ ] AuthMatrix           — 階層化 authz 測試
[ ] Param Miner          — 隱藏 parameter / header 發掘
[ ] Backslash Powered Scanner — 進階 XSS/SQLi scan
[ ] HTTP Request Smuggler    — smuggling 檢測
[ ] Stepper              — 多步驟 replay
[ ] Hackvertor           — encoding 快速轉換
[ ] JWT Editor           — JWT 測試
[ ] SAML Raider          — SAML XSW
[ ] Active Scan++        — 追加 scan rule
[ ] Logger++             — 歷史追溯
[ ] Turbo Intruder       — race / 大量請求
[ ] BChecks              — 自訂 rule
[ ] Software Vulnerability Scanner
[ ] Upload Scanner       — 檔案上傳測試
[ ] CO2                  — SSL/URL 工具
[ ] Collaborator Everywhere — 每個 request 塞 collaborator domain
```

### 8.2 安裝 Jython / JRuby

```
User options → Extender → Python Environment → Jython 2.7.x
                         → Ruby Environment → JRuby
```

## 9. Bambda（Burp 2023+ 新 filter DSL）

```java
// Proxy history → Filter → Bambda
return requestResponse.hasResponse() 
    && requestResponse.response().statusCode() == 500
    && requestResponse.response().bodyToString().contains("stack trace");
```

## 10. DOM Invader

```
Burp Browser → DOM Invader
```

自動找 DOM XSS / client-side prototype pollution / postMessage / client-side URL reflection。

啟用後 browser F12 多個 "DOM Invader" tab。

## 11. 快速 workflow

### 11.1 新 target

```
1. Target → Scope → 加入 in-scope
2. Proxy → 瀏覽全站 → 建 site map
3. Scanner → Crawl + Audit in-scope
4. Extender → Param Miner → 跑 headers/params discovery
5. DOM Invader 自動開著
```

### 11.2 深入測試 (per endpoint)

```
1. Repeater 打 baseline
2. Change method (GET↔POST↔PUT↔DELETE)
3. Add debug headers (X-Original-URL, X-Rewrite-URL)
4. Intruder auth fuzzing (cookie, header, body)
5. Collaborator 塞 SSRF / injection candidate
6. Autorize replay with other session
```

### 11.3 JWT / OAuth flow

```
1. JWT Editor 解 token → 看 alg / claim
2. 試 alg=none / kid injection
3. Macro 自動 refresh
4. OAuth redirect_uri 試 bypass（見 16）
```

## 12. Collaborator 一鍵整合

### 12.1 Collaborator Everywhere

每個 request 自動加入 `Referer: https://<collab>`、`X-Forwarded-Host: <collab>` 等常見 SSRF header。

### 12.2 Copy to clipboard + quick insert

```
# Repeater 中游標點 body 任意處 → Ctrl+Shift+C (collab address) → paste
```

## 13. 速查鍵

```
Ctrl+R       送 Repeater
Ctrl+I       送 Intruder
Ctrl+Shift+R 新 Repeater tab
Ctrl+B       把選取值送 Decoder
Ctrl+U       URL encode
Ctrl+Shift+U URL decode
Ctrl+F       搜尋 history
Ctrl+Alt+O   Project options
```

## 14. Scanner 進階

### 14.1 Audit checks

```
Active scan → Audit options → 選 insertion point（path, body, cookie...）
→ Scan → 看 Issues
```

### 14.2 Passive scan

```
所有 proxy 過的請求自動 passive scan
→ 找 info leak / missing headers / CSP / cookie flag
```

### 14.3 Scan definitions

```
自訂 insertion point（如 JSON nested key）
```

## 15. 實用 tip

- 用不同 project 分專案（File → New project）
- 定期 save project（避免 crash）
- 用 Burp Suite Enterprise 排程掃大量 target（團隊版）
- CI 接 Burp API：https://portswigger.net/burp/documentation/enterprise/api

## 關聯文件

- [20-burp-cheatsheet.md](20-burp-cheatsheet.md) — Burp 基本操作
- [31-jwt-cheatsheet.md](31-jwt-cheatsheet.md) — JWT Editor 用法
- [83-saml-oidc-attacks.md](83-saml-oidc-attacks.md) — SAML Raider
- PortSwigger Web Security Academy：https://portswigger.net/web-security
- BApp Store：https://portswigger.net/bappstore
- Turbo Intruder：https://github.com/PortSwigger/turbo-intruder
