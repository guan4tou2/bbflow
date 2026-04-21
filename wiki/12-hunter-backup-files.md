---
type: wiki
category: hunter
hunter: backup-files
status: active
last-updated: 2026-04-21
---

# Hunter: `backup-files`

> **目的：** 對 WAF 後的網站低噪音偵測「網站根目錄 / 子目錄」的**備份檔案、資料庫 dump、壓縮封存**。
> **原理：** 41 個靜態候選 + 依 hostname 推導的動態候選（e.g. `target.zip`、`target.tar.gz`），每個只送 1 次 HEAD + 局部 GET 驗證 magic bytes。

## 為什麼值得用

- 政府/老舊系統最常見的 P2-P3 quick win（`backup.zip`、`db.sql`、`www.tar.gz`）
- **HEAD first**：多數情境先用 HEAD 確認 size + content-type，不會真的下載
- **Magic byte 驗證**：不是 HTTP 200 就算中，真的抓前 8 bytes 比對 ZIP / gzip / SQLite / tar 特徵
- **Directory listing** 附帶偵測（`/backup/`、`/uploads/` 開了 `Index of`）

## 用法

```bash
# 基本
tools/hunters/hunt-backup-files.sh https://target.gov.tw

# 附帶候選關鍵字（建議傳目標的英文名 + 簡稱 / 機關英文縮寫）
tools/hunters/hunt-backup-files.sh https://target.gov.tw TargetName abbr

# 經 bbflow
bbflow hunt target --only backup-files
```

### 輸出

```
./backup_files_out/https_target.gov.tw.txt
```

```
[12:34:56] === Backup files hunt: https://target.gov.tw ===
🔴 [P1-CRIT] /backup.zip [200] size=348291842 type=application/zip magic=PK\x03\x04
🔴 [P1-CRIT] /db.sql [200] size=128492 magic=SQL dump
🟠 [P2-HIGH] /www.tar.gz [200] size=84728341 magic=1f8b
🟡 [P3-MED]  /backup/ [200] Index-of directory listing
```

## 覆蓋的候選清單

### 壓縮封存（按命中率排序）

| 檔名 | 備註 |
|------|------|
| `/backup.zip` `/backup.tar.gz` `/backup.tar` `/backup.rar` `/backup.7z` | 最常中 |
| `/www.zip` `/www.tar.gz` `/www.rar` `/www.7z` | Apache 常見 |
| `/web.zip` `/wwwroot.zip` `/website.zip` `/site.zip` | IIS / 混合 |
| `/admin.zip` `/src.zip` `/app.zip` `/code.zip` | |
| `/bak.zip` `/bak.tar.gz` `/old.zip` `/oldsite.zip` | |
| `/{hostname}.zip` `/{hostname}.tar.gz` | 動態推導 |
| `/{domain-no-tld}.zip` | e.g. `target` without `.gov.tw` |
| `/{abbr}.zip` | 自訂參數 |

### 資料庫 dump

```
/db.sql, /dump.sql, /database.sql, /data.sql
/mysql.sql, /backup.sql, /old.sql
/db.zip, /db.tar.gz, /dump.zip, /database.zip
/sql.sql, /sql.zip
```

### 單檔備份（透過 FAST=1 仍保留高信度）

```
/config.php.bak       /config.php.old       /config.php~
/database.php.bak     /settings.py.bak
/.env.bak             /.env.backup
/web.config.bak       /wp-config.php.bak    /wp-config.php.old
/index.php.bak        /index.html.bak
```

### Directory listing 檢查

```
/backup/  /backups/  /bak/  /db/  /dbs/
/upload/  /uploads/  /files/  /download/  /downloads/
/old/  /temp/  /tmp/  /archive/  /archives/  /log/  /logs/
```

## 驗證邏輯（本 hunter 的核心）

`check()` 內部流程：

```bash
# 1. HEAD 先看 Content-Type / Content-Length
HEADERS=$(curl -sIk --max-time 6 "$HOST/$PATH")

# 2. 若 200 且 Content-Length > 1024 → range GET 前 8 bytes
MAGIC=$(curl -sk --max-time 6 -r 0-7 "$HOST/$PATH" | xxd -p)

# 3. 比對 magic
case "$MAGIC" in
  504b0304*)         echo "ZIP archive" ;;
  1f8b08*)           echo "gzip" ;;
  377abcaf*)         echo "7z" ;;
  526172211a*)       echo "RAR" ;;
  53514c697465*)     echo "SQLite" ;;
  2d2d2044756d70*)   echo "SQL dump" ;;
esac
```

> **關鍵**：即使 HEAD 回 200，很多 SPA 會回 index.html。Magic byte 比對是唯一可靠的確認方式。

## 配合 content-length 判斷

| Content-Length | 通常是 |
|----------------|--------|
| < 1KB | 誤報（SPA 回 index.html）|
| 1KB - 10KB | 小 config 檔 / 空壓縮檔 |
| 10KB - 100MB | 真實備份 |
| > 100MB | 全站備份（政府案超常見）|

> **下載建議**：檔案太大不要完整下載浪費頻寬，用 `curl -r 0-10485760` 抓前 10MB 即可查看內容（`unzip -l`、`tar -tzf`）。

## 政府案專用候選字典

在 `tools/payloads/gov-backup.txt`（用 `-w` 參數傳入）：

```
ministry.zip
mof.zip
moea.zip
moj.zip
exam.zip
old-site.zip
archive-2020.zip
archive-2021.zip
archive-2022.zip
data-2024.zip
final.zip
final-backup.zip
release.zip
publish.zip
```

## 擴充：加自訂候選

編輯 `hunt-backup-files.sh`，在 `CANDIDATES` 陣列加：

```bash
CANDIDATES+=(
  "/your-custom.zip"
  "/project-name.tar.gz"
  "/company-internal.sql"
)
```

## 跟其他 hunter 的關係

```
backup-files → 找到 /backup.zip → 解壓 → git-exposure 掃 .git/
backup-files → 找到 /db.sql    → grep -iE "password|secret|token|key"
backup-files → 找到 /backup/   → 進 directory listing → 抓子檔案
config-leak  → 發現 .env       → backup-files 試 .env.bak / .env.backup
```

## 下載與分析流程（發現 backup.zip 後）

```bash
# 1. 下載（用 -C 續傳，若連線不穩）
curl -sk -C - -O "https://target.gov.tw/backup.zip"

# 2. 檢視清單（不解壓）
unzip -l backup.zip | head -50

# 3. 擷取有價值的檔案
unzip backup.zip -d ./dump "*.env" "*.sql" "wp-config.php" "application.yml"

# 4. grep 敏感內容
grep -rEi "password|secret|api[_-]?key|token|mysql|aws" ./dump/

# 5. 若是 DB dump，快速看 schema
head -500 ./dump/database.sql | grep -E "CREATE TABLE|INSERT INTO"
```

## 報告寫法

**報告重點：**
- 附上 `curl -sI` 輸出證明檔案存在 + 大小（不要真的完整下載）
- 附上 magic bytes 前幾 hex（e.g. `50 4b 03 04` for ZIP）
- 列出解壓後發現的敏感檔名（不揭露內容）
- 對於 DB dump，列出表格結構（不揭露資料）

範例：

```markdown
## 漏洞概述
https://target.gov.tw/backup.zip 可匿名下載，檔案大小 348MB，內含全站原始碼 + DB dump。

## 重現步驟
```bash
# 1. HEAD 確認可下載
curl -sI https://target.gov.tw/backup.zip
# HTTP/1.1 200 OK
# Content-Type: application/zip
# Content-Length: 348291842

# 2. Range GET 前 8 bytes 確認 magic
curl -sk -r 0-7 https://target.gov.tw/backup.zip | xxd
# 00000000: 504b 0304 1400 0000  PK......

# 3. 抓前 10MB 看結構
curl -sk -r 0-10485760 -O https://target.gov.tw/backup.zip
unzip -l backup.zip | head -50
# (列出：application.yml / database.sql / src/ / uploads/)
```

## 影響
- 網站完整原始碼外洩 (src/)
- DB schema 外洩 (database.sql, 前 10MB 見 CREATE TABLE 142 張表)
- 可能含硬編碼憑證（application.yml 已確認含 DB_PASSWORD）

## Severity
P2-HIGH（若驗證 DB 能連線 → P1-CRIT）
```

## 關聯文件

- [03-xray-rules-reference.md](03-xray-rules-reference.md) §「Backup / Dump」
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) §#5
- [10-hunter-config-leak.md](10-hunter-config-leak.md)
- [28-tool-git-dumper.md](28-tool-git-dumper.md)
