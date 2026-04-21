---
type: wiki
category: hunter
hunter: config-leak
status: active
last-updated: 2026-04-21
---

# Hunter: `config-leak`

> **目的：** 對 WAF / 防火牆後的網站，用 **最低噪音**（每個路徑 1 次 GET）偵測 100+ 個常見的敏感檔案暴露。
> **靈感：** [chaitin/xray](https://github.com/chaitin/xray) `config-leak` + `dirscan` 規則類 + Nuclei `exposures/configs`。

## 為什麼值得用

1. **1 GET per path** — WAF 幾乎不會觸發（相比 ffuf/feroxbuster 一次幾百個 request）
2. **Content-match 驗證** — 不是 HTTP 200 就算中，body 必須符合對應的 regex
3. **分級標註** — `P1-CRIT` / `P2-HIGH` / `P3-MED` / `P4-INFO` 四級嚴重度
4. **FAST=1 模式** — 只跑 24 個最高信心的路徑（< 30 秒全部跑完）
5. **zero LLM** — 全部 bash + curl，不依賴外部服務

## 用法

```bash
# 完整掃描（100+ paths）
tools/hunters/hunt-config-leak.sh https://target.gov.tw

# 快速模式（P1/P2 only，< 30 秒）
FAST=1 tools/hunters/hunt-config-leak.sh https://target.gov.tw

# 經 bbflow
bbflow hunt target --only config-leak
```

### 輸出

```
./config_leak_out/https_target.gov.tw.txt
```

格式：
```
[12:34:56] === Config leak hunt: https://target.gov.tw (FAST=0) ===
🔴 [P1-CRIT] .git/config: https://target.gov.tw/.git/config [200]
     evidence: [core] repositoryformatversion = 0 filemode = true ...
🔴 [P2-HIGH] swagger-ui.html: https://target.gov.tw/swagger-ui.html [200]
     evidence: <!DOCTYPE html><html><head><title>Swagger UI</title>
🟡 [P3-MED]  composer.json: https://target.gov.tw/composer.json [200]
```

## 覆蓋的類別（完整清單）

### P1 Critical（FAST=1 也會跑）

| 類別 | 路徑 | 判定 regex |
|------|------|-----------|
| **SCM** | `/.git/config` `/.git/HEAD` `/.git/index` `/.git/logs/HEAD` | `\[core\]`, `ref: refs/heads/`, `DIRC` magic |
| | `/.svn/entries` `/.svn/wc.db` | dir/file, SQLite magic |
| | `/.hg/hgrc` | `\[paths\]` |
| **環境變數** | `/.env` `/.env.local` `/.env.production` `/.env.backup` | `DB_PASSWORD\|APP_KEY\|SECRET_KEY\|AWS_\|_TOKEN` |
| | `/appsettings.json` `/appsettings.Development.json` | `ConnectionStrings`, `Jwt`, `Secret` |
| **IDE** | `/.idea/workspace.xml` | `<project\|<component` |
| **Spring Boot** | `/actuator` `/actuator/env` `/actuator/heapdump` `/env` `/heapdump` | `"activeProfiles"`, `"propertySources"`, `JAVA PROFILE` |
| **WEB-INF** | `/WEB-INF/web.xml` | `<web-app\|<servlet\|<filter` |
| **phpinfo** | `/phpinfo.php` `/info.php` | `phpinfo\(\)\|PHP Version` |
| **Druid** | `/druid/index.html` | `Druid Monitor` |

### P2 High

| 類別 | 路徑 | 判定 |
|------|------|------|
| **Config JS** | `/env.js` `/config.js` `/config.json` | `window\.`, `apiKey`, `"apiKey` |
| **IDE** | `/.idea/modules.xml` `/.vscode/settings.json` `/.DS_Store` | XML/JSON start, `Bud1` magic |
| **Swagger** | `/swagger-ui.html` `/v2/api-docs` `/v3/api-docs` `/openapi.json` | `Swagger UI`, `"swagger"`, `"openapi"` |
| **PHPMyAdmin** | `/phpmyadmin/` `/pma/` | `phpMyAdmin` |
| **Nacos** | `/nacos/` | `Nacos\|nacos-server` |
| **Druid login** | `/druid/login.html` | `Druid Monitor` |
| **Apache** | `/.htaccess` `/server-status` `/server-info` | `RewriteEngine`, `Apache Server Status` |
| **Backup** (P1 實質) | `/backup.zip` `/backup.sql` `/db.sql` `/dump.sql` `/www.zip` | `PK\x03\x04`, `CREATE TABLE`, `INSERT INTO` |
| **SVN wc.db** | `/.svn/wc.db` | `SQLite format` |
| **CI/CD** | `/.gitlab-ci.yml` `/.travis.yml` `/.circleci/config.yml` | `stages:`, `language:` |
| **web.config** | `/web.config` | `<configuration\|<system\.web` |
| **.htpasswd** | `/.htpasswd` | `^[a-zA-Z0-9]+:\$` |

### P3 Medium

| 類別 | 路徑 |
|------|------|
| 依賴管理 | `/composer.json` `/package.json` `/Gemfile` `/requirements.txt` `/pom.xml` `/build.gradle` `/go.mod` |
| Docker | `/Dockerfile` `/docker-compose.yml` `/Jenkinsfile` |
| crossdomain | `/crossdomain.xml` `/clientaccesspolicy.xml` |
| PHP ini | `/.user.ini` |

### P4 Info

| 類別 | 路徑 |
|------|------|
| 機器可讀 | `/sitemap.xml` `/robots.txt` `/.well-known/security.txt` |
| 專案說明 | `/README.md` `/CHANGELOG.md` `/TODO` `/.gitignore` |

## 誤報過濾

config-leak 內建的 content-match 已經濾掉大部分 SPA 假 200。如果你仍然看到誤報：

- **SPA 對所有 path 回 index.html**：可以在 bash 裡加 `Content-Type: text/html` 排除，但 `hunt-config-leak.sh` 已經排除 HTML body 對 binary 類檔案。
- **CDN cache miss 第一次 200**：手動用 `curl -I` 再跑一次確認。
- **Honeypot**：有些政府站會對 `/.git/config` 回假 content。用 `git-dumper` 跟著抓，若抓到的 repo commit 是空的就是 honeypot。

## 進階：自訂路徑

編輯 `hunt-config-leak.sh`，在 `!FAST` 區塊加新規則：

```bash
# 自訂 path 格式：
probe "標籤"  "/path"  'content regex'  severity

# 舉例：公司內部 CMS 的洩漏路徑
probe "MyCMS config"  "/admin/config.inc"  'db_pass|db_user'  critical
```

## 與其他 hunter 的關係

```
config-leak  → 發現 .git/config → git-exposure 還原 repo → trufflehog 掃 history
config-leak  → 發現 /actuator   → actuator-deep 深入探測 /env /heapdump
config-leak  → 發現 swagger     → crawl-chain 吃 swagger endpoints 做 DAST
config-leak  → 發現 /admin      → weak-login 試預設帳密
```

## 報告寫法（範例）

HITCON ZeroDay 送件範例：

```markdown
## 漏洞概述
發現 https://target.gov.tw/.env 可直接下載，內含 DB_PASSWORD、APP_KEY、AWS credentials。

## 重現步驟
```bash
curl -sI https://target.gov.tw/.env
# HTTP/1.1 200 OK
# Content-Type: text/plain

curl -s https://target.gov.tw/.env | head -5
# APP_KEY=base64:xxxxxxxxxxxxx==
# DB_PASSWORD=XXXX
# AWS_ACCESS_KEY_ID=AKIAxxxxx
```

## 影響
- DB 憑證洩漏 → 若 DB 對外開放可直接連線
- AWS credentials 洩漏 → 需進一步驗證 key 是否 active

## 分類
Sensitive Data Exposure > Sensitive Application Data
```

**注意：**
- 不要誇大成 RCE（除非真的登入了）
- 選精準分類，不要選「Disclosure of Secrets For Publicly Accessible Asset」（會自動建議 P1）

## 關聯文件

- [03-xray-rules-reference.md](03-xray-rules-reference.md)
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- [28-tool-git-dumper.md](28-tool-git-dumper.md)
