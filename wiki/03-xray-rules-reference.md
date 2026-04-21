---
type: wiki
category: reference
status: active
last-updated: 2026-04-21
source: https://github.com/chaitin/xray
---

# xray 規則本地化速查

> [ChaitinTech/xray](https://github.com/chaitin/xray) 社群版的規則本身開源 (phantasm YAML 規則)，商業版 PoC 閉源。這份文件是把 xray **穩定可用** 的規則分類，對照到 bbflow hunter 或 nuclei template，讓你不用裝 xray 也能跑。

## xray 規則分類

xray 規則總類分：
- **`baseline`** — 基礎安全檢測（CORS、CSP、CRLF、cookie flags、X-Frame-Options）
- **`config-leak`** — 敏感配置檔洩漏
- **`dirscan`** — 目錄掃描（備份、SCM、IDE）
- **`jsonp`** — JSONP 洩漏
- **`redirect`** — 開放重定向
- **`ssrf`** — SSRF 偵測
- **`crlf`** — CRLF injection
- **`sql-injection`** — SQL 注入（僅錯誤類型）
- **`xss`** — 反射 XSS
- **`xxe`** — XXE
- **`path-traversal`** — 路徑遍歷
- **`struts2`** — OGNL/Struts2
- **`shiro`** — Shiro rememberMe
- **`fastjson`** — Fastjson 反序列化
- **`brute-force`** — 弱密碼
- **`phantasm`** — PoC-based（CVE / 已知漏洞）

## 一、xray → bbflow hunter 對照

| xray 規則類 | bbflow hunter | 備註 |
|-----------|--------------|------|
| `config-leak` + `dirscan` | `hunt-config-leak.sh` | 100+ path，content-match 驗證 |
| `brute-force` | `hunt-weak-login.sh` | vendor panel 偵測 + default cred |
| `dirscan` backup | `hunt-backup-files.sh` | 41 個靜態 + 動態候選 |
| `baseline` CORS | `hunt-cors-reflect.sh` | 4 層反射 + credentials:true |
| `redirect` | `hunt-open-redirect.sh` | redirect param 變體 |
| `shiro` | `hunt-weak-login.sh` | rememberMe cookie 檢測 |
| `xss` | `hunt-dalfox-xss.sh` + `hunt-crawl-chain.sh` | nuclei DAST + dalfox |
| `sql-injection` | `hunt-crawl-chain.sh` | gf sqli + nuclei DAST |
| `ssrf` | `hunt-crawl-chain.sh` | gf ssrf + nuclei DAST |
| `path-traversal` | `hunt-crawl-chain.sh` | gf lfi + nuclei DAST |
| `phantasm` (CVE) | `hunt-nuclei` + `hunt-nuclei-wp` | 官方 templates + Wordfence |

## 二、xray `config-leak` / `dirscan` 路徑總整理

xray 最穩的就是這一類。以下是從開源版抽出的完整路徑清單（都寫進了 `hunt-config-leak.sh`）：

### SCM 洩漏

```
/.git/config
/.git/HEAD
/.git/index
/.git/logs/HEAD
/.git/refs/heads/master
/.git/packed-refs
/.svn/entries
/.svn/wc.db
/.svn/all-wcprops
/.hg/hgrc
/.hg/store/00manifest.i
/.bzr/branch-format
/CVS/Root
/CVS/Entries
```

### IDE / 編輯器殘留

```
/.idea/workspace.xml
/.idea/modules.xml
/.idea/misc.xml
/.idea/vcs.xml
/.vscode/settings.json
/.vscode/launch.json
/.DS_Store
/.ftpconfig
/.phpintel
/.project
/.classpath
/.settings/
```

### 環境變數 / 設定檔

```
/.env
/.env.local
/.env.production
/.env.development
/.env.backup
/.env.bak
/.env.example
/.env.sample
/.env.test
/.env.stage
/env.js
/config.js
/config.json
/config.php
/config.yaml
/config.yml
/appsettings.json
/appsettings.Development.json
/application.properties
/application.yml
/application-dev.yml
/application-prod.yml
```

### 依賴 / 建置

```
/composer.json
/composer.lock
/package.json
/package-lock.json
/yarn.lock
/Gemfile
/Gemfile.lock
/requirements.txt
/Pipfile
/Pipfile.lock
/pom.xml
/build.gradle
/go.mod
/go.sum
/.gitignore
/Dockerfile
/docker-compose.yml
/Jenkinsfile
/.gitlab-ci.yml
/.travis.yml
/.circleci/config.yml
/buildspec.yml
```

### Backup / Dump

```
/backup.zip, /backup.tar.gz, /backup.tar, /backup.rar, /backup.7z, /backup.sql
/bak.zip, /bak.tar.gz
/www.zip, /www.tar.gz, /www.rar, /www.7z
/web.zip, /wwwroot.zip, /website.zip, /site.zip
/db.sql, /db.zip, /dump.sql, /dump.zip
/database.sql, /data.sql
/admin.zip, /src.zip, /app.zip
/{hostname}.zip, /{hostname}.tar.gz, /{hostname}.sql
```

### WEB-INF / J2EE

```
/WEB-INF/web.xml
/WEB-INF/classes/
/WEB-INF/lib/
/WEB-INF/classes/config.properties
/WEB-INF/classes/db.properties
/WEB-INF/classes/application.xml
/META-INF/MANIFEST.MF
```

### Debug / Info endpoints

```
/phpinfo.php, /info.php, /test.php, /debug.php
/server-status, /server-info
/status
/.user.ini
/php_info.php
```

### Apache / Nginx / IIS

```
/.htaccess
/.htpasswd
/web.config
/nginx.conf
/httpd.conf
/crossdomain.xml
/clientaccesspolicy.xml
```

### Spring Boot Actuator

```
/actuator
/actuator/env
/actuator/heapdump
/actuator/mappings
/actuator/configprops
/actuator/beans
/actuator/loggers
/actuator/httptrace
/actuator/threaddump
/actuator/jolokia
/actuator/caches
/actuator/metrics
/env
/heapdump
/mappings
/beans
/configprops
```

### Swagger / API docs

```
/swagger-ui.html
/swagger/index.html
/swagger/ui/index
/swagger-ui/index.html
/swagger.json
/swagger.yaml
/openapi.json
/openapi.yaml
/v2/api-docs
/v3/api-docs
/api-docs
/docs
/documentation
```

### Other high-value

```
/phpmyadmin/
/pma/
/druid/index.html
/druid/login.html
/nacos/
/solr/
/kibana/
/grafana/
/jenkins/
/elasticsearch/_cat/indices
/manager/html
```

## 三、xray `baseline` 類（加到 hunt 流程）

這些 xray 一定跑 — 低噪音、高 ROI：

| 檢測項 | 工具 | 說明 |
|-------|------|------|
| CORS misconfig | `hunt-cors-reflect.sh` | Origin reflect / null origin / regex bypass |
| CSP 缺失 | `nuclei -t misconfiguration/missing-csp.yaml` | 單獨 P5，搭配 XSS 升級 |
| CRLF injection | `nuclei -t vulnerabilities/crlf-injection` | 不過現代 WAF 都擋 |
| Cookie 沒 HttpOnly/Secure | 手動 `curl -I` | P5 Info |
| X-Frame-Options 缺失 | 手動 `curl -I` | Clickjacking P5 |
| 反射 email（user enum） | `hunt-user-enum.sh` | 單獨 P5，串鏈 P3 |
| HTTP method 過多 | 手動 `curl -X OPTIONS` | TRACE / PUT / DELETE |

## 四、xray `phantasm` 類（CVE/PoC）

xray 商業版的 PoC 是閉源的，但社群版 `phantasm` 有幾十個。bbflow 的替代方案：

```bash
# 用 nuclei 官方 templates 覆蓋 phantasm 類
bbflow hunt target --only nuclei,nuclei-wp

# 特定高價值 CVE 快速檢測
nuclei -u https://target \
  -tags cve,oast,struts,fastjson,shiro,thinkphp,weblogic,tomcat \
  -severity high,critical \
  -silent
```

## 五、xray 規則實作範例（參考用）

xray 的 YAML 規則長這樣：

```yaml
name: poc-yaml-git-source-code
rules:
  - method: GET
    path: /.git/config
    expression: |
      response.status == 200 &&
      response.body.bcontains(b"[core]") &&
      response.body.bcontains(b"repositoryformatversion")
```

這個規則在 bbflow 裡對應：

```bash
# hunt-config-leak.sh 第 55 行
probe ".git/config" "/.git/config" 'repositoryformatversion|\[core\]|\[remote ' critical
```

邏輯一樣：`HTTP 200 + body match content regex`。

## 六、把 xray 規則轉成 nuclei template（進階）

如果想把某個 xray YAML 轉成 nuclei：

**xray:**
```yaml
rules:
  - method: GET
    path: /actuator/env
    expression: response.status==200 && response.body.bcontains(b"activeProfiles")
```

**nuclei 等價：**
```yaml
id: actuator-env-exposure
info:
  name: Spring Boot Actuator env
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/actuator/env"
    matchers:
      - type: word
        words:
          - "activeProfiles"
          - "propertySources"
        part: body
        condition: or
      - type: status
        status:
          - 200
```

把這種 template 丟進 `tools/nuclei-templates/bb-recon/` 就會被 bbflow 的 `nuclei` hunter 自動跑。

## 七、跑 xray（若真的要用商業版）

```bash
# Docker 版（社群版 phantasm 規則）
docker run --rm -it -v $PWD:/data chaitin/xray webscan \
  --basic-crawler https://target.gov.tw \
  --html-output result.html

# 重要：社群版可 webscan 但 phantasm 很有限
# 商業版授權要向長亭科技申請
```

## 關聯文件

- [10-hunter-config-leak.md](10-hunter-config-leak.md)
- [11-hunter-weak-login.md](11-hunter-weak-login.md)
- [12-hunter-backup-files.md](12-hunter-backup-files.md)
- [24-tool-nuclei.md](24-tool-nuclei.md)
