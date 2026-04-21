---
type: wiki
category: tool
tool: nuclei
status: active
last-updated: 2026-04-21
source: https://github.com/projectdiscovery/nuclei
---

# Tool: nuclei（YAML-based DAST scanner）

> **用途：** 最主流的 template-based 漏洞 scanner。**4000+ 官方 template** 覆蓋 CVE / exposure / misconfig / default-login / CORS / etc。
> 搭配 `hunt-nuclei-deep.sh` 做全覆蓋見 [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md)。

## 安裝

```bash
# 推薦 Go install
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Homebrew
brew install nuclei

# 首次安裝完要更新 template
nuclei -update-templates
nuclei -update

# 查看版本
nuclei -version
```

## 基本用法

```bash
# 單一目標
nuclei -u https://target.com -silent

# 從 list
nuclei -l alive.txt -silent

# 指定 template 目錄
nuclei -u https://target -t ~/nuclei-templates/http/cves/ -silent

# 指定 tag
nuclei -u https://target -tags cve,rce -silent

# 指定 severity
nuclei -u https://target -severity high,critical -silent

# 輸出
nuclei -u https://target -silent -o nuclei.txt
nuclei -u https://target -silent -json-export nuclei.json
```

## 必學 flag

| Flag | 用途 |
|------|------|
| `-u URL` | 單一目標 |
| `-l file` | Target list |
| `-t path` | Template 路徑（可多次） |
| `-tags tag1,tag2` | 只跑指定 tag |
| `-etags tag` | 排除 tag |
| `-severity info,low,medium,high,critical` | 嚴重度過濾 |
| `-c 25` | Concurrency |
| `-rate-limit 150` `-rl 150` | Rate limit |
| `-timeout 10` | Per-request timeout |
| `-retries 1` | Retry 次數 |
| `-H 'Header: value'` | 加 header |
| `-dast` | DAST mode（對 param fuzz） |
| `-ni` | No interactsh（不連 OAST server） |
| `-iserver oast.pro` | 指定 interactsh server |
| `-silent` | 只輸出 finding |
| `-v` | Verbose |
| `-debug` | Debug |
| `-stats` | 顯示進度 |
| `-nmhe` | No template hash 驗證（快） |
| `-o file` | Text output |
| `-json-export file.json` | JSON export |
| `-jsonl-export file.jsonl` | JSONL |
| `-newer-than 7d` | 只用最近 7 天的 template |
| `-exclude-matchers matcher-name` | 排除特定 matcher |

## 重要 tag 分類

### 按漏洞類型

```
xss, dom                 → XSS
sqli, sql-injection      → SQL Injection
ssrf                     → SSRF
lfi, file, traversal     → LFI / Path Traversal
rce, cmd, command        → RCE
ssti                     → Template injection
xxe                      → XXE
redirect, open-redirect  → Open Redirect
cors                     → CORS misconfig
takeover                 → Subdomain Takeover
```

### 按暴露類型

```
exposure, exposed        → 通用暴露
disclosure               → 資訊洩漏
token, key               → API token / API key
secret, apikey           → Secret 類
debug, trace             → Debug endpoint
phpinfo                  → PHP info
actuator, springboot     → Spring Boot Actuator
prometheus, jmx          → 監控面板
```

### 按功能

```
panel, exposed-panel     → 管理介面
default-login, default-logins, weak-credential  → 預設帳密
misconfig, misconfiguration  → 通用錯誤設定
```

### 按技術

```
wordpress, wp            → WordPress
joomla                   → Joomla
drupal                   → Drupal
jenkins                  → Jenkins
gitlab                   → GitLab
oracle                   → Oracle
log4j                    → Log4Shell
spring                   → Spring
fastjson                 → Fastjson
shiro                    → Apache Shiro
struts                   → Struts2
```

### 按 CVE 年份

```
cve,2023
cve,2024
cve,2025
cve,2026
```

## 推薦組合

### 全面掃（官方 templates）

```bash
nuclei -u https://target \
  -severity low,medium,high,critical \
  -silent \
  -o nuclei_all.txt
```

### 高價值快速掃

```bash
nuclei -u https://target \
  -tags cve,rce,sqli,xss,ssrf,lfi,default-login,exposure \
  -severity high,critical \
  -silent \
  -o nuclei_hit.txt
```

### 政府案低噪音

```bash
nuclei -u https://target.gov.tw \
  -tags exposure,disclosure,phpinfo,actuator,springboot,default-login \
  -severity medium,high,critical \
  -rate-limit 10 \
  -c 5 \
  -timeout 15 \
  -silent \
  -o nuclei_gov.txt
```

### DAST 模式（對 URL params fuzz）

```bash
nuclei -l endpoints_with_params.txt \
  -dast \
  -tags xss,sqli,ssrf,lfi,redirect \
  -silent \
  -o nuclei_dast.txt
```

### CVE 專項（最近兩年）

```bash
nuclei -u https://target \
  -tags cve,2025,2026 \
  -severity high,critical \
  -silent
```

### WordPress 專項（已知 ~200 外掛漏洞）

```bash
nuclei -u https://target/wp \
  -tags wordpress,wp \
  -silent
```

### 自訂 template（bb-recon）

```bash
nuclei -u https://target \
  -t tools/nuclei-templates/bb-recon/ \
  -silent
```

## Template 開發

### 最簡單的 template

```yaml
# http/custom/my-vuln.yaml
id: my-vuln-check
info:
  name: My Vulnerability Check
  author: yourself
  severity: high
  tags: exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/config.inc"

    matchers:
      - type: word
        words:
          - "db_password"
          - "secret_key"
        condition: or
      - type: status
        status:
          - 200
    matchers-condition: and
```

### DAST template

```yaml
id: custom-xss-dast
info:
  name: Reflected XSS
  severity: high
  tags: xss,dast

http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'

    payloads:
      reflection:
        - "'\"><svg onload=alert(1)>"
        - "<script>alert(1)</script>"

    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{reflection}}"

    matchers:
      - type: word
        part: body
        words:
          - "{{reflection}}"
```

## Template 管理

```bash
# 更新 official templates
nuclei -update-templates

# 列出所有 tag
nuclei -tl | awk '{print $NF}' | tr ',' '\n' | sort -u

# 看某 tag 有哪些 template
nuclei -tl -tags xss

# 只跑最近 30 天新增的 template
nuclei -u target -tags cve -newer-than 30d

# 驗證自訂 template 語法
nuclei -t my-template.yaml -validate

# 看 template 詳情
nuclei -tl -silent | grep "log4j"
nuclei -t http/cves/2021/CVE-2021-44228.yaml -silent -verbose
```

## 加速技巧

### 1. 平行度調高

```bash
nuclei -u target -c 50 -rl 500 -silent
```

### 2. 跳過 template hash 驗證

```bash
nuclei -u target -nmhe -silent
```

### 3. 只跑你關心的 severity

```bash
# 其他 severity 直接不載入 template
nuclei -u target -severity critical -silent
```

### 4. 只載入你要的 template

```bash
nuclei -u target -t http/cves/2025/ -silent
```

### 5. -no-store-response 節省記憶體

```bash
nuclei -u target -nsr -silent
```

## 常見問題

### Q：-dast mode 不會觸發
A：必須傳 URL **含 `=` 的 param**。例：`https://target/search?q=test`（OK）vs `https://target/`（不會觸發）。

### Q：template 太多跑不完
A：
- 用 `-tags` 過濾
- 用 `-severity` 限縮
- 用 `-exclude-tags dos,intrusive`

### Q：OAST 連不上
A：
- 加 `-ni` 跳過 OAST（但 blind vuln 掃不到）
- 或用自架 interactsh server（`interactsh-server`）

### Q：被 WAF ban
A：
- `-rate-limit 5 -c 5`
- 加 header：`-H "X-Forwarded-For: 127.0.0.1"`
- 改 User-Agent：`-H "User-Agent: Mozilla/5.0 ..."`

### Q：Template 更新後壞掉
A：`nuclei -update-templates` 偶爾會有 breaking change。rollback：
```bash
cd ~/nuclei-templates
git log --oneline
git checkout <previous-commit>
```

## bbflow 整合

```bash
# 預設 tag 集（hunt-nuclei）
bbflow hunt target --only nuclei

# 深度擴充（所有類別）
bbflow hunt target --only nuclei-deep

# 只跑特定 CATEGORY
CATEGORY=xss,sqli bbflow hunt target --only nuclei-deep
```

## 輔助工具

### interactsh（自架 OAST）

```bash
go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

# 自架（需要公網 domain）
interactsh-server -domain oast.yourdomain.com

# Client 只收 payload
interactsh-client -server oast.yourdomain.com
```

### notify（結果推 Slack / Telegram）

```bash
go install github.com/projectdiscovery/notify/cmd/notify@latest

nuclei -u target -silent | notify -bulk -id telegram
```

## 關聯文件

- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) — 攻擊面完整覆蓋
- [03-xray-rules-reference.md](03-xray-rules-reference.md) — xray → nuclei template 轉換
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) §Stage 9
