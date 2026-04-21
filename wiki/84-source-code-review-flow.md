---
type: wiki
category: flow
tool: semgrep,grep,ripgrep,ast-grep
status: active
last-updated: 2026-04-21
---

# Source Code Review Flow（2026 版）

> **用途：** 找到 .git / source map / GitHub repo / decompile APK / ghidra binary 後，該怎麼「在 2 小時內找到 3 個高價值漏洞」。本文分語言列出 sink、regex、快速 tool。

## 0. 流程骨架

```
1. 識別語言 / framework
2. 找 entrypoint（router / controller）
3. 跟 user input 流向（taint tracking）
4. 找危險 sink
5. 驗 sanitize / validation
6. 寫 PoC
```

## 1. 通用 regex（任何語言）

### 1.1 Credentials

```bash
rg -i 'api[_-]?key|secret|password|token|auth' --type-add 'all:*' -t all
rg '(aws_access_key|aws_secret|sk_live_|pk_live_|AKIA[0-9A-Z]{16})'
rg '(-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----)'
```

工具：`trufflehog`, `gitleaks`, `detect-secrets`。

```bash
trufflehog filesystem ./source --json
gitleaks detect --source ./source --report-format json
```

### 1.2 URLs / Internal hosts

```bash
rg 'https?://' | grep -v 'github.com\|google.com\|w3.org'
rg '(internal|admin|staging|dev)\.[a-z-]+\.'
rg '10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.'
```

### 1.3 SQL

```bash
rg -i 'select\s+.*from|insert\s+into|update\s+.*set|delete\s+from'
rg 'execute\(|executequery\(|rawQuery\('
```

### 1.4 Command execution

```bash
rg 'exec\(|system\(|popen\(|spawn\(|Runtime\.getRuntime'
```

## 2. PHP

### 2.1 File inclusion

```bash
rg 'include\s*\(|include_once\s*\(|require\s*\(|require_once\s*\('
rg 'file_get_contents\s*\(|fopen\s*\(|readfile\s*\('
```

Sink + `$_GET`/`$_POST`/`$_REQUEST` 在同個 function = LFI / RFI。

### 2.2 SQL

```bash
rg 'mysql_query\(|mysqli_query\(|pg_query\('
rg '\$(pdo|db|conn)->query\('
rg '->raw\('       # Laravel raw query
```

### 2.3 Command

```bash
rg 'shell_exec\(|exec\(|system\(|passthru\(|popen\(|proc_open\(|backtick'
```

### 2.4 Deserialization

```bash
rg 'unserialize\('
```

### 2.5 XXE

```bash
rg 'simplexml_load_string|DOMDocument|SoapClient'
rg 'LIBXML_NOENT'  # if set → 啟用 entity expansion
```

### 2.6 Laravel / Symfony 重點檔

```
.env
config/database.php
routes/web.php / routes/api.php
app/Http/Controllers/
app/Http/Middleware/
```

## 3. Node.js / JavaScript

### 3.1 Command

```bash
rg 'child_process\.(exec|execSync|spawn|execFile)'
rg 'require\([\'"]child_process'
```

### 3.2 SQL

```bash
rg 'raw\(|\.query\([\'"][^?]*\+'
rg 'sequelize\.(query|literal)'
rg 'knex\.raw'
```

### 3.3 Template injection (SSTI)

```bash
rg 'ejs\.render|pug\.render|handlebars|dust\.render'
rg 'new Function\('
rg 'eval\('
```

### 3.4 Deserialization

```bash
rg 'node-serialize|unserialize'
```

### 3.5 Prototype pollution

```bash
rg '__proto__|constructor\.prototype|Object\.assign'
rg 'lodash\.(merge|defaultsDeep|set)'
```

### 3.6 Express routes

```bash
rg 'app\.(get|post|put|delete|patch)\('
rg 'router\.(get|post|put|delete|patch)\('
```

### 3.7 Key files

```
package.json          # dependencies / scripts
.env.local
config/*.json
next.config.js        # 有時 leak env
```

## 4. Python

### 4.1 Command

```bash
rg 'os\.system|subprocess\.(run|Popen|call|check_output)'
rg 'shell=True'
```

### 4.2 Eval

```bash
rg '\beval\(|\bexec\('
rg 'pickle\.(loads|load)'
rg 'yaml\.load\('     # without SafeLoader
```

### 4.3 SQL

```bash
rg 'cursor\.execute\(|cursor\.executemany\('
rg '\.raw\(|\.extra\('       # Django
rg '(text|sqlalchemy\.text)\('
```

### 4.4 SSTI (Flask/Django)

```bash
rg 'render_template_string|Template\('
rg 'Mark(Safe|safe)'
```

### 4.5 Deserialization

```bash
rg 'pickle\.|cPickle|marshal\.'
rg 'yaml\.load\b'             # dangerous 若無 Loader=SafeLoader
```

### 4.6 Django / Flask entrypoint

```
urls.py / views.py
app.py / main.py
requirements.txt / pyproject.toml
settings.py           # SECRET_KEY, DB
```

## 5. Java

### 5.1 Command

```bash
rg 'Runtime\.getRuntime\(\)\.exec|ProcessBuilder'
```

### 5.2 SQL

```bash
rg 'createQuery|createNativeQuery|createStatement'
rg 'prepareStatement\(' -A 5 | rg '\+ '     # concat in prepare
```

### 5.3 Deserialization

```bash
rg 'ObjectInputStream|readObject|XMLDecoder|JsonMapper.*DefaultTyping'
rg 'ysoserial'
```

### 5.4 XXE

```bash
rg 'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory'
rg 'setFeature.*disallow-doctype'   # if missing → XXE
```

### 5.5 Log4Shell

```bash
rg 'log4j' --no-ignore
cat pom.xml | grep -i log4j
```

### 5.6 Spring

```bash
rg '@RequestMapping|@GetMapping|@PostMapping|@RequestBody'
rg '@PreAuthorize|@Secured'
```

### 5.7 Key files

```
pom.xml / build.gradle
application.properties / application.yml
src/main/resources/
```

## 6. Go

### 6.1 Command

```bash
rg 'exec\.Command\(|exec\.CommandContext\('
```

### 6.2 SQL

```bash
rg 'db\.Exec\(|db\.Query\(|db\.QueryRow\('
rg 'fmt\.Sprintf.*SELECT|fmt\.Sprintf.*INSERT'  # concat
```

### 6.3 SSRF

```bash
rg 'http\.Get\(|http\.Post\('
rg 'net\.Dial\('
```

### 6.4 Template

```bash
rg 'text/template|html/template'
# html/template auto-escape，text/template 不
```

## 7. Ruby / Rails

### 7.1 Command

```bash
rg '\bsystem\(|\bexec\(|%x\(|\bbacktick|Kernel\.open'
```

### 7.2 SQL

```bash
rg 'find_by_sql|execute\(|exec_query'
rg 'where\([\'"][^?]*#{'       # interpolation → SQLi
```

### 7.3 Deserialization

```bash
rg 'Marshal\.load|YAML\.load'  # not safe_load
```

### 7.4 Mass assignment

```bash
rg 'params\.permit'            # 檢查 permit list
rg 'params\[.*\]\.permit!'     # 全開
```

### 7.5 Rails routes

```
config/routes.rb
app/controllers/
app/models/
```

## 8. C / C++

### 8.1 Buffer overflow

```bash
rg '\b(strcpy|strcat|sprintf|gets|scanf)\b'
```

### 8.2 Format string

```bash
rg 'printf\s*\([^,]*\);|fprintf[^,]*,\s*[^"]*\);'
```

### 8.3 Integer overflow

```bash
rg 'malloc\(.*\*|alloca\('
```

### 8.4 Use after free

ASan / Valgrind 跑 runtime 較準。

## 9. Semgrep（自動化）

```bash
# 安裝
pip install semgrep
# 或
brew install semgrep

# Registry rules（好用）
semgrep --config=p/security-audit ./source
semgrep --config=p/owasp-top-ten ./source
semgrep --config=p/javascript ./source
semgrep --config=p/php ./source

# 輸出 JSON 方便後處理
semgrep --config=p/security-audit --json ./source > findings.json
```

## 10. ast-grep（結構化搜尋）

```bash
brew install ast-grep

# 找所有 eval 直接接 user input
ast-grep run -l js -p 'eval($_)'

# 複雜 pattern
ast-grep run -l python -p 'subprocess.$FN($CMD, shell=True)'
```

## 11. 優先順序（2 小時內最高 ROI）

```
1. Credentials（trufflehog 跑全 repo）
2. Hardcoded API keys (AWS/GCP/Stripe)
3. .env / config 類檔案 → 找連線字串
4. Router / route file → 找沒 auth 的 endpoint
5. Exec / system call → 追 user input
6. SQL query 中 string concat
7. File include / read → 追 user input
8. Deserialize → 追 data 來源
9. XML / YAML parser 設定
10. 版本檢查：dependency 是否有 CVE
```

## 12. 工具一覽

| 工具 | 用途 | URL |
|------|------|-----|
| trufflehog | Credentials scan | https://github.com/trufflesecurity/trufflehog |
| gitleaks | Git secret scan | https://github.com/gitleaks/gitleaks |
| detect-secrets | Yelp secret scanner | https://github.com/Yelp/detect-secrets |
| semgrep | Static analysis with rule sets | https://semgrep.dev/ |
| ast-grep | Structural search | https://github.com/ast-grep/ast-grep |
| ripgrep | Fast grep | https://github.com/BurntSushi/ripgrep |
| bandit | Python SAST | https://github.com/PyCQA/bandit |
| brakeman | Rails SAST | https://brakemanscanner.org/ |
| njsscan | Node.js SAST | https://github.com/ajinabraham/njsscan |
| sonarqube | Enterprise SAST | https://www.sonarsource.com/ |
| SAST-scan (Shiftleft) | Multi-lang | https://github.com/ShiftLeftSecurity/sast-scan |
| CodeQL | GitHub advanced | https://codeql.github.com/ |

## 13. 快速打法 checklist

```
[ ] trufflehog + gitleaks 跑一次
[ ] 搜 .env / config/*.{json,yml,properties}
[ ] 搜 hardcoded host / internal.*
[ ] 列 routes → 標 no-auth 的
[ ] Regex 跑本文表 1-8
[ ] semgrep p/security-audit 跑
[ ] 對照 package.json / pom.xml / requirements 看 CVE（snyk db）
[ ] Readme / CI 設定 → 可能 leak CI secret
[ ] Test fixtures → 常含真實資料
```

## 關聯文件

- [42-gitleaks-cheatsheet.md](42-gitleaks-cheatsheet.md) — gitleaks 用法
- [43-semgrep-cheatsheet.md](43-semgrep-cheatsheet.md) — semgrep 規則
- [73-ssti-deep.md](73-ssti-deep.md) — template injection sinks
- [72-sqli-deep.md](72-sqli-deep.md) — SQL sink patterns
- OWASP Code Review Guide：https://owasp.org/www-project-code-review-guide/
- SEMgrep rules registry：https://semgrep.dev/explore
