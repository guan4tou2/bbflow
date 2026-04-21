---
type: wiki
category: tool
tool: katana
status: active
last-updated: 2026-04-21
source: https://github.com/projectdiscovery/katana
---

# Tool: katana（主動爬蟲）

> **用途：** 現代 SPA 友善的爬蟲 — 會執行 JS、抽 endpoint、從 form 抽 param。比 hakrawler 更深，比 Burp Spider 更快。

## 安裝

```bash
# 官方 binary（推薦）
go install github.com/projectdiscovery/katana/cmd/katana@latest

# 或用 pdtm
pdtm -i katana

# 或 Homebrew（較舊）
brew install katana
```

## 基本用法

```bash
# 單一目標爬 depth=3
katana -u https://target.com -d 3 -silent

# 存活目標列表
katana -list alive.txt -silent

# 輸出到檔案
katana -u https://target.com -d 5 -silent -o endpoints.txt
```

## 必學 flag

| Flag | 用途 |
|------|------|
| `-d 5` | Crawl depth（往下 5 層） |
| `-jc` | **JavaScript crawling** — 從 JS 抽 endpoint（關鍵 flag） |
| `-js-crawl` | 同 `-jc` |
| `-headless` | 啟動 headless Chrome（需 Chrome 裝好）|
| `-aff` | Automatic form fill |
| `-fx` | Field extraction（form input 也抓） |
| `-ef woff,css,png,svg,jpg,woff2,jpeg,gif` | Exclude extension |
| `-em js,json,xml` | 只抓這些 extension |
| `-cs "*.target.com"` | Crawl scope（限制在某個 domain） |
| `-c 10` | Concurrency |
| `-rl 100` | Rate limit（100 req/s） |
| `-timeout 10` | Per-request timeout |
| `-ct 60` | Total crawl time limit |
| `-silent` | 只輸出結果 |
| `-o file.txt` | 輸出檔 |
| `-jsonl` | JSON lines 格式 |
| `-kf robotstxt,sitemapxml` | Known files 也抓 |

## 推薦組合

### 一般 web app

```bash
katana -u https://target.com \
  -d 5 \
  -jc \
  -aff \
  -fx \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif,tiff,tif \
  -silent -o katana.txt
```

### SPA / 重 JS 的站

```bash
katana -u https://target.com \
  -d 5 \
  -jc \
  -headless \
  -xhr \
  -aff \
  -silent -o katana_spa.txt
```

`-xhr` 會攔截 XHR request → 抓 API endpoint。

### 政府站（低噪音）

```bash
katana -u https://target.gov.tw \
  -d 3 \
  -jc \
  -rl 10 \
  -c 3 \
  -timeout 15 \
  -silent -o katana.txt
```

### 多目標 + 範圍限制

```bash
katana -list subs.txt \
  -cs "*.target.com" \
  -d 3 \
  -jc \
  -silent -o katana_all.txt
```

### 帶 auth token（已登入狀態）

```bash
katana -u https://target.com \
  -d 5 -jc \
  -H "Authorization: Bearer xxx" \
  -H "Cookie: session=yyy" \
  -silent -o katana_auth.txt
```

## 配合其他工具

### katana → uro → gf

```bash
# 1. 爬
katana -u https://target.com -d 5 -jc -silent -o katana.txt

# 2. 去重
cat katana.txt | uro > endpoints.txt

# 3. 分類
gf xss < endpoints.txt > gf_xss.txt
gf sqli < endpoints.txt > gf_sqli.txt
```

### katana → dalfox

```bash
katana -u https://target.com -d 5 -jc -silent | \
  grep "=" | \
  dalfox pipe --silence
```

### katana + gau + waybackurls（全面覆蓋）

```bash
# 這就是 bbflow 的 crawl-chain hunter 在做的事
(
  katana -u https://target.com -d 5 -jc -silent
  echo target.com | gau --subs
  echo target.com | waybackurls
) | sort -u | uro > endpoints.txt
```

## 輸出格式

### 預設（URL 一行一個）

```
https://target.com/
https://target.com/api/users
https://target.com/api/users/1
https://target.com/admin?action=list
```

### JSONL（`-jsonl`）

```json
{"timestamp":"...","request":{"method":"GET","endpoint":"https://target/admin"},"response":{"status_code":200}}
```

JSONL 輸出可用 `jq` 過濾：

```bash
katana -u https://target.com -jsonl -silent | \
  jq -r 'select(.response.status_code == 200) | .request.endpoint'
```

## bbflow 整合

katana 被 `hunt-crawl-chain.sh` 在 Stage 1 呼叫：

```bash
tools/hunters/hunt-crawl-chain.sh https://target.com
```

或經 bbflow：

```bash
bbflow hunt target --only crawl-chain
```

環境變數：

| 變數 | 影響 |
|------|------|
| `DEPTH` | `katana -d $DEPTH`（預設 5） |
| `KATANA_EXTRA_ARGS` | 額外 flag（不常用）|

## 常見問題

### Q：headless mode 卡住？
A：確認 Chrome 已裝 + `which google-chrome` / `which chromium`。macOS：`brew install chromium`。

### Q：爬到一半 timeout？
A：降低 `-c` / `-rl` / 加 `-timeout 15`。或用 `-ct 300` 限制總時間。

### Q：爬不到 API endpoint？
A：加 `-jc -headless -xhr`。若 SPA 用 graphql，直接找 `/graphql` endpoint。

### Q：爬到 scope 外的 URL？
A：用 `-cs "*.target.com"` 限制。

## 效能調校

```bash
# 高速（自用機，對方 CDN/CF 擋住時很有用）
katana -u target -d 5 -jc -c 50 -rl 500 -silent

# 低速（對政府 / 弱 server）
katana -u target -d 3 -jc -c 2 -rl 5 -timeout 20 -silent

# 只抓 HTML + JS
katana -u target -d 5 -em html,js -silent
```

## 關聯文件

- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md)
- [21-tool-gau.md](21-tool-gau.md)
- [23-tool-arjun.md](23-tool-arjun.md)
- [25-tool-dalfox.md](25-tool-dalfox.md)
