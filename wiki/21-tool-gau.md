---
type: wiki
category: tool
tool: gau
status: active
last-updated: 2026-04-21
source: https://github.com/lc/gau
ref: https://medium.com/@felixmelvinchitechi/gau-for-recon-91f8b331293d
---

# Tool: gau（Get All URLs）

> **用途：** 從 **Wayback Machine / OTX / Common Crawl / URLScan** 抽目標的歷史 URL。
> 找**已移除 endpoint**、**舊版參數**、**廠商不知道的 staging subdomain** 最好用。

## 安裝

```bash
# 推薦 Go install
go install github.com/lc/gau/v2/cmd/gau@latest

# Homebrew
brew install gau
```

## Config（bbflow 用）

bbflow 已建立 `tools/configs/gau.toml`：

```toml
# 平行度與超時
threads = 5
timeout = 45
retries = 2
verbose = false

# 子域名 → true 會抽 *.target.com
subdomains = true

# providers：不要只用 wayback，多源才全面
providers = ["wayback", "otx", "commoncrawl", "urlscan"]

# 排除沒意義的 extension
blacklist = [
  "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "webp",
  "woff", "woff2", "ttf", "eot", "otf",
  "css", "scss",
  "mp3", "mp4", "avi", "mov",
  "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
]
```

自動載入：`GAU_CONFIG=$PWD/tools/configs/gau.toml`（bbflow 會自動 export）。

## 基本用法

```bash
# 最簡單
gau target.com

# 吃一個 list
cat domains.txt | gau

# 限制 providers
gau --providers wayback,otx target.com

# 排除 extension
gau --blacklist jpg,png,css target.com

# subdomain 一起抽
gau --subs target.com

# 存檔
gau target.com --o gau.txt

# JSON 輸出
gau --json target.com
```

## 必學 flag

| Flag | 用途 |
|------|------|
| `--subs` | 抽 `*.target.com` |
| `--providers` | `wayback,otx,commoncrawl,urlscan` |
| `--blacklist` | 排除 extension（逗號分隔） |
| `--threads 10` | 平行度 |
| `--timeout 45` | 每 provider timeout |
| `--retries 2` | 失敗重試 |
| `--mc 200,301` | 只保留指定 HTTP status（需要另外跑 probe） |
| `--fc 404` | 排除某 status（同上） |
| `--from 202101` | 從某月份開始 |
| `--to 202412` | 到某月份 |
| `--json` | JSON 輸出 |
| `--o file.txt` | 輸出檔 |

## 推薦組合

### 全面抽（bbflow 預設）

```bash
GAU_CONFIG=$PWD/tools/configs/gau.toml \
  gau --subs target.com > gau.txt
```

### 只看最近 2 年（快）

```bash
gau --from 202301 --subs target.com > gau_recent.txt
```

### 只看舊版（回溯找移除的 endpoint）

```bash
gau --to 202012 --subs target.com > gau_old.txt
```

### 多標的批次

```bash
cat subs.txt | gau --threads 10 --providers wayback,otx > gau_batch.txt
```

## 後處理

### 過濾有 query param 的 URL（可能有洞）

```bash
gau target.com | grep "?" > params.txt
```

### 去重 + 正規化

```bash
gau target.com | uro > endpoints.txt
```

uro 會：
- 去掉相同 endpoint 不同 value 的重複
- 去掉靜態資源

### 抽 email / subdomain

```bash
# 抽 email
gau target.com | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' | sort -u

# 抽 subdomain（URL 裡出現但 subfinder 沒找到的）
gau --subs target.com | awk -F/ '{print $3}' | sort -u
```

### gf 分類

```bash
gau --subs target.com | uro | tee endpoints.txt | \
  gf xss > gf_xss.txt

# 其他 pattern
for p in xss sqli ssrf lfi redirect idor; do
  gf $p < endpoints.txt > gf_${p}.txt
done
```

### probe 存活狀態

```bash
gau --subs target.com | httpx -silent -status-code -mc 200,301,302,401 > alive_urls.txt
```

## 常見攻擊面發現

### 發現 1：舊版 API endpoint

```bash
gau target.com | grep "/api/v1" > old_api.txt
# v1 可能被 v2 取代但還沒下線 → 沒 auth check
```

### 發現 2：移除但還活的後台

```bash
gau target.com | grep -iE "admin|login|manage|dashboard" | sort -u
# 對每個跑 curl -I 看是否還回 200
```

### 發現 3：被遺忘的 test endpoint

```bash
gau target.com | grep -iE "test|debug|dev|beta"
```

### 發現 4：敏感路徑（過往 hits）

```bash
gau target.com | grep -iE "\.env|\.git|backup|config|\.sql"
```

## 效能與限制

### Rate limit

- Wayback Machine：無明確 limit，但過度會被暫停
- OTX：需要 API key（`export OTX_KEY=xxx`）才能高速
- Common Crawl：慢，但量大
- URLScan：需要 API key（`export URLSCAN_KEY=xxx`）

### 輸出量估算

| Target type | gau 量 |
|-------------|--------|
| 小型 site | 100-1000 URLs |
| 中型 site | 1k-10k URLs |
| 大公司 | 10k-100k URLs |
| 政府大站 | 50k-500k URLs |

## bbflow 整合

```bash
# gau 被 crawl-chain 的 Stage 2 呼叫
bbflow hunt target --only crawl-chain
```

單獨用（不經 bbflow）：

```bash
GAU_CONFIG=$PWD/tools/configs/gau.toml gau --subs target.com | uro > endpoints.txt
```

## 擴展：waybackurls

gau 覆蓋不到的場合用 waybackurls（tomnomnom 經典）：

```bash
go install github.com/tomnomnom/waybackurls@latest

echo target.com | waybackurls > wayback.txt

# 兩個合併最全
(gau --subs target.com; echo target.com | waybackurls) | sort -u | uro
```

## 關聯文件

- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md)
- [20-tool-katana.md](20-tool-katana.md)
- [參考教學（Medium）](https://medium.com/@felixmelvinchitechi/gau-for-recon-91f8b331293d)
