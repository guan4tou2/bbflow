# Tool Configuration Guide

## Profiles

bbflow 支援兩個掃描 profile，透過環境變數切換：

```bash
BBFLOW_PROFILE=safe bbflow hunt target   # 預設：保守速率
BBFLOW_PROFILE=deep bbflow hunt target   # 深度：更高併發、遞迴、headless
```

| 參數 | safe | deep | 說明 |
|------|------|------|------|
| nuclei rate-limit | 5/s | 15/s | 單位秒請求數 |
| nuclei bulk-size | 25 | 50 | 每批 template 數 |
| nuclei retries | 2 | 3 | 失敗重試 |
| katana depth | 3 | 5 | 爬蟲深度 |
| katana headless | ✗ | ✓ | SPA JS rendering |
| katana crawl time | 5m | 15m | 最大爬取時間 |
| dalfox workers | 5 | 10 | 平行 XSS 掃描 |
| dalfox delay | 100ms | 50ms | 請求間隔 |
| ffuf recursion | 0 | 2 | 目錄遞迴深度 |
| ffuf threads | 20 | 30 | 平行線程 |

## API Keys（強烈建議設定）

### Subfinder Provider Config

```bash
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml << 'EOF'
# https://docs.projectdiscovery.io/tools/subfinder/install#post-install-configuration
securitytrails: [YOUR_API_KEY]
shodan: [YOUR_API_KEY]
censys: [YOUR_API_KEY:YOUR_SECRET]
chaos: [YOUR_API_KEY]
virustotal: [YOUR_API_KEY]
passivetotal: [YOUR_EMAIL:YOUR_API_KEY]
binaryedge: [YOUR_API_KEY]
hunter: [YOUR_API_KEY]
zoomeye: [YOUR_API_KEY]
fofa: [YOUR_EMAIL:YOUR_API_KEY]
EOF
```

免費 API key 來源（優先順序）：
1. **SecurityTrails** — 免費帳號 50 req/mo → `securitytrails.com`
2. **Shodan** — 免費帳號 → `shodan.io`
3. **Censys** — 免費 250 req/mo → `search.censys.io`
4. **Chaos** — ProjectDiscovery 自家，免費 → `chaos.projectdiscovery.io`
5. **VirusTotal** — 免費 500 req/day → `virustotal.com`

### Nuclei Interactsh（OOB 偵測：blind SSRF/XXE/RCE）

```bash
# 使用 ProjectDiscovery 公共 interactsh 伺服器（預設）
# 或自建：go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

# 自訂伺服器（可選）
export INTERACTSH_SERVER="oast.pro"
export INTERACTSH_TOKEN="your-token"
```

### Dalfox Blind XSS

```bash
# 方法一：XSS Hunter (xsshunter.trufflesecurity.com)
export DALFOX_BLIND_URL="https://your-subdomain.xss.ht"

# 方法二：interactsh
export DALFOX_BLIND_URL="https://your-id.oast.pro"
```

### GAU / URLScan

```bash
# ~/.gau.toml 或 configs/gau.toml
# URLScan API key（免費）: urlscan.io/user/profile/
```

## 環境變數一覽

| 變數 | 預設 | 說明 |
|------|------|------|
| `BBFLOW_PROFILE` | `safe` | `safe` / `deep` |
| `NUCLEI_RATE_LIMIT` | profile | 覆蓋 nuclei 速率 |
| `KATANA_DEPTH` | profile | 覆蓋爬蟲深度 |
| `DALFOX_BLIND_URL` | — | Blind XSS callback URL |
| `DALFOX_COOKIE` | — | Authenticated XSS scan |
| `DALFOX_HEADERS` | — | Extra headers |
| `FFUF_COOKIE` | — | Authenticated fuzzing |
| `FFUF_HEADER` | — | Extra header |
| `ARJUN_HEADERS` | — | Authenticated param discovery |
| `INTERACTSH_SERVER` | — | Nuclei OOB server |
| `INTERACTSH_TOKEN` | — | Nuclei OOB token |
| `CURL_UA` | Chrome 125 | User-Agent string |
| `WCD_COOKIE` | — | Cache Deception authenticated probe |
| `REDIRECT_CANARY` | `evil.example.com` | Open redirect test domain |

## Per-tool 最佳實踐

### Nuclei
- **`-retries 2`** — 網路抖動不漏掉真結果
- **`-bulk-size 25`** — 批次提交 template 減少連線開銷
- **`-c 10`** — 併發控制，避免觸發 WAF
- **`-etags dos,fuzz`** — 排除 DoS/Fuzz 類 template
- **interactsh** — 有 INTERACTSH_SERVER 時自動啟用 OOB 偵測

### Katana
- **`-jc`** — JS crawl（解析 JS 中的 URL）
- **`-kf all`** — 自動抓 robots.txt/sitemap/security.txt
- **`-aff`** — 自動填表（登入表單等）
- **`-xhr`** — 擷取 XMLHttpRequest/fetch 呼叫（v1.1+）
- **`-form-extraction`** — 提取表單 action URL
- **`-headless`** — deep profile 啟用，SPA 必備
- **`-ef`** — 排除靜態副檔名節省時間

### Dalfox
- **`--deep-domxss`** — DOM XSS 深度分析
- **`--mining-dict`** — 從 response 內容自動挖掘隱藏參數
- **`--skip-bav`** — kxss 已確認反射後跳過基本告警驗證（省時）
- **`--blind URL`** — Blind XSS callback（搭配 xsshunter 或 interactsh）

### ffuf
- **`-ic`** — 忽略 wordlist 中的註解行
- **`-recursion -recursion-depth 2`** — deep 模式遞迴探測子目錄
- **404 baseline filtering** — 自動偵測 404 回應大小並過濾（已內建）
- **`-rate 15`** — safe 模式限速避免封鎖

### Waymore
- **`-ko "api,admin,..."`** — deep 模式用 keyword 篩選高價值 URL
- **`--stream`** — 邊跑邊輸出
- **`-p 3`** — 平行查詢 3 個 provider
