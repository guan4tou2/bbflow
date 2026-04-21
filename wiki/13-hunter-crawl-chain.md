---
type: wiki
category: hunter
hunter: crawl-chain
status: active
last-updated: 2026-04-21
---

# Hunter: `crawl-chain`

> **目的：** 對目標執行完整的 **10 階段資訊蒐集 + 被動/主動 DAST 工具鏈**，解決 nuclei 預設 template 掃不到「需要正確參數 / 路徑」的 deep surface 問題。
> **解決的痛點：** nuclei 預設 template 只對 known path 檢測；若 endpoint 需要特定 query param 才觸發漏洞（如 `?file=`、`?redirect=`、`?id=`），預設 template 直接 miss。

## 工具鏈全流程

```
┌───────────────────────────────────────────────────────────────┐
│ Stage 1 主動爬蟲    katana  → endpoints from JS / crawl      │
│ Stage 2 歷史 URL     gau     → wayback + otx + commoncrawl    │
│ Stage 3 更多歷史     waybackurls → 舊版 endpoint              │
│ Stage 4 隱藏參數     paramspider → ?param= 挖掘              │
│ Stage 5 JS 爬蟲     hakrawler → 補漏 endpoint                │
│ Stage 6 去重合併     uro     → URL normalize + dedupe         │
│ Stage 7 模式分類     gf      → xss / sqli / ssrf / lfi / ...  │
│ Stage 8 隱藏參數發現 arjun   → endpoint 沒看到的 param        │
│ Stage 9 DAST 掃描    nuclei  → 每個 gf pattern 各跑一次       │
│ Stage 10 XSS 驗證    dalfox  → 真正試 XSS payload             │
└───────────────────────────────────────────────────────────────┘
```

## 用法

```bash
# 完整掃描（10 stages, 10-30 分鐘）
tools/hunters/hunt-crawl-chain.sh https://target.com

# 深度掃描（katana depth=8）
DEPTH=8 tools/hunters/hunt-crawl-chain.sh https://target.com

# 快速模式（跳過 arjun + dalfox，只跑到 Stage 9）
FAST=1 tools/hunters/hunt-crawl-chain.sh https://target.com

# 經 bbflow
bbflow hunt target --only crawl-chain
```

### 輸出結構

```
./crawl_chain_out/https_target.com/
├── 01_katana.txt           # 主動爬蟲 endpoint
├── 02_gau.txt              # 歷史 URL
├── 03_wayback.txt          # wayback 補漏
├── 04_paramspider.txt      # ?param= endpoint
├── 05_hakrawler.txt        # JS 爬蟲
├── 06_merged.txt           # uro 去重合併
├── 07_gf_xss.txt           # XSS 可疑
├── 07_gf_sqli.txt          # SQLi 可疑
├── 07_gf_ssrf.txt          # SSRF 可疑
├── 07_gf_lfi.txt           # LFI 可疑
├── 07_gf_ssti.txt          # SSTI 可疑
├── 07_gf_redirect.txt      # Open redirect 可疑
├── 07_gf_idor.txt          # IDOR 可疑
├── 08_arjun.txt            # 新發現的隱藏參數
├── 09_nuclei_xss.txt       # nuclei DAST XSS 結果
├── 09_nuclei_sqli.txt
├── 09_nuclei_ssrf.txt
├── 09_nuclei_lfi.txt
├── 10_dalfox.txt           # dalfox XSS 驗證
└── summary.txt             # 總結 + hit count
```

## 每階段詳解

### Stage 1：katana（主動爬蟲）

```bash
katana -u https://target.com \
  -d 5 \
  -jc \
  -aff \
  -fx \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif,tiff,tif \
  -silent -o 01_katana.txt
```

**關鍵 flag：**
- `-d 5` — depth 5（往下爬 5 層）
- `-jc` — JavaScript crawling（從 JS 抽 endpoint）
- `-aff` — automatic form fill
- `-fx` — field extraction（form input 也抓）
- `-ef` — exclude extensions

### Stage 2：gau（歷史 URL）

```bash
gau --threads 5 --subs target.com > 02_gau.txt
```

**設定：** `tools/configs/gau.toml` 已設定 providers=wayback,otx,commoncrawl,urlscan

### Stage 3：waybackurls（補漏）

```bash
echo target.com | waybackurls > 03_wayback.txt
```

### Stage 4：paramspider（隱藏 param）

```bash
paramspider -d target.com -o 04_paramspider.txt
```

輸出格式：`https://target.com/page.php?id=FUZZ&name=FUZZ`

### Stage 5：hakrawler

```bash
echo https://target.com | hakrawler -d 3 > 05_hakrawler.txt
```

### Stage 6：uro（去重合併）

```bash
cat 01_katana.txt 02_gau.txt 03_wayback.txt 04_paramspider.txt 05_hakrawler.txt \
  | sort -u | uro > 06_merged.txt
```

uro 會：
- 去掉相同 endpoint 不同 param value 的重複
- 排除靜態資源

### Stage 7：gf（pattern 分類）

```bash
for pattern in xss sqli ssrf lfi ssti redirect idor; do
  gf $pattern < 06_merged.txt > 07_gf_${pattern}.txt
done
```

gf patterns 要先安裝：
```bash
mkdir -p ~/.gf
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf-patterns
cp ~/.gf-patterns/*.json ~/.gf/
```

### Stage 8：arjun（隱藏參數發現）

```bash
# 對 endpoint 挖掘新 param
arjun -i 06_merged.txt -oT 08_arjun.txt \
  --passive \
  --include-status 200,301,302,403
```

### Stage 9：nuclei DAST（per-pattern）

```bash
# XSS
nuclei -l 07_gf_xss.txt -tags xss -dast -silent -o 09_nuclei_xss.txt

# SQLi
nuclei -l 07_gf_sqli.txt -tags sqli -dast -silent -o 09_nuclei_sqli.txt

# SSRF
nuclei -l 07_gf_ssrf.txt -tags ssrf -dast -silent -o 09_nuclei_ssrf.txt

# LFI
nuclei -l 07_gf_lfi.txt -tags lfi,file -dast -silent -o 09_nuclei_lfi.txt
```

### Stage 10：dalfox（XSS 真實驗證）

```bash
dalfox file 07_gf_xss.txt \
  --skip-bav \
  --skip-mining-all \
  --silence -o 10_dalfox.txt
```

dalfox 會真的送 XSS payload 並用 headless browser 驗證執行。

## 環境變數

| 變數 | 預設 | 說明 |
|------|------|------|
| `DEPTH` | 5 | katana crawl depth |
| `FAST` | 0 | 1 = 跳過 arjun + dalfox |
| `THREADS` | 10 | 爬蟲 threads |
| `RATE` | 50 | nuclei rate limit |
| `TIMEOUT` | 10 | 單 URL timeout |

## 常見場景

### 場景 A：政府站一般掃描

```bash
DEPTH=3 FAST=1 bbflow hunt target.gov.tw --only crawl-chain
```

- DEPTH=3 避免噪音
- FAST=1 跳 dalfox（政府 WAF 會擋）

### 場景 B：SPA 前端 Source Map 暴露

```bash
# 先抽 source map 的 URL
bbflow hunt target --only sourcemap

# 再吃抽出的 endpoint 跑 nuclei
cat sourcemap_out/endpoints.txt >> crawl_chain_out/https_target.com/06_merged.txt
bbflow hunt target --only crawl-chain --skip-stages 1,2,3,4,5
```

### 場景 C：發現 Swagger 後深入

```bash
# config-leak 找到 /swagger-ui.html
curl -sk https://target.com/v2/api-docs > swagger.json

# 用 katana + swagger 抽 endpoint
katana -u https://target.com -swagger swagger.json -silent > endpoints.txt
```

## 注意事項

### 不要對小 program 跑全流程

- 10 stages 完跑會發 ~5000-20000 個 request
- 對政府案 / 小廠商可能會被封 IP
- 建議 **DEPTH=3 + FAST=1** 當預設

### gf pattern 匹配只是「可疑」不是「確認」

- `07_gf_xss.txt` 裡的 URL 只是有 `?q=` / `?search=` 這類 param
- **真的要確認 XSS 必須跑 Stage 10 dalfox**
- SQLi 類似：gf 只是發現有 `?id=` `?user=`，要跑 sqlmap 或手動測試

### arjun 會挖很多無用 param

過濾：
```bash
# 保留 reflected params（可能 XSS）
grep -iE "q|search|keyword|callback|redirect|url|file|path" 08_arjun.txt
```

## 關聯文件

- [20-tool-katana.md](20-tool-katana.md)
- [21-tool-gau.md](21-tool-gau.md)
- [23-tool-arjun.md](23-tool-arjun.md)
- [24-tool-nuclei.md](24-tool-nuclei.md)
- [25-tool-dalfox.md](25-tool-dalfox.md)
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md)
