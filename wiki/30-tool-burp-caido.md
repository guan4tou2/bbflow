---
type: wiki
category: tool
tool: burp,caido
status: active
last-updated: 2026-04-21
---

# Tool: Burp Suite + Caido（手動 Proxy）

> **用途：** 所有自動化工具做完後的**手動最後一哩路**。Burp 是業界標準，Caido 是開源替代（免費、輕量）。

## 比較

| 特色 | Burp Community | Burp Pro | Caido |
|------|---------------|----------|-------|
| 價格 | 免費 | ~$500/year | 免費 + pro 選購 |
| Repeater | ✅ | ✅ | ✅（Replay）|
| Intruder | 限速 | ✅ 無限速 | ✅（Automate）|
| Scanner | ❌ | ✅ | ❌（用外部 tool）|
| Extension | ✅（BApp Store） | ✅ | ✅（Plugins）|
| 平台 | Java（慢） | Java | 原生（快）|
| 團隊協作 | ❌ | ❌ | ✅（Collab）|

**推薦：** 個人用 Caido（快、免費），公司用 Burp Pro。

## Burp 基本設定

### 1. 下載 + 安裝

```bash
# Burp Community
# https://portswigger.net/burp/communitydownload

# macOS brew cask
brew install --cask burp-suite
```

### 2. 啟動 proxy（預設 127.0.0.1:8080）

### 3. 瀏覽器 proxy

- Firefox：Options → Network Settings → Manual Proxy → 127.0.0.1:8080
- 或用 FoxyProxy extension

### 4. 安裝 Burp CA 證書

```bash
# 從 http://burp 下載 CA
# 瀏覽器 import 為受信任 CA
```

### 5. 推薦 extensions（BApp Store）

| Extension | 用途 |
|-----------|------|
| Logger++ | 更強的 log |
| Turbo Intruder | 超高速攻擊 |
| Autorize | 自動 IDOR 測試 |
| Hackvertor | payload encode |
| Copy as Python-Requests | 轉 request 成 Python |
| Param Miner | hidden param fuzz |
| Collaborator Everywhere | 自動 inject OAST |
| Active Scan++ | 加強掃描 |
| Backslash Powered Scanner | 找異常 |
| J2EE Scan | J2EE 專用 |

## Caido 基本設定

### 1. 下載 + 安裝

```bash
# https://caido.io/download
# Linux AppImage / macOS dmg / Windows msi
```

### 2. 啟動

```bash
caido server  # CLI 模式
# 或打開 GUI app
```

### 3. 瀏覽器 proxy 到 127.0.0.1:8080（預設）

### 4. 匯入 Burp CA（Caido 用同格式）

## 核心工作流程

### Workflow 1：手動驗證 nuclei finding

```
1. nuclei 找到 XSS at https://target/search?q=...
2. 在 Burp Proxy history 找到這個 request（或手動瀏覽一次）
3. Send to Repeater
4. 手動調整 payload：
   - 試不同 encoding
   - 試 CSP 繞過
   - 試 WAF 繞過
5. 確認能在瀏覽器真的執行（截圖）
```

### Workflow 2：Intruder brute force

```
1. 拿一個 POST login request
2. Send to Intruder
3. Positions 標記 password 欄位
4. Payload → wordlist
5. Start attack → 看 Length 欄的差異
6. 找不同長度的 response = 可能正確密碼
```

### Workflow 3：IDOR 批次測試

```
1. 登入 user A，對 /api/user/:id 送 request
2. Send to Repeater
3. 把 Cookie 換成 user B 的
4. 同一個 id 試看看是否能看到 A 的資料
5. 用 Intruder 對 id 範圍做 fuzz
```

### Workflow 4：GraphQL introspection

```
1. 找到 /graphql endpoint
2. Repeater 送 introspection query
3. 從 schema 找敏感 mutation
4. 試未授權 mutation
5. 用 Param Miner / CODE 插件整合
```

## 推薦快捷鍵

### Burp

| 動作 | 快捷 |
|------|------|
| Send to Repeater | `Ctrl+R` / `Cmd+R` |
| Send to Intruder | `Ctrl+I` |
| Copy URL | `Ctrl+U` |
| Forward request | `Ctrl+F` |
| Drop | `Ctrl+D` |

### Caido

| 動作 | 快捷 |
|------|------|
| Send to Replay | `Ctrl+R` |
| Send to Automate | `Ctrl+I` |
| Forward | `F` |

## 與 bbflow 整合

bbflow 主要是自動化，Burp/Caido 是手動驗證：

```bash
# 1. bbflow 跑完 hunter 找出候選
bbflow hunt target

# 2. 把候選 URL 在 Burp 開（或直接用 Burp import）
# 3. 手動跑 Repeater 確認
# 4. 拿 curl 命令後寫報告
```

### 把 curl 轉成 Burp request

Burp 有 "Copy as curl command"；反向需要手動：

```bash
# 假設 nuclei 找到的 URL
URL="https://target.com/api/v1/secret?id=1"
curl -v "$URL" -H "Authorization: Bearer xxx" > out.txt 2>&1

# 把 -v 的 request 部分貼到 Burp Repeater
```

### 把 Burp proxy 設成中繼（bbflow 工具 → Burp → Target）

```bash
# 讓 nuclei 把流量送 Burp 看
nuclei -u target -proxy http://127.0.0.1:8080

# 讓 sqlmap 送 Burp
sqlmap -u target --proxy=http://127.0.0.1:8080

# 讓 ffuf 送 Burp
ffuf -u target/FUZZ -w words.txt -replay-proxy http://127.0.0.1:8080
```

## 常見場景

### 場景 A：找到登入後才有的 endpoint

1. 用 Burp 登入一次（錄下整個 flow）
2. Save Item 某個請求成 request file
3. `sqlmap -r request.txt --batch`

### 場景 B：JWT 測試

1. Burp extension：**JWT Editor**
2. 解碼 JWT
3. 試 `alg=none` / 改 `role=admin`
4. 直接在 Repeater 改 token 送

### 場景 C：CORS 測試

```
Request 加上 Origin: https://evil.com
看 Response 的 Access-Control-Allow-Origin

若回 https://evil.com → reflective CORS
若回 null → 可用 sandbox iframe / data: URL
```

### 場景 D：Open Redirect 測試

```
用 Repeater 改 redirect param：
?redirect=https://evil.com
?redirect=//evil.com
?redirect=/\evil.com
?redirect=javascript:alert(1)
?redirect=%2f%2fevil.com
```

## Payload 字典（內建於 Burp Intruder）

Intruder → Payloads → Type：

- Simple list
- Runtime file（外部字典）
- Numbers（數字範圍，IDOR 用）
- Dates
- Brute forcer（暴力組合）
- Null payloads（測 empty）
- **Recursive grep**（從 response 抓值再送回去）

## 注意

### Burp Community 限速

- Intruder 只能 1 thread，約 1 req/s
- 對 brute force 不實用 → 改用 ffuf / hydra

### Burp Scanner 只有 Pro 才有

- 用外部 nuclei 代替
- 或手動跑 Burp 的 Active Scan（Pro）

### Caido Automate 對應 Intruder

- 免費版無速度限制
- 但 extension 生態較少

## 關聯文件

- [00-bbflow-complete-flow.md](00-bbflow-complete-flow.md)
- [40-checklist-new-target.md](40-checklist-new-target.md)
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md)
