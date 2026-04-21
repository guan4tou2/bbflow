---
type: wiki
category: flow
status: active
last-updated: 2026-04-21
---

# bbflow 完整操作流程

> 從 0 到送件，每一步都可照做。`bbflow` 是 `tools/bbflow.sh` 的 CLI 入口，零 LLM 依賴。

## 0. 安裝與健康檢查

```bash
# 首次設定（在 BugBounty 根目錄）
cd ~/Desktop/BugBounty
export PATH="$PWD/tools:$PATH"         # 讓 bbflow 全域可用
alias bbflow='tools/bbflow.sh'

# 檢查依賴
bbflow doctor
```

預期輸出應該包含：
- `✓ nuclei / httpx / subfinder` — 打包在 `tools/` 下
- `✓ katana / gau / waybackurls / uro / gf` — 需要另外裝
- `✓ dalfox / arjun / trufflehog / ffuf` — 需要另外裝
- `✓ GAU_CONFIG → .../tools/configs/gau.toml` — 自動掛載
- `✓ SecLists → ...` — wordlist 路徑

### 缺什麼補什麼

```bash
# Go 工具（subfinder/httpx/nuclei 已打包，以下補齊）
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/hakluke/hakscan@latest

# gf patterns（給 crawl-chain 分類）
git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
# 或 git clone https://github.com/tomnomnom/gf 再 cp -r examples ~/.gf

# Python 工具
pip3 install arjun paramspider uro --break-system-packages

# Homebrew
brew install dalfox ffuf feroxbuster rustscan nmap trufflehog
brew install gitleaks dnsx

# SecLists
git clone --depth=1 https://github.com/danielmiessler/SecLists.git ~/Tools/SecLists
```

### Nuclei templates 同步

```bash
bbflow nuclei-update
# = nuclei -update-templates + clone topscoder/nuclei-wordfence-cve
```

## 1. 初始化 target

```bash
bbflow init example.com
# → 建立 research/example.com/SCOPE.md 模板

# 手動填入 SCOPE.md（必須！）
vim research/example.com/SCOPE.md
```

**SCOPE.md 必填欄位：**
- Platform（HackerOne / Bugcrowd / HITCON / TWCERT / 政府案）
- In-scope assets（完整清單 + wildcards）
- Out-of-scope rules（漏洞類型 + 禁止行為）
- Bounty range
- Submission rules

> ⚠️ **沒填 SCOPE.md 時 `bbflow recon` 會拒絕執行**。這是強制 scope-first 規範。

## 2. Recon — 被動子域名 + 存活偵測

```bash
# 走 BBOT（預設）— 完全被動，約 10 分鐘
bbflow recon example.com

# 或走 Osmedeus VPS（需先 export OSMEDEUS_VPS）
OSMEDEUS_VPS=user@1.2.3.4 bbflow recon example.com --osmedeus
```

輸出：
- `research/example.com/bbot/subdomains.txt` — 所有找到的子域名
- `research/example.com/bbot/live_hosts.txt` — httpx 確認存活的 URL（`https://sub.example.com`）

### 2.5 單標的直接 hunt（跳過 recon）

```bash
# 單一 URL 直接 hunt，不跑 recon
bbflow hunt https://target.example.com --only config-leak,weak-login

# 用現成的 hostname list（如從 Shodan/Censys 手動收集）
bbflow hunt --list hosts.txt --name my-program --probe --only cors,graphql
```

## 3. Hunt — 跑 hunters

### 3.1 全部跑（時間最久，covers everything）

```bash
bbflow hunt example.com
```

### 3.2 按類型挑（常用組合）

```bash
# WAF-friendly 低噪音四件套（政府站首推）
bbflow hunt example.com --only config-leak,weak-login,backup-files,devops-unauth

# SPA 前端洩漏（JS bundle / source map / window.envData）
bbflow hunt example.com --only envdata,sourcemap,js-secrets

# Google API key 驗證（需先從其他 hunter 找到 key）
tools/hunters/hunt-google-api-key.sh AIzaSy...XXX

# 完整 URL discovery + DAST
bbflow hunt example.com --only crawl-chain
DEPTH=5 bbflow hunt example.com --only crawl-chain  # 更深的 crawl

# 單純 nuclei template scan
bbflow hunt example.com --only nuclei,nuclei-secrets,nuclei-panels,nuclei-wp
```

### 3.3 Hunter 速覽（26 個）

| 類別 | Hunter | 主要發現 | ROI |
|------|--------|---------|-----|
| **Config / Info 洩漏** | config-leak | .git/.env/actuator/swagger/WEB-INF | ⭐⭐⭐⭐⭐ |
| | backup-files | .zip/.sql/.tar.gz/Index-of | ⭐⭐⭐⭐ |
| | git-exposure | .git/config + 歷史 credential | ⭐⭐⭐⭐ |
| | envdata | window.envData AWS/Google key | ⭐⭐⭐⭐ |
| | sourcemap | .js.map sourcesContent | ⭐⭐⭐ |
| | js-secrets | 硬編碼 clientSecret/Bearer | ⭐⭐⭐ |
| | trufflehog | git history 100+ detector | ⭐⭐⭐ |
| **Authentication** | weak-login | vendor default creds | ⭐⭐⭐⭐⭐ |
| | userenum | validate_email differential | ⭐⭐ |
| | jwt | alg:none / weak HS256 | ⭐⭐⭐ |
| **DevOps / Infra** | devops-unauth | Harbor/ArgoCD/Jenkins 無 auth | ⭐⭐⭐⭐ |
| | actuator-deep | /env /heapdump /jolokia | ⭐⭐⭐⭐ |
| | portscan | rustscan → nmap service | ⭐⭐ |
| **Auth Flow** | cors | 4-layer reflection + credentials | ⭐⭐⭐ |
| | graphql | introspection + IDOR | ⭐⭐⭐ |
| | open-redirect | redirect param + bypass 變體 | ⭐⭐ |
| | mcp-oauth | MCP OAuth scope 差異 | ⭐⭐⭐ |
| | hybris-occ | SAP Hybris default OAuth | ⭐⭐⭐ |
| **Takeover** | takeover | CNAME → vendor fingerprint | ⭐⭐⭐ |
| | nxdomain | 歷史 hostname superset | ⭐⭐ |
| **Google** | gkey | Maps/Vision/Translate unrestricted | ⭐⭐⭐ |
| **Fuzzing** | crawl-chain | 10 階段完整鏈 | ⭐⭐⭐⭐ |
| | param-fuzz | katana+gau → nuclei DAST | ⭐⭐⭐ |
| | dalfox-xss | 深度 XSS | ⭐⭐ |
| | arjun-params | 隱藏 param discovery | ⭐⭐ |
| | ffuf-dirs | 目錄 fuzzing | ⭐⭐ |
| | nuclei-wp | Wordfence 1000+ WP CVE | ⭐⭐ |

## 4. Report — 產生彙總報告

Hunt 結束會自動產生：
```
research/example.com/HUNTERS_REPORT_YYYYMMDD_HHMM.md
```

這份報告彙整所有 hunter 的 `🔴` hit，並列出對應的原始輸出檔路徑。

重新產生報告（如果你清掉或想刷新）：
```bash
bbflow report example.com
```

## 5. Dedupe — 對照已送報告去重

```bash
bbflow dedupe example.com
```

會比對：
- `<reports>/submited/`（你自訂的已送件目錄）
- `<reports>/fixed/`
- `research/<target>/submited/`
- `research/<target>/reports/`

輸出：
- `NEW` — 新發現（可準備送）
- `DUP` — 已送過，別再送

## 6. Status — 查看 target 進度

```bash
bbflow list                    # 所有 target 概況
bbflow status example.com      # 單一 target 細節
bbflow scope example.com       # 看 SCOPE.md
```

## 7. 完整工作流（範例）

```bash
# Day 1：偵察
bbflow init example.com
vim research/example.com/SCOPE.md          # 填完整 scope
bbflow recon example.com                   # 10 min

# Day 2：低噪音掃描（對 WAF 站）
bbflow hunt example.com --only config-leak,weak-login,backup-files,devops-unauth,git-exposure

# Day 3：前端洩漏 + Google key 驗證
bbflow hunt example.com --only envdata,sourcemap,js-secrets,trufflehog
# 如果找到 AIza* key，手動驗證
tools/hunters/hunt-google-api-key.sh AIzaSy...

# Day 4：完整 fuzzing chain（需要授權 / VDP 明確允許）
DEPTH=5 bbflow hunt example.com --only crawl-chain

# Day 5：去重 + 看報告
bbflow dedupe example.com
cat research/example.com/HUNTERS_REPORT_*.md | less

# Day 6：挑 NEW 的發現寫報告
# 依對應平台格式撰寫（HITCON / HackerOne / Bugcrowd / YesWeHack / Intigriti）
```

## 8. 常用 env 變數

| 變數 | 用途 |
|------|------|
| `BBFLOW_WORKSPACE` | override research/ 路徑，預設 `$PWD` |
| `GAU_CONFIG` | gau 設定檔，預設 `tools/configs/gau.toml` |
| `NUCLEI_COMMUNITY` | nuclei templates 路徑，預設 `~/nuclei-templates` |
| `SECLISTS` | SecLists 路徑（自動偵測） |
| `OSMEDEUS_VPS` | `user@ip` 走 VPS recon |
| `EXISTING_EMAIL` | 給 userenum / gkey identity toolkit 用 |
| `DALFOX_BLIND_URL` | dalfox blind XSS callback |
| `DALFOX_COOKIE` / `DALFOX_HEADERS` | authenticated XSS scan |
| `FFUF_COOKIE` / `FFUF_HEADER` | authenticated dir fuzzing |
| `ARJUN_HEADERS` / `ARJUN_COOKIES` | authenticated param discovery |
| `FAST=1` | config-leak / crawl-chain / backup-files 快速模式 |
| `SAFE=1` | weak-login 只跑單次 request 判斷的 vendor |

## 9. 疑難排解

| 症狀 | 解法 |
|------|------|
| `bbflow doctor` 顯示 `bbot not found` | `pipx install bbot` 或走 `--osmedeus` |
| Nuclei templates 很舊 | `bbflow nuclei-update` |
| `httpx` 被 WAF 擋 | 降速 `-rate-limit 5` 或改用 curl/手動 |
| `gau` 找不到東西 | 確認 `~/.gau.toml` 或檢查 `echo $GAU_CONFIG` |
| `arjun` 太慢 | 改用 `--passive` 或只在 crawl-chain top-20 endpoint |
| 掃出一堆誤報 | 每個 hunter 都支援 `SAFE=1` / `FAST=1`，先過一遍篩 |

## 關聯文件

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — WAF 後面怎麼打
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) — 政府站肥肉
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) — nuclei 掃不到時的解法
- [40-checklist-new-target.md](40-checklist-new-target.md) — 新標的 24h checklist
