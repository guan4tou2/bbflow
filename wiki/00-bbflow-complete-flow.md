---
type: wiki
category: flow
status: active
last-updated: 2026-05-20
---

# bbflow 完整操作流程

> 從 0 到送件，每一步都可照做。`bbflow` 是 `tools/bbflow.sh` 的 CLI 入口，零 LLM 依賴。
> 掃描邊界先看 [`../BBFLOW_OPERATIONS.md`](../BBFLOW_OPERATIONS.md)：`bbflow recon` / `bbflow hunt` / `bbflow flow` 預設 **VPS required**；Local OK 僅限健康檢查、狀態讀取、init、report/dedupe。
> VPS 部署與拉回輸出指令也在 `../BBFLOW_OPERATIONS.md ## VPS 部署流程`，不要只照本頁片段跳過部署/health check。
> 標準外部部署：**單 VPS + Docker compose + cron**；scope 使用 v1 `scope.yaml` / `scope.json`，必要時才用 `--allow-no-scope`。

## Standalone runtime boundary

bbflow runtime **MUST NOT require Vault**、**MUST NOT require LLM**。本 repo 必須能在單 VPS、Docker compose、cron 或一般 shell 環境獨立執行；Vault 是 optional integration，只能在 run 完成後透過 machine-readable output 讀取 `run_manifest.json`、`candidates.jsonl`、`SCOPE.md`、`scope_contract.json`。Vault adapter 可以把結論整理回 Vault，但不得成為 bbflow 掃描前置條件。

操作邊界：
- `BBFLOW_WORKSPACE` 控制本地輸出根目錄，預設 `$PWD`。
- `BBFLOW_REMOTE_ROOT` 控制 VPS 上 repo 位置，預設 `~/bbflow`。
- `tools/wiki/` 只保存通用知識與技術；不保存 target-specific 資料。
- `bbflow recon/hunt/flow` 只信任 scope contract、host list、template、hunter 與工具輸出，不讀 Vault Markdown 或 LLM context。

## wiki sanitization gate

bbflow wiki 不保存實戰目標資料，**不得保存機敏資料**、**不得保存 target-specific 資料**，只保存知識與技術。從 Vault / workspace 回寫到 `tools/wiki/` 前，先把實戰材料抽象成可重用 pattern：

| 原始材料 | wiki 寫法 |
|---|---|
| target / program / 客戶名稱 | 移除 target 名稱，改成 `example.com`、`<target>`、`<program>` |
| host / IP / endpoint / 帳號 | 改成泛化樣板；真實值留在 workspace 或 Vault |
| token / cookie / credential / API key | 不進 wiki；只描述驗證方式、遮罩格式或 hunter 需要的環境變數 |
| raw log / screenshot / PoC / payload 證據 | 不進 wiki；只抽成命令模板、命中判斷、false-positive 規則 |
| finding / submission / triage 對話 | 不進 wiki；需要追溯時放 Vault metadata 或 report path |

wiki 只寫可重用的技術知識：觸發條件、輸入、命令、輸出、判斷規則、安全邊界與部署方式。真實掃描過程與證據留在 workspace 或 Vault。

## End-to-end 操作流程

完整規範見 [`../BBFLOW_OPERATIONS.md`](../BBFLOW_OPERATIONS.md#end-to-end-操作流程)。本頁照這條 gate 流程操作：

| Gate | 做什麼 | 產物 |
|---|---|---|
| Gate 0 | 開局與 claim | active session lock |
| Gate 1 | Scope / dedupe / pre-flight | `SCOPE.md`、pre-flight、Attempt 停損 |
| Gate 2 | 決定掃描規模 | Scale 0-4 與 Operation Log |
| Gate 3 | VPS 執行 bbflow | BBOT / Osmedeus / Nuclei / hunter output；外部自動化用 `--scope-file` |
| Gate 4 | workspace 歸位 | `workshop/<target>/bbot/`、`hunters/`、`scan_results/`；輸出 `run_manifest.json` + `candidates.jsonl`；raw output 不進 Vault |
| Gate 5 | candidate triage | false positive / duplicate 寫 Attempt；成立 -> Finding + Submission + FORM |
| Gate 6 | Vault canonical update | 報告資料整理回 Vault |
| Gate 7 | bbflow 經驗回寫 | Knowledge Capture 必填 `bbflow 回寫判斷`；可重複知識回 bbflow，更新 hunter / template / profile / wiki / `CHANGELOG.md` |
| Gate 8 | session close-out | checklist、handoff、release lock |

## Recon ladder v1

bbflow 從 domain seed 開始，逐層收斂到可以人工驗證的 attack entrypoint：

| 階段 | 輸入 | 做什麼 | 產物 |
|---|---|---|---|
| domain seed | `scope.yaml` / `scope.json` | 確認 in-scope / out-of-scope / scan level | `scope_contract.json` |
| asset discovery | domain seed | BBOT / Osmedeus 找 subdomain、cloud asset、live host | `bbot/subdomains.txt`, `bbot/live_hosts.txt` |
| fingerprint | live hosts | tech、title、status、CDN/WAF、screenshot | fingerprint / screenshot output |
| path discovery | live hosts + archive | katana / gau / wayback / config paths | URL and path candidates |
| endpoint discovery | paths | API endpoint、query param、hidden param | `param_urls.txt`, `arjun.json` |
| CVE / template scan | live hosts / endpoints | Nuclei / Wordfence / custom bb-recon template | `nuclei_results.txt` |
| attack entrypoint | candidate hits | dedupe + manual verification | Attempt / Finding / Pattern |

WAF-safe mode 是 low-noise 安全邊界，不是預設繞過防護：先 passive、低 `rate-limit`、GET-first。payload mutation 只在明確授權時使用，例如 encoding、path normalization、header 差異或參數替換；**不得把 WAF bypass 當預設**。需要 DAST、ffuf、dalfox、arjun、nuclei high-noise 或 `waf-bypass` 時，先寫 Operation Log 和停止條件。

## 0. 安裝與健康檢查

```bash
# 首次設定（在 bbflow repo 根目錄）
cd ~/bbflow
export PATH="$PWD/tools:$PATH"         # 讓 bbflow 全域可用
alias bbflow='tools/bbflow.sh'

# 檢查依賴
bbflow doctor
```

### 0.5 標準部署：單 VPS + Docker compose + cron

外部 bbflow repo 不依賴 Vault / LLM。標準部署先固定為 **單 VPS + Docker compose + cron**：

```bash
mkdir -p ~/bbflow-runs/logs
cd ~/bbflow-runs
vim compose.yaml
vim scope.yaml
vim hosts.txt

docker compose run --rm bbflow doctor
docker compose run --rm bbflow hunt --list hosts.txt --scope-file scope.yaml --name daily-safe --only nuclei-secrets,cors
crontab -e
```

cron 範例：

```cron
15 2 * * * cd ~/bbflow-runs && docker compose run --rm bbflow hunt --list hosts.txt --scope-file scope.yaml --name daily-safe --only nuclei-secrets,cors >> logs/daily-safe.log 2>&1
```

`--allow-no-scope` 保留給明確授權的內部 / dry run；標準部署不得預設使用。

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
# → 建立 workshop/example.com/SCOPE.md 模板

# 手動填入 SCOPE.md（必須！）
vim workshop/example.com/SCOPE.md
```

**SCOPE.md 必填欄位：**
- Platform（HackerOne / Bugcrowd / HITCON / TWCERT / 政府案）
- In-scope assets（完整清單 + wildcards）
- Out-of-scope rules（漏洞類型 + 禁止行為）
- Bounty range
- Submission rules

> ⚠️ **沒填 SCOPE.md 時 `bbflow recon` 會拒絕執行**。這是強制 scope-first 規範。

外部自動化建議直接使用 v1 `scope.yaml` 或 `scope.json`，bbflow 會保留原檔並產生標準 `SCOPE.md` / `scope_contract.json`：

```yaml
schema_version: 1
program: Example Program
target: example.com
scan_level: safe
rate_limit: 5
in_scope:
  - example.com
  - "*.example.com"
out_of_scope:
  - "admin.example.com"
allowed_tools:
  - bbot
  - nuclei
  - hunters
```

## 2. Recon — 被動子域名 + 存活偵測

```bash
# VPS required：走 BBOT（預設）— passive enum + live probing，約 10 分鐘
bbflow recon example.com --scope-file scope.yaml

# VPS required：或走 Osmedeus VPS（需先 export OSMEDEUS_VPS）
OSMEDEUS_VPS=user@1.2.3.4 bbflow recon example.com --scope-file scope.yaml --osmedeus
```

輸出：
- `workshop/example.com/bbot/subdomains.txt` — 所有找到的子域名
- `workshop/example.com/bbot/live_hosts.txt` — httpx 確認存活的 URL（`https://sub.example.com`）

### 2.5 單標的直接 hunt（跳過 recon）

```bash
# VPS required：單一 URL 直接 hunt，不跑 recon
bbflow hunt https://target.example.com --scope-file scope.yaml --only config-leak,weak-login

# VPS required：用現成的 hostname list（如從 Shodan/Censys 手動收集）
bbflow hunt --list hosts.txt --scope-file scope.yaml --name my-program --probe --only cors,graphql
```

## 3. Hunt — 跑 hunters

本章所有 `bbflow hunt` 範例皆為 **VPS required**。

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
workshop/example.com/HUNTERS_REPORT_YYYYMMDD_HHMM.md
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
- `<reports>/submitted/`（你自訂的已送件目錄）
- `<reports>/fixed/`
- `workshop/<target>/submitted/`
- `workshop/<target>/reports/`

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
vim workshop/example.com/SCOPE.md          # 填完整 scope
bbflow recon example.com                   # VPS required，約 10 min

# Day 2：低噪音掃描（對 WAF 站）
bbflow hunt example.com --only config-leak,weak-login,backup-files,devops-unauth,git-exposure  # VPS required

# Day 3：前端洩漏 + Google key 驗證
bbflow hunt example.com --only envdata,sourcemap,js-secrets,trufflehog  # VPS required
# 如果找到 AIza* key，手動驗證
tools/hunters/hunt-google-api-key.sh AIzaSy...

# Day 4：完整 fuzzing chain（需要授權 / VDP 明確允許）
DEPTH=5 bbflow hunt example.com --only crawl-chain

# Day 5：去重 + 看報告
bbflow dedupe example.com
cat workshop/example.com/HUNTERS_REPORT_*.md | less

# Day 6：挑 NEW 的發現寫報告
# 依對應平台格式撰寫（HITCON / HackerOne / Bugcrowd / YesWeHack / Intigriti）
```

## 8. 常用 env 變數

| 變數 | 用途 |
|------|------|
| `BBFLOW_WORKSPACE` | override workspace root，預設 `$PWD`（target 輸出在 `workshop/<target>/`） |
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
