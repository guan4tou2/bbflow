# bbflow — Bug Bounty Flow Toolchain

統一的 bug bounty 偵察 + pattern hunter 工具鏈。**零 LLM 依賴**，純 `bash + curl + python3 stdlib`。

BBOT / Osmedeus 負責 recon，47 個 pattern hunter 負責驗證。完全獨立執行，不依賴特定資料夾結構。

---

## Standalone runtime boundary

bbflow 是 standalone CLI，不是 Vault plugin。Runtime **MUST NOT require Vault**、**MUST NOT require LLM**：任何人只拿 bbflow repo，也應能用 Docker、Docker compose、cron 或 `install.sh --all` 執行掃描。Vault 是 optional integration；Vault adapter 只能在掃描完成後讀取 machine-readable output，包含 `run_manifest.json`、`candidates.jsonl`、`SCOPE.md` 與 `scope_contract.json`。

環境邊界：
- `BBFLOW_WORKSPACE`：本地輸出根目錄，預設目前工作目錄；產物在 `workshop/<target>/`。
- `BBFLOW_REMOTE_ROOT`：VPS 上 bbflow repo 位置，預設 `~/bbflow`。
- machine-readable output 是 integration contract；Markdown report 只給人讀。
- Vault adapter 可以整理結果回 Vault，但 bbflow runtime 不讀 Vault Markdown、不需要 graphify、不需要 LLM context。

---

## 快速部署 / 快速安裝

### Docker（零本地依賴）

```bash
# 拉 image（~1.5 GB，含 nuclei-templates + SecLists）
docker pull ghcr.io/guan4tou2/bbflow:latest

# 用 wrapper script（最方便）
curl -sO https://raw.githubusercontent.com/guan4tou2/bbflow/main/bbflow-docker.sh
chmod +x bbflow-docker.sh

./bbflow-docker.sh doctor
./bbflow-docker.sh hunt target.com --scope-file scope.yaml --only cors,graphql
./bbflow-docker.sh hunt --list hosts.txt --scope-file scope.yaml --probe
./bbflow-docker.sh flow target.com --scope-file scope.yaml
```

輸出在執行目錄的 `workshop/` 結構中（自動掛載 `$(pwd):/workspace`）。

**auth env vars 直接 export 後執行即可：**
```bash
export DALFOX_BLIND_URL="https://xxx.oast.fun"
export DALFOX_COOKIE="session=abc123"
./bbflow-docker.sh hunt target.com --only dalfox-xss
```

**用 host 的 nuclei-templates + SecLists（省流量）：**
```bash
BBFLOW_MOUNT_TEMPLATES=1 ./bbflow-docker.sh hunt target.com
```

**docker-compose：**
```bash
git clone https://github.com/guan4tou2/bbflow.git && cd bbflow
docker compose run --rm bbflow hunt target.com
# 或自行 build：
docker compose build && docker compose run --rm bbflow doctor
```

### 標準部署：單 VPS + Docker compose + cron

bbflow 的標準外部部署先固定為 **單 VPS + Docker compose + cron**。VPS 保存 `compose.yaml`、`scope.yaml`、`hosts.txt` 與 `logs/`，cron 只呼叫穩定的 Docker compose 命令：

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

---

### 自動安裝（推薦）

```bash
git clone https://github.com/guan4tou2/bbflow.git
cd bbflow
./install.sh          # 互動式，問每個工具
./install.sh --all    # 全自動（VPS / CI 用）
./install.sh --check  # 只檢查環境，不安裝
```

install.sh 會自動建立 `~/.local/bin/bbflow` symlink，安裝後直接用 `bbflow` 指令。

若 `bbflow` 找不到：

```bash
export PATH="$HOME/.local/bin:$PATH"   # 加到 ~/.bashrc / ~/.zshrc
```

支援：Ubuntu/Debian（apt）、Fedora/RHEL（dnf）、Arch（pacman）、macOS（brew）。

---

## wiki 更新與資料淨化

bbflow 是零 LLM 依賴的獨立工具 repo；`tools/wiki/` 是給無 LLM 環境快速部署與操作的技術手冊，不保存 target-specific 資料。新增 hunter、Nuclei template、Osmedeus profile、VPS wrapper 或快速部署流程時，必須同步更新對應 wiki 頁與 `CHANGELOG.md`。

最低同步規則：
- 快速部署或安裝流程改變 → 更新本 README、`tools/wiki/00-bbflow-complete-flow.md`、`CHANGELOG.md`。
- 新 hunter 或 hunter 行為改變 → 更新 `hunters/README.md`、對應 `tools/wiki/` 頁、`CHANGELOG.md`。
- Nuclei template 收集或更新策略改變 → 確認 `bbflow nuclei-update` 文件仍正確，並更新對應 `tools/wiki/` 頁。
- 從實戰學到的技巧回寫 bbflow → 只保留通用知識與技術，移除 target 名稱、host / IP、token / cookie / credential、raw log / screenshot / PoC。

wiki 更新前先看 [`BBFLOW_OPERATIONS.md`](BBFLOW_OPERATIONS.md) 的 `wiki sanitization gate`。

---

## 外部自動化 contract

bbflow 用於外部自動化找漏洞時，不依賴 Vault 或 LLM，但仍強制 scope-first：

```bash
bbflow hunt target.com --scope-file scope.yaml --only cors,graphql
bbflow hunt --list hosts.txt --scope-file scope.yaml --name q1-scope --probe
```

建議外部 scope 使用 v1 schema，`scope.yaml` 或 `scope.json` 皆可。legacy `scope.md` 仍可用。

```yaml
schema_version: 1
program: Example Program
target: target.com
scan_level: safe
rate_limit: 5
in_scope:
  - target.com
  - "*.target.com"
out_of_scope:
  - "admin.target.com"
allowed_tools:
  - bbot
  - nuclei
  - hunters
```

輸出給其他模組讀取：
- `workshop/<target>/run_manifest.json` — run metadata，含 `schema_version`、`scope_file`、`scope_contract`、`candidate_schema_version`、`candidate_count`、artifact paths。
- `workshop/<target>/candidates.jsonl` — candidate hits，每行一筆 JSON；v1 欄位含 `candidate_id`、`hunter`、`vuln_class`、`confidence`、`severity`、`dedupe_key`、`artifact_refs`、`triage_status`。
- `HUNTERS_REPORT_*.md` — 人類閱讀用報告，不作為唯一 machine source。

`--allow-no-scope` 只給明確授權的內部 / dry run 使用。

---

## Recon ladder v1

bbflow 的標準流程是從 domain 到 path / endpoint，再到 CVE / known-vuln template 與 attack entrypoint：

| 階段 | 目的 | 主要命令 |
|---|---|---|
| domain seed | 讀 v1 `scope.yaml` / `scope.json`，確定合法 target | `bbflow hunt --list hosts.txt --scope-file scope.yaml` |
| asset discovery | subdomain / cloud asset / live host baseline | `bbflow recon <domain> --scope-file scope.yaml`、Osmedeus `bbflow-safe` |
| fingerprint | title / status / tech / CDN/WAF / screenshot | BBOT httpx、Osmedeus fingerprint / screenshot |
| path discovery | 歷史 URL、JS route、敏感路徑 | `wayback`, `config-leak`, `ffuf-dirs`, `crawl-chain` |
| endpoint discovery | API endpoint、query param、hidden param | `param-fuzz`, `arjun-params`, Swagger hunter |
| CVE / template scan | 已知漏洞、misconfig、exposure、WordPress CVE | `nuclei`, `nuclei-deep`, `nuclei-wp`, custom bb-recon |
| attack entrypoint | 可接續攻擊的入口，先 candidate triage | targeted hunters + `candidates.jsonl` |

WAF-safe mode：預設 **low-noise**、低 `rate-limit`、GET-first。payload mutation 只在 scope 明確允許時使用，例如 encoding、path normalization、header 差異或參數替換；**不得把 WAF bypass 當預設**，也不能用來規避 program policy 或 rate-limit。高噪音工具先寫 Operation Log，再從 VPS 執行。

---

### 手動安裝（Linux，Debian/Ubuntu）

```bash
# 系統依賴
sudo apt install -y golang pipx python3-pip git curl

# Go 工具（全部放 ~/go/bin/）
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
export PATH="$HOME/go/bin:$PATH"   # 加到 ~/.bashrc

# Python 工具
pip3 install arjun uro git-dumper waymore --break-system-packages

# bbot（passive recon）
pipx install bbot && pipx ensurepath

# trufflehog（secret scan）
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sudo sh -s -- -b /usr/local/bin

# nuclei templates
nuclei -update-templates

# SecLists（僅拉需要的路徑，~200MB）
git clone --depth=1 --filter=blob:none --sparse \
  https://github.com/danielmiessler/SecLists.git ~/Tools/SecLists
git -C ~/Tools/SecLists sparse-checkout set Discovery/Web-Content Fuzzing/XSS

# gf patterns
mkdir -p ~/.gf
for p in sqli ssrf lfi ssti xss idor redirect; do
  curl -sL "https://raw.githubusercontent.com/1ndianl33t/Gf-Patterns/master/${p}.json" \
    -o ~/.gf/${p}.json
done

# bbflow symlink（install.sh 已自動建立，手動也可）
ln -sf "$(pwd)/bbflow.sh" ~/.local/bin/bbflow
export PATH="$HOME/.local/bin:$PATH"

# 驗證
bbflow doctor
```

> **macOS**：把 `go install ...` 換成 `brew install httpx subfinder nuclei katana gau waybackurls dalfox ffuf trufflehog`；其餘相同。

---

## 使用方法

### 基本流程（單一 target）

```bash
# workshop/ 預設建在當前目錄；可用環境變數固定位置（一勞永逸）：
# export BBFLOW_WORKSPACE=~/my-bugbounty-workspace

# 初始化（建 SCOPE.md — scope-first 強制）
bbflow init target.com

# 填寫 SCOPE.md（必填）
nano workshop/target.com/SCOPE.md

# 一條龍
bbflow flow target.com --scope-file scope.yaml

# 或分開跑
bbflow recon target.com --scope-file scope.yaml          # BBOT subdomain enum + live probe
bbflow hunt target.com --scope-file scope.yaml           # 全部 hunter scripts
bbflow hunt target.com --scope-file scope.yaml --only cors,graphql,envdata   # 指定 hunters
```

### List 輸入（IP / domain / URL 混合）

```bash
# hosts.txt 可以混合：IP、裸 domain、完整 URL、# 註解
cat hosts.txt
# https://app.target.com
# api.target.com          ← 自動補 https://
# 192.168.1.100           ← 自動補 https://
# 10.0.0.1:8443           ← 自動補 https://
# # 這行被忽略

bbflow hunt --list hosts.txt --scope-file scope.yaml                     # 直接跑 hunters
bbflow hunt --list hosts.txt --scope-file scope.yaml --probe             # 先 httpx 探活再跑
bbflow hunt --list hosts.txt --scope-file scope.yaml --name q1-scope     # 自訂 workshop 目錄名稱
bbflow hunt --list hosts.txt --scope-file scope.yaml --only ffuf-dirs,cors --probe
bbflow flow --list hosts.txt --scope-file scope.yaml --name q1-scope     # 等同 hunt --list（略過 recon）
```

### Authenticated scan

```bash
# export env vars before running — 全部 hunter 會繼承
export DALFOX_BLIND_URL="https://xxx.oast.fun"   # blind XSS callback
export DALFOX_COOKIE="session=abc123"             # authenticated XSS
export FFUF_COOKIE="session=abc123"               # authenticated dir fuzzing
export ARJUN_HEADERS="Authorization: Bearer xxx"  # authenticated param discovery

bbflow hunt target.com --only dalfox-xss,ffuf-dirs,arjun-params
```

### 其他指令

```bash
bbflow doctor               # 檢查所有依賴 + workspace 路徑
bbflow status target.com    # 目前 target 進度
bbflow list                 # 所有 target
bbflow dedupe target.com    # 比對已送報告找重複
bbflow submit-checklist hitcon   # 輸出 HITCON 送件檢查清單
bbflow submit-checklist twcert   # 輸出 TWCERT/CVE 送件檢查清單
bbflow nuclei-update        # 更新 PD templates + clone Wordfence CVE repo
bbflow test                 # regression smoke test (example.com, 0 FP)
```

---

## 送件檢查（HITCON / TWCERT）

```bash
bbflow submit-checklist hitcon
bbflow submit-checklist twcert
```

這個命令把實戰 triage 教訓固定成可重複檢查清單，重點包含：
- HITCON：僅 `敘述(detail)` 支援 Markdown、圖片證據與 `{{IMG#N}}` 引用規則。
- TWCERT：CVE 適用性（使用者可控制版本 vs 純 SaaS）、Rule 3 拆分原則。
- 共通：`Verified` 與 `Potential` 分開寫、外送稿移除內部追蹤 ID、附件清單與 ZIP 實檔一致。

---

## Workspace 設定

bbflow 完全獨立，不依賴任何特定父資料夾：

```
TOOLS_DIR        = bbflow repo 本身（自動偵測）
BBFLOW_WORKSPACE = workshop/ 和 reports/ 的存放位置
                   預設: $PWD（執行 bbflow 的目錄）
                   覆蓋: export BBFLOW_WORKSPACE=/my/path
```

```bash
# 範例: 在 ~/pentest-work/ 存放所有 workshop output
export BBFLOW_WORKSPACE=~/pentest-work
bbflow hunt target.com
# → 輸出在 ~/pentest-work/workshop/target.com/
```

Bundled binaries：
- `tools/httpx`, `tools/nuclei`, `tools/subfinder` — 放在 repo 裡，優先使用
- `tools/bin/` — 加入 PATH，放 bbot/osmedeus wrapper 即自動生效

---

## 47 個 Hunters

| Hunter | 用途 | 案例 |
|---|---|---|
| `hybris-occ` | SAP Hybris OCC default creds + cart IDOR | SAP Hybris OCC pattern |
| `envdata` | `window.envData` + AWS/Google/Sentry keys | SPA inline config ✅ |
| `sourcemap` | `.js.map` → sourcesContent 密鑰 grep | multi-brand SSO ✅ |
| `js-secrets` | live `.js` bundle 19 種密鑰 pattern | SPA hardcoded secret |
| `cors` | 四層反射 + credentials:true | reflective CORS ✅ |
| `graphql` | 無認證 + introspection + integer IDOR | GraphQL IDOR ✅ |
| `userenum` | validate_email differential + rate limit | multi-brand / differential |
| `git-exposure` | `.git` 多路徑 + remote URL + `--dump` | nested .git CMS ✅ |
| `takeover` | CNAME + 20+ vendor fingerprint | CNAME fingerprint |
| `open-redirect` | 20 param × 9 bypass + OAuth chain | OAuth redirect_uri chain |
| `jwt` | decode + alg:none + weak HS256 + kid/jku | generic |
| `devops-unauth` | 40+ DevOps 工具無認證 | Harbor/ArgoCD/Jenkins ✅ |
| `actuator-deep` | Spring Boot Actuator + heapdump | Spring Boot Actuator |
| `mcp-oauth` | MCP OAuth consent vs token 差異 | MCP OAuth scope ✅ |
| `gkey` | `AIza*` → 16 個 Google 服務 validation | multi-service API key ✅ |
| `nxdomain` | 歷史 hostname → NXDOMAIN payload | Starbucks writeup |
| `nuclei` | 27 個 bb-recon 自訂 templates（直接可利用） | firebase/k8s/elastic/… |
| `nuclei-secrets` | 官方 PD tokens + configs（329 個） | AWS/GitHub/Stripe key |
| `nuclei-panels` | 官方 PD exposed-panels（DevOps/DB/Vault） | Redis/RabbitMQ/phpMyAdmin |
| `nuclei-wp` | Wordfence WordPress CVE（1000+） | WP plugin/theme CVE |
| `param-fuzz` | katana+gau+gf → nuclei DAST XSS/SQLi/SSRF | DAST fuzzing |
| `dalfox-xss` | dalfox + gf filter（blind XSS 支援） | reflected/blind XSS |
| `arjun-params` | 隱藏 GET/POST/JSON parameter discovery | hidden param hunting |
| `trufflehog` | git history 100+ detector secret scan | `--only-verified` |
| `ffuf-dirs` | 3 層 dir fuzzing + BB-ROI wordlist；feroxbuster fallback | dir/file exposure |
| `portscan` | rustscan → nmap service detection；Docker API/Redis/ES/Mongo/Consul 自動標 🔴 | port scan + service detection |
| `config-leak` | 100+ 路徑 single-shot content-match；FAST=1 P1/P2 only（24 paths） | WAF-friendly gov/firewall sites |
| `weak-login` | 25+ vendor default creds (Nacos/Druid/Grafana/Jenkins/phpMyAdmin/...)；differential body match | default creds 驗證 |
| `backup-files` | 40 static names + hostname-derived (target.com.zip/sql) + Index-of fallback；content-type+size dual verify | backup leak hunting |
| `waf-bypass` | wafw00f + 15+ bypass (path mutation/nullbyte/unicode/Origin/X-Forwarded-For)；ORIGIN_IP= 直連 origin | WAF-protected target |
| `crawl-chain` | 10-stage URL discovery + DAST (katana→gau→waybackurls→paramspider→hakrawler→uro→gf→arjun→nuclei→dalfox) | full SPA/API fuzz pipeline |

✅ = 對真實目標實測重現。詳見 [`hunters/README.md`](hunters/README.md)。

---

## 目錄結構

```
bbflow/                      (這個 repo)
├── bbflow.sh                主 CLI
├── bbflow-docker.sh         Docker wrapper（零本地依賴）
├── install.sh               本機依賴安裝器
├── Dockerfile               multi-stage build（go-builder + python:3.12-slim）
├── docker-compose.yml       compose 版本
├── .dockerignore
├── ci.sh                    本地 CI
├── bbot_preset_bugbounty.yml
├── bin/
│   └── bbot                 bbot wrapper（pipx/~/.local/bin 自動偵測）
├── hunters/
│   ├── hunt-*.sh            47 個 hunter scripts
│   └── README.md            每個 hunter 範例輸出 + 決策規則
├── nuclei-templates/
│   ├── bb-recon/            27 個自訂 templates
│   └── nuclei-wordfence-cve/ （bbflow nuclei-update 後出現）
└── payloads/
    └── xss-custom.txt       dalfox 自訂 XSS payloads

$BBFLOW_WORKSPACE/           (預設 $PWD，可 export 覆蓋)
└── workshop/
    └── <target>/
        ├── SCOPE.md          scope 定義（必填）
        ├── bbot/
        │   ├── subdomains.txt
        │   └── live_hosts.txt
        ├── hunters/<name>/
        └── HUNTERS_REPORT_YYYYMMDD_HHMM.md
```

---

## 設計原則

1. **零 LLM 依賴** — 所有 hunters 純 `bash + curl + python3 stdlib`。可 cron / VPS / offline 跑。
2. **Scope-first 強制** — `bbflow recon` 沒 SCOPE.md 會拒絕執行。
3. **類型 hunter，不是特定標的** — 每個 hunter 對任何 target 都能跑；成功案例是靈感 + 首個驗證目標。
4. **Differential 驗證** — 不做盲 fuzzing，只做條件判斷，FP 率低。
5. **可攜** — 任意機器 git clone + install.sh 即可使用，不依賴特定資料夾結構。

---

## CI

```bash
./ci.sh                   # 全 check
./ci.sh --fast            # 跳過網路呼叫
./ci.sh --install-hook    # 安裝 pre-push hook
```

CI 檢查：bash syntax、Python heredoc py_compile、bbflow doctor、regression test（0 FP）、hunter executable、README/WORKFLOW 數量一致。

---

## 授權 / 使用範圍

- 只對你有授權測試的 target 跑（bug bounty scope / 自己的基礎設施 / CTF）
- `bbflow init` 強制建 SCOPE.md，請先填完整再 recon
- 不做 rate-limit bypass / DoS / mass exfil / 任何 destructive action
