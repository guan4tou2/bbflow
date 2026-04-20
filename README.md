# bbflow — Bug Bounty Flow Toolchain

統一的 bug bounty 偵察 + pattern hunter 工具鏈。**零 LLM 依賴**，純 `bash + curl + python3 stdlib`。

BBOT / Osmedeus 負責 recon，21 個 pattern hunter 負責驗證。完全獨立執行，不依賴特定資料夾結構。

---

## 快速安裝

### 自動安裝（推薦）

```bash
git clone https://github.com/guan4tou2/bbflow.git
cd bbflow
./install.sh          # 互動式，問每個工具
./install.sh --all    # 全自動（VPS / CI 用）
./install.sh --check  # 只檢查環境，不安裝
```

支援：Ubuntu/Debian（apt）、Fedora/RHEL（dnf）、Arch（pacman）、macOS（brew）。

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

# 驗證
./bbflow.sh doctor
```

> **macOS**：把 `go install ...` 換成 `brew install httpx subfinder nuclei katana gau waybackurls dalfox ffuf trufflehog`；其餘相同。

---

## 使用方法

### 基本流程（單一 target）

```bash
# 切換到你的工作目錄（research/ 會建在這裡）
cd ~/my-bugbounty-workspace

# 初始化（建 SCOPE.md — scope-first 強制）
bbflow init target.com

# 填寫 SCOPE.md（必填）
nano research/target.com/SCOPE.md

# 一條龍
bbflow flow target.com

# 或分開跑
bbflow recon target.com          # BBOT subdomain enum + live probe
bbflow hunt target.com           # 全 21 hunters
bbflow hunt target.com --only cors,graphql,envdata   # 指定 hunters
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

bbflow hunt --list hosts.txt                     # 直接跑 hunters
bbflow hunt --list hosts.txt --probe             # 先 httpx 探活再跑
bbflow hunt --list hosts.txt --name q1-scope     # 自訂 research 目錄名稱
bbflow hunt --list hosts.txt --only ffuf-dirs,cors --probe
bbflow flow --list hosts.txt --name q1-scope     # 等同 hunt --list（略過 recon）
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
bbflow nuclei-update        # 更新 PD templates + clone Wordfence CVE repo
bbflow test                 # regression smoke test (example.com, 0 FP)
```

---

## Workspace 設定

bbflow 完全獨立，不依賴任何特定父資料夾：

```
TOOLS_DIR        = bbflow repo 本身（自動偵測）
BBFLOW_WORKSPACE = research/ 和 reports/ 的存放位置
                   預設: $PWD（執行 bbflow 的目錄）
                   覆蓋: export BBFLOW_WORKSPACE=/my/path
```

```bash
# 範例: 在 ~/pentest-work/ 存放所有 research
export BBFLOW_WORKSPACE=~/pentest-work
bbflow hunt target.com
# → 輸出在 ~/pentest-work/research/target.com/
```

Bundled binaries：
- `tools/httpx`, `tools/nuclei`, `tools/subfinder` — 放在 repo 裡，優先使用
- `tools/bin/` — 加入 PATH，放 bbot/osmedeus wrapper 即自動生效

---

## 21 個 Hunters

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
| `ffuf-dirs` | 3 層 dir fuzzing + BB-ROI wordlist | dir/file exposure |

✅ = 對真實目標實測重現。詳見 [`hunters/README.md`](hunters/README.md)。

---

## 目錄結構

```
bbflow/                      (這個 repo)
├── bbflow.sh                主 CLI
├── install.sh               依賴安裝器
├── ci.sh                    本地 CI
├── bbot_preset_bugbounty.yml
├── bin/
│   └── bbot                 bbot wrapper（pipx/~/.local/bin 自動偵測）
├── hunters/
│   ├── hunt-*.sh            21 個 hunters
│   └── README.md            每個 hunter 範例輸出 + 決策規則
├── nuclei-templates/
│   ├── bb-recon/            27 個自訂 templates
│   └── nuclei-wordfence-cve/ （bbflow nuclei-update 後出現）
└── payloads/
    └── xss-custom.txt       dalfox 自訂 XSS payloads

$BBFLOW_WORKSPACE/           (預設 $PWD，可 export 覆蓋)
└── research/
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
