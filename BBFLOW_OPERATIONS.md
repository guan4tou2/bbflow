# bbflow 操作規範

> Source of truth for bbflow / Osmedeus execution boundaries. 若拼成 `osuedemu`，此處規範指的是現有工具 `osmedeus`。

## 結論

bbflow 是獨立 repo，位於 workspace 的 `tools/`，不搬進 Vault，也不跟 Vault-root migration 綁定。Vault 只收斂知識：Recon note、Pattern、Playbook、Lessons、Finding/Submission/FORM；bbflow repo 只保存可重用工具、hunter、wrapper、掃描 profile 與操作規模。

`osmedeus` 一律 **VPS required**。`bbflow recon --osmedeus` 已要求 `OSMEDEUS_VPS`，並透過 SSH 在遠端執行掃描；不要在本機直接跑 Osmedeus。

`bbflow recon`、`bbflow hunt`、`bbflow flow` 預設也視為 **VPS required**，因為它們會進行 live probing、批次 GET、fingerprinting、hunter loop、nuclei/ffuf/dalfox/arjun 等自動化探測。只有不打外部 target 的管理/讀取類命令可以本機跑。

## Standalone runtime boundary

bbflow 的 runtime 必須能在沒有 Vault、沒有 LLM、沒有本工作區規範檔的環境獨立運作。Vault integration 是 **optional integration**，只能透過 `run_manifest.json`、`candidates.jsonl`、`SCOPE.md`、`scope_contract.json` 這些 machine-readable output 消費結果；不得讓掃描流程依賴 Vault Markdown、graphify、AGENTS/CLAUDE/CODEX/GEMINI、Obsidian 或 LLM 判讀。

Hard boundary:
- bbflow runtime **MUST NOT require Vault**。
- bbflow runtime **MUST NOT require LLM**。
- `BBFLOW_WORKSPACE` 決定本地輸出根目錄，預設為執行目錄；輸出固定在 `workshop/<target>/`。
- `BBFLOW_REMOTE_ROOT` 決定 VPS 上 bbflow repo 位置，預設 `~/bbflow`；不得硬編碼個人桌面路徑或 Vault 路徑。
- Vault adapter 只能在 bbflow run 完成後讀取 machine-readable output，再把結論整理進 Vault。
- bbflow repo 文件可以說明如何「回寫 Vault」，但必須同時提供無 Vault 的操作指令與輸出 contract。

## Vault / workspace / bbflow 三層資料流

整體流程不是「把 bbflow 放進 Vault」，而是三層各司其職：

| 階段 | 主體 | 動作 | 產物 |
|---|---|---|---|
| 1. Vault 發起 | Vault / AGENTS 規範 | 選 target、讀 scope、跑 dedupe、開 Recon note、決定掃描規模 | Target、Recon note、Pattern / Lessons 查詢結果 |
| 2. workspace 暫存 | `workshop/<target>/` | 保存掃描過程、raw log、PoC、截圖、Operation Log、bbot/live hosts、hunter output | `scan_results/`, `bbot/`, `hunters/`, `RECON_DB.md` |
| 3. bbflow 執行 | `tools/` 獨立 repo + VPS | 依 Scale 跑 `bbflow recon` / `bbflow hunt` / Osmedeus profile / hunter | raw scan output、candidate hits、HUNTERS_REPORT |
| 4. 整理回 Vault | Vault | 把確認後的結果整理成 Recon note、Finding、Submission、Pattern、Lessons | 可查詢的長期知識與報告 |
| 5. 經驗回寫 bbflow | bbflow repo | 把可重複的經驗整理成 hunter、掃描範本、Osmedeus profile、wordlist 或 wrapper 預設 | `tools/hunters/`, `tools/vps/osmedeus/`, bbflow docs |

判斷標準：
- 過程與暫存 log → workspace。
- 可長期查詢、可串 Finding/Pattern 的結論 → Vault。
- 可重複自動化的偵測經驗 → 經驗回寫 bbflow。

## End-to-end 操作流程

這條流程是 Vault / workspace / bbflow 的主線。原則是：Vault 做決策與 canonical 紀錄，workspace 放暫存與 raw output，bbflow 做無 LLM 自動化掃描；最後報告資料整理回 Vault，可重複知識回 bbflow。

| Gate | 輸入 | Go / Stop 條件 | 產物與歸位 |
|---|---|---|---|
| Gate 0: 開局與 claim | target / scope / 任務目的 | Go：`check_active_sessions` 無衝突並成功 `claim`；Stop：active scope 衝突或 target 不明 | lock 在 `automation/active_sessions/`；target 工作進 `workshop/<target>/` |
| Gate 1: Scope / dedupe / pre-flight | `SCOPE.md` / v1 `scope.yaml` / `scope.json`、`session_start_brief`、`vault_precheck`、§0g | Go：scope 明確、未撞既有 Finding、software/firmware/SaaS 已做 pre-flight；Stop：OOS、known CVE、duplicate likely；外部自動化用 `--scope-file scope.yaml`，只有明確授權才用 `--allow-no-scope` | 不成立或重複 -> Attempt；pre-flight 結論寫 `RECON_DB.md` / Vault Recon note |
| Gate 2: 決定掃描規模 | scope、KB Pattern / Lessons、program policy | Go：選定 Scale 0-4；Stop：高噪音但 scope 不允許、payload / write 未滿足 GET-first | 掃描規模與理由寫 Operation Log / Recon note |
| Gate 3: VPS 執行 bbflow | BBOT / Osmedeus / Nuclei / hunter list | Go：VPS ready、`bbflow doctor` / `osmedeus health` 通過；Stop：未確認來源 IP、工具不健康 | raw output 放 `workshop/<target>/bbot/`、`hunters/`、`scan_results/`；每輪輸出 `run_manifest.json` + `candidates.jsonl`；raw output 不進 Vault |
| Gate 4: workspace 歸位 | VPS tarball / hunter output / screenshots | Go：輸出可追溯到命令、來源 IP、scope；Stop：來源不明或混入跨 target 輸出 | 單 target 放 `workshop/<target>/...`；跨 target 放 `workshop/_all/` |
| Gate 5: candidate triage | HUNTERS_REPORT / nuclei hit / manual PoC | Go：可重現、有明確 impact、未重複；Stop：false positive、duplicate、未驗證 | 不成立或重複 -> Attempt；成立 -> Finding + Submission + FORM |
| Gate 6: Vault canonical update | Finding / Submission / FORM / Recon note | Go：Discovery Log、audit ref、impact、修補建議齊全；Stop：外部 citation 未驗證、內部 ID 未清 | 報告資料整理回 Vault；平台輸出副本放 `reports/<platform>/<target>/` |
| Gate 7: bbflow 經驗回寫 | confirmed pattern、false-positive rule、可重複掃描步驟 | Go：能泛化、能自動化、已做 wiki sanitization gate；Stop：含 target-specific 或機敏資料 | Knowledge Capture 必填 `bbflow 回寫判斷`；可重複知識回 bbflow：hunter / Nuclei template / Osmedeus profile / wiki / `CHANGELOG.md` |
| Gate 8: session close-out | 本輪 changes / active lock / checklist | Go：`recon_kb_capture_gate --verify`、`session_end_checklist` 或 `_meta release`；Stop：Deferred Action 未寫、lock 未釋放 | HANDOFF / RECON_DB / Kanban / active session mirror 更新 |

### Stop / go 條件

- 沒有 scope、沒有 dedupe、沒有 claim：不掃描。
- scope 不允許 high-noise：停在 Scale 2 或 Scale 3，不跑 nuclei/ffuf/dalfox/arjun/portscan 類高噪音流程。
- candidate 未驗證或撞既有 root cause：不開 Finding，寫 Attempt。
- 已驗證且有 impact：成立 -> Finding + Submission + FORM。
- raw output 不進 Vault；Vault 只收斂 Recon note、Finding、Submission、FORM、Pattern、Lessons。
- 報告資料整理回 Vault；可重複知識回 bbflow。
- 回寫 `tools/wiki/` 前必跑 wiki sanitization gate，移除 target 名稱、host/IP、token/cookie、raw log、screenshot、PoC 證據。

## bbflow machine-readable output contract

bbflow 會用於外部自動化找漏洞，因此工具本身必須獨立執行且輸出穩定格式，不依賴 Vault / LLM 解析 Markdown。

### Scope guard

- `bbflow recon` / `bbflow hunt` / `bbflow flow` 預設拒絕在沒有 `workshop/<target>/SCOPE.md` 的狀態下掃描。
- 外部自動化入口使用 `--scope-file <path>`；v1 schema 優先使用 `scope.yaml` 或 `scope.json`，legacy Markdown 仍可用。
- `scope.yaml` / `scope.json` 必須含 `schema_version: 1`、`target`、`scan_level`、`rate_limit`、`in_scope`、`out_of_scope`；`allowed_tools` 可選。bbflow 會保留原始 scope 檔，並產生標準 `workshop/<target>/SCOPE.md` 與 `scope_contract.json`。
- `--allow-no-scope` 只允許明確授權的內部 / dry run 使用；使用時 `run_manifest.json` 會標記 `allow_no_scope: true`。

最小 `scope.yaml`：

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

### Output files

每次 `bbflow hunt` 都必須輸出：

| 檔案 | 用途 | 必要欄位 |
|---|---|---|
| `workshop/<target>/run_manifest.json` | machine-readable run metadata | `schema_version`, `candidate_schema_version`, `candidate_schema_fields`, `target`, `command`, `scope_file`, `scope_contract`, `allow_no_scope`, `live_hosts_count`, `candidate_count`, `artifacts` |
| `workshop/<target>/candidates.jsonl` | machine-readable candidate hits | 每行 JSON；v1 欄位：`schema_version`, `candidate_id`, `target`, `hunter`, `vuln_class`, `confidence`, `severity`, `source`, `text`, `url`, `dedupe_key`, `evidence_path`, `artifact_refs`, `triage_status` |

消費規則：
- Vault / automation 優先讀 `run_manifest.json` 與 `candidates.jsonl`；`HUNTERS_REPORT_*.md` 是人類閱讀用。
- `candidate_count > 0` 只代表候選，不代表 Finding；仍要 Gate 5 triage。
- `schema_version` 變更時，同步更新 `tools/wiki/00-bbflow-complete-flow.md`、`tools/README.md`、`CHANGELOG.md`。

## bbflow wiki 更新流程

bbflow 是**無 LLM 自動化工具**：拿到 repo 的人應能在沒有 Vault、沒有 LLM context 的環境，用 Docker 或 `install.sh --all` 快速部署，直接執行健康檢查、template 更新與掃描命令。Vault 只提供治理與知識來源；bbflow repo 自己必須保存可操作的工具文件。

### 快速部署入口

```bash
docker pull ghcr.io/guan4tou2/bbflow:latest
./bbflow-docker.sh doctor

git clone https://github.com/guan4tou2/bbflow.git
cd bbflow
./install.sh --all
bbflow doctor
bbflow nuclei-update
```

### wiki 更新矩陣

任何從 Vault / workspace 回寫到 bbflow 的可重用經驗，都要同步更新 `tools/wiki/` 與 `CHANGELOG.md`，不能只改腳本。`00-bbflow-complete-flow.md` 是完整流程入口，部署、VPS、scope-first、sanitization 或主要命令變更時必改。

| 變更類型 | 必改位置 |
|---|---|
| 新 hunter / hunter 行為改變 | `tools/hunters/README.md`、對應 `tools/wiki/` 頁、`CHANGELOG.md` |
| 新 Nuclei template / template 收集策略 | `tools/wiki/15-nuclei-attack-templates.md` 或 `tools/wiki/24-tool-nuclei.md`、`CHANGELOG.md` |
| 新 Osmedeus profile / VPS wrapper | `tools/wiki/00-bbflow-complete-flow.md`、本檔、`CHANGELOG.md` |
| 快速部署 / 安裝 / doctor 流程改變 | `tools/README.md`、`tools/wiki/00-bbflow-complete-flow.md`、`CHANGELOG.md` |
| 從 target 學到可重複偵測技巧 | 只寫通用 pattern / hunter / template 用法；target 細節留在 Vault 或 workspace |

### wiki sanitization gate

bbflow wiki **不得保存機敏資料**、**不得保存 target-specific 資料**，只保存知識與技術。更新 `tools/wiki/` 前先做 sanitization：

| 類別 | 處置 |
|---|---|
| target / program / 客戶名稱 | 移除 target 名稱，改成 `example.com`、`<target>`、`<program>` |
| host / IP / endpoint / 帳號 | 改成泛化樣板；真實值留在 workspace 或 Vault |
| token / cookie / credential / API key | 不進 wiki；必要時只描述「驗證方式」與遮罩格式 |
| raw log / screenshot / PoC / payload 證據 | 不進 wiki；只抽象成判斷條件、命令模板、false-positive 規則 |
| finding ID / submission ID / triage 對話 | 不進 wiki；需要追溯時放 Vault metadata 或 report path |

**wiki 更新**只回答「這個技術如何重用」：觸發條件、輸入、命令、輸出、判斷規則、false-positive 過濾與安全邊界。真實掃描過程、目標資料、raw artifact 留在 workspace 或 Vault。

## 核心工具角色

bbflow 的核心不是單一掃描器，而是三種工具角色：

| 工具 | 角色 | 何時用 | 輸出 |
|---|---|---|---|
| **BBOT** | 第三個核心工具；預設資產發現 / passive recon | `bbflow recon <target>` 預設路徑，適合先建立 subdomain / live host baseline | `workshop/<target>/bbot/subdomains.txt`, `workshop/<target>/bbot/live_hosts.txt` |
| **Osmedeus** | 自動化挖洞流程 / orchestration | 需要整套 recon flow、archive、screenshot、fingerprint、VPS 隔離時 | `workshop/<target>/scan_results/osmedeus/` |
| **Nuclei** | 快速掃描已知漏洞 / template-based verification | 已有 live hosts，要快速掃 CVE、misconfig、exposure、panel、WordPress CVE 時 | `workshop/<target>/hunters/nuclei*/` 或 `scan_results/nuclei/` |

選擇順序：
1. 先用 BBOT 或 Osmedeus 建立資產 baseline。
2. 再用 Nuclei 針對已知漏洞 / 已知 template 快掃。
3. Nuclei 掃不到但 Pattern 可重複時，整理成 bbflow hunter 或 Osmedeus 掃描範本。

## BBOT vs Osmedeus 使用情境

BBOT 和 Osmedeus 都能做 recon，但定位不同：BBOT 是輕量 baseline 建立器，Osmedeus 是完整自動化挖洞流程。

| 判斷點 | 優先用 BBOT | 切到 Osmedeus |
|---|---|---|
| 任務目標 | 建立 subdomain / live host baseline | 跑完整 recon flow、archive、screenshot、fingerprint |
| 掃描規模 | Scale 1-2 的低噪音初始盤點 | Scale 2 的 safe flow 或更完整 orchestration |
| 速度 | 快速取得可餵給 hunter / Nuclei 的 host list | 較慢，但產物完整 |
| 控制力 | bbflow 自己管輸出與 hunter chaining | Osmedeus 管 workflow 與 modules |
| 失敗 fallback | BBOT 不在環境中時可退 crt.sh/httpx fallback | VPS 已部署 Osmedeus profile 時使用 |
| 適用情境 | 新 target 初始 baseline、只需要 live hosts、想降低噪音 | 多資產 target、需要 screenshots/archive、需要標準化 recon package |

**BBOT input**：`<target>`、`SCOPE.md`、bbot preset、可選 seed host list。
**BBOT output**：`workshop/<target>/bbot/subdomains.txt`、`workshop/<target>/bbot/live_hosts.txt`。

**Osmedeus input**：`<domain>`、VPS、`bbflow-safe` / `domain-lite` / `domain-standard` profile、scope gate。
**Osmedeus output**：VPS workspace tarball，拉回 `workshop/<target>/scan_results/osmedeus/`；可再萃取成 `bbot/live_hosts.txt` 或 Recon note。

決策樹：

```text
是否已有 scope + dedupe brief?
  否 -> 回 Vault / workspace 開局，不掃描
  是 -> 只需要 baseline live hosts?
        是 -> 優先用 BBOT
        否 -> 需要 archive/screenshot/fingerprint package?
              是 -> 切到 Osmedeus standard / bbflow-safe
              否 -> 用既有 live_hosts 跑 Nuclei / targeted hunters
```

## bbflow 主流程

```text
Step 1: Vault 決策
  check_active_sessions -> claim -> session_start_brief -> scope / dedupe / KB Pattern lookup

Step 2: 建 baseline
  優先用 BBOT：bbflow recon <target>
  或切到 Osmedeus：tools/vps/bbflow-vps.sh standard <domain>

Step 3: 快速已知漏洞掃描
  先 bbflow nuclei-update，再用 Nuclei / nuclei-* hunters 對 live hosts 做 template-based scan

Step 4: targeted hunters
  依 Vault Pattern / Lessons 選 hunter；產出 candidate hits，不直接升級 Finding

Step 5: 回寫與升級
  raw output 留 workspace；candidate hits 先 dedupe review；確認後整理回 Vault；
  可重複經驗再回寫 bbflow hunter / Nuclei template / Osmedeus 掃描範本
```

## Recon ladder v1

bbflow 的目標不是「只跑漏洞掃描」，而是建立可接續攻擊分析的完整 recon ladder。每一層都要有輸入、輸出、停止條件與回寫位置：

| 階段 | 目的 | 典型工具 | 產物 |
|---|---|---|---|
| 1. domain seed | 從 program scope / v1 `scope.yaml` 建立合法 seed | scope parser, Vault precheck | `scope_contract.json`, Operation Log |
| 2. asset discovery | 找 subdomain、cloud asset、live host baseline | BBOT, Osmedeus `bbflow-safe`, crt.sh fallback | `bbot/subdomains.txt`, `bbot/live_hosts.txt` |
| 3. fingerprint | 辨識 tech stack、title、status、server、CDN/WAF | httpx, Osmedeus fingerprint, screenshots | `scan_results/`, screenshots, Recon note |
| 4. path discovery | 收斂歷史 URL、JS route、常見敏感路徑 | katana, gau, waybackurls, `config-leak`, `ffuf-dirs` | `all_urls.txt`, path candidates |
| 5. endpoint discovery | 從 path 進一步抽 API endpoint、query param、hidden param | `crawl-chain`, `param-fuzz`, `arjun-params`, Swagger hunter | `param_urls.txt`, `arjun.json`, endpoint candidates |
| 6. CVE / template scan | 對已知產品、misconfig、exposure、CVE 做快速驗證 | custom bb-recon templates, PD templates, Wordfence CVE | `nuclei_results.txt`, `candidates.jsonl` |
| 7. attack entrypoint triage | 找可接續攻擊的入口，不直接升級 Finding | targeted hunters, manual curl, Vault dedupe | Attempt / Finding / Pattern / Lessons |

WAF-safe mode：預設採 **low-noise**、低 `rate-limit`、GET-first、先 passive 後 active。payload mutation 只用於已授權、低噪音且能解釋風險的情境，例如 path normalization、encoding 差異、header 差異或參數替換；**不得把 WAF bypass 當預設**，也不得用來規避 program policy、rate limit 或封鎖規則。若需要 `waf-bypass` hunter、DAST、ffuf、dalfox、arjun 或 nuclei high-noise 類別，必須先在 Operation Log 記錄 scope 依據、來源 VPS、命令、rate-limit 與停止條件。

## Local OK / VPS required

| 類別 | 命令 / 行為 | 規範 |
|---|---|---|
| 健康檢查 / 管理 | `bbflow doctor`, `bbflow status`, `bbflow list`, `bbflow scope`, `bbflow report`, `bbflow dedupe`, `bbflow init` | Local OK |
| 讀既有輸出 | 查看 `workshop/<target>/bbot/`, `workshop/<target>/hunters/`, `workshop/<target>/scan_results/` | Local OK |
| regression/null-case | `bbflow test` 對 `example.com` | Local OK |
| 自動 recon | `bbflow recon <target>`, `bbflow recon <target> --osmedeus` | VPS required |
| hunter orchestration | `bbflow hunt <target>`, `bbflow hunt --list <file> --probe`, `bbflow flow <target>` | VPS required |
| Osmedeus | `tools/vps/bbflow-vps.sh lite|standard|vulnscan|extensive`, raw `osmedeus run/scan` | VPS required |
| high-noise tools | nuclei, ffuf, dalfox, arjun, katana/gau crawl-chain, portscan, rustscan/nmap, DNS brute-force | VPS required |
| payload / write / exploit | SSRF probe, RCE PoC, SQLi payload, POST/PUT/PATCH/DELETE, SMS/email trigger | VPS required 且遵守 AGENTS.md §6c GET-first |
| destructive / uncertain | bulk delete, lifecycle stop/restart, unknown POST side effect, `commix`, aggressive `reconftw` | 禁止，除非 scope 明確允許且先寫 Operation Log |

例外很窄：單一 URL 的手動 `GET` 讀取確認可本機執行；任何批次、掃描、payload、寫入、fuzzing 都走 VPS。

## 掃描規模分級

掃描規模用來把「學到的經驗」轉成可重複執行的 bbflow profile / hunter 選擇，而不是把所有工具一次全開。

| Scale | 名稱 | 典型命令 | 網路位置 | 何時使用 | 門檻 |
|---|---|---|---|---|---|
| Scale 0 | Local management | `bbflow doctor`, `bbflow status`, `bbflow report`, `bbflow dedupe`, `bbflow init` | Local OK | 整理狀態、讀既有輸出、建 target 骨架 | 不打外部 target |
| Scale 1 | passive / read-only recon | `tools/vps/bbflow-vps.sh lite <domain>` | VPS required | 剛建立 target、scope 已確認、需要快速資產盤點 | 只做 passive enum + probe，無 fuzz |
| Scale 2 | safe standard recon | `tools/vps/bbflow-vps.sh standard <domain>` / `standard / bbflow-safe` | VPS required | 預設掃描規模；多數 program 的第一輪 | safe profile：無 nuclei、無 content fuzz、無 DNS brute |
| Scale 3 | targeted hunter | `bbflow hunt <target> --only <hunter-list>` | VPS required | 依 KB Pattern / Lessons 選少量 hunter 驗證特定攻擊面 | 先跑 vault_precheck；命中後 dedupe review |
| Scale 4 | high-noise / active scan | `vulnscan`, `extensive`, nuclei, ffuf, dalfox, arjun, portscan | VPS required | program 明確允許掃描、需要驗證高價值假設 | 先寫 Operation Log；scope 明確允許；必要時降速 |

預設從 Scale 2 起跑；只有需要快速盤點時用 Scale 1。Scale 4 不作為預設，必須有 scope/policy 依據。

## 標準流程

本機只做 scope、dedupe、文件與輸出整理：

```bash
bash automation/check_active_sessions.sh
bash automation/claim.sh <target> --eta-minutes=60
bash automation/session_start_brief.sh <target> "<keyword>" "<host>"
bash automation/vault_precheck.sh <target> "<keyword>" "<host>"
bbflow init <target>
```

## VPS 部署流程

標準部署先定為 **單 VPS + Docker compose + cron**。目標：在單一 VPS 上以 Docker compose 固定 bbflow 執行環境，cron 排程拉取 hosts/scope、執行 `bbflow hunt --list` 或 Osmedeus safe profile，結果再拉回本機 `workshop/<target>/`。多 VPS、Kubernetes、queue worker 暫不列為標準流程。

標準檔案：

```text
compose.yaml          # bbflow image + /workspace volume + env file
scope.yaml            # v1 scope contract
hosts.txt             # 本輪輸入 host list
crontab               # cron 呼叫 docker compose run --rm bbflow ...
```

cron 範例：

```bash
crontab -e
15 2 * * * cd ~/bbflow-runs && docker compose run --rm bbflow hunt --list hosts.txt --scope-file scope.yaml --name daily-safe --only nuclei-secrets,cors >> logs/daily-safe.log 2>&1
```

`--allow-no-scope` 保留，但標準部署不得預設使用；只有內部 dry run、工具健康檢查或明確授權的無 scope 測試可加。

### 1. 本機準備 scope 與 precheck（Vault adapter，可選）

```bash
cd <vault-workspace>
bash automation/check_active_sessions.sh
bash automation/claim.sh <target> --eta-minutes=60
bash automation/session_start_brief.sh <target> "<keyword>" "<host>"
bash automation/vault_precheck.sh <target> "<keyword>" "<host>"
bash automation/init_target.sh <target>
```

外部 bbflow repo / VPS 可直接使用 v1 scope：

```bash
bbflow hunt --list hosts.txt --scope-file scope.yaml --name <program>-safe --probe
```

### 2. 部署 wrapper / Osmedeus profile 到 VPS

```bash
export BBFLOW_REMOTE_ROOT=~/bbflow
ssh oracle-a1 "mkdir -p ~/bbflow/tools/vps/osmedeus"
rsync -av tools/vps/bbflow-vps.sh oracle-a1:~/bbflow/tools/vps/
rsync -av tools/vps/osmedeus/bbflow-safe.yaml oracle-a1:~/bbflow/tools/vps/osmedeus/
ssh oracle-a1 "chmod +x ~/bbflow/tools/vps/bbflow-vps.sh"
```

若 VPS 的 Osmedeus flow 目錄尚未放入 `bbflow-safe.yaml`，在 VPS 上同步到 Osmedeus workflow path：

```bash
ssh oracle-a1
mkdir -p ~/.osmedeus/core/workflows
cp ~/bbflow/tools/vps/osmedeus/bbflow-safe.yaml ~/.osmedeus/core/workflows/bbflow-safe.yaml
```

### 3. VPS 健康檢查

```bash
ssh oracle-a1
cd ~/bbflow
osmedeus health
tools/vps/bbflow-vps.sh tools
```

最低要求：
- `osmedeus health` 可正常跑完。
- `tools/vps/bbflow-vps.sh tools` 至少列出 `osmedeus`, `subfinder`, `httpx`, `dnsx`, `nuclei`（nuclei 只在允許時使用）。

### 4. VPS 執行掃描

預設先跑 safe profile：

```bash
ssh oracle-a1
cd ~/bbflow
tools/vps/bbflow-vps.sh standard <domain>
```

本機 wrapper 觸發遠端 Osmedeus也可以，但只用於已有 `OSMEDEUS_VPS` 的情境：

```bash
OSMEDEUS_VPS=ubuntu@138.2.59.206 BBFLOW_REMOTE_ROOT=~/bbflow tools/bbflow.sh recon <target> --osmedeus
```

### 5. 拉回輸出並歸位

VPS wrapper 支援把 workspace 打包到 stdout：

```bash
ssh oracle-a1 "cd ~/bbflow && tools/vps/bbflow-vps.sh pull <domain>" > /tmp/bbflow-<target>-<date>.tgz
mkdir -p workshop/<target>/scan_results/osmedeus
tar -xzf /tmp/bbflow-<target>-<date>.tgz -C workshop/<target>/scan_results/osmedeus
```

若只拉指定檔案，仍放到下列位置：

| 輸出 | 位置 |
|---|---|
| 單 target Osmedeus / nuclei / ffuf / crawl raw | `workshop/<target>/scan_results/` |
| `bbflow recon` live hosts / subdomains | `workshop/<target>/bbot/` |
| `bbflow hunt` raw hunter output | `workshop/<target>/hunters/` |
| 跨 target report / targets list / shared hunter output | `workshop/_all/` |

結束前：

```bash
bash automation/recon_report_dedupe_review.sh <target> <recon_report_path> [recon_note_path]
bash automation/recon_kb_capture_gate.sh --verify <target> [recon_note_path]
bash automation/session_end_checklist.sh <target>
```

## Operation Log

自動化掃描不需逐條記每個 HTTP request，但必須記掃描任務的開始/結束。

RECON_DB `## 📋 Operation Log` 至少包含：

| 欄位 | 內容 |
|---|---|
| 時間 | 本地時間 + UTC |
| 來源 IP | VPS IP 或 `OSMEDEUS_VPS` host |
| 目標 | program / root domain / host list |
| 命令 | `bbflow recon`, `bbflow hunt`, `bbflow flow`, `tools/vps/bbflow-vps.sh standard` |
| scope | 對應 SCOPE.md 的 in-scope 規則 |
| 輸出 | `workshop/<target>/scan_results/` / `bbot/` / `hunters/` |
| 結果 | completed / stopped / rate-limited / false-positive-only |

## Nuclei template 更新與收集

Nuclei 用於「快速掃描已知漏洞」，不是完整挖洞流程。每次要跑 Nuclei 前先更新 template，避免用舊 CVE / 舊 matcher 做判斷。

### 更新指令

```bash
cd <bbflow-repo>
tools/bbflow.sh nuclei-update
```

`bbflow nuclei-update` 目前負責：
- 呼叫 `nuclei -update-templates` 更新官方 ProjectDiscovery templates。
- 使用 `NUCLEI_COMMUNITY` 指向官方 template 目錄，預設 `$HOME/nuclei-templates`。
- clone / pull `tools/nuclei-templates/nuclei-wordfence-cve/`，補 WordPress CVE templates。
- 顯示 `tools/nuclei-templates/bb-recon/` 自訂 templates 數量。

等價底層動作：

```bash
nuclei -update-templates
git -C tools/nuclei-templates/nuclei-wordfence-cve pull
```

### template 收集規則

| 來源 | 位置 | 收集條件 |
|---|---|---|
| 官方 ProjectDiscovery | `NUCLEI_COMMUNITY` / `$HOME/nuclei-templates` | 官方維護；用 `nuclei -update-templates` 更新 |
| bbflow custom | `tools/nuclei-templates/bb-recon/` | 已知漏洞或 misconfig 可用單一 template 穩定驗證 |
| Wordfence WP CVE | `tools/nuclei-templates/nuclei-wordfence-cve/` | WordPress plugin/theme CVE 快掃 |

從 Vault / workspace 學到新經驗時：
- 單一 HTTP request + matcher 可穩定驗證 → 寫成 Nuclei template，放 `tools/nuclei-templates/bb-recon/`。
- 需要多步驟、狀態保存、差異比對、登入或複雜解析 → 寫成 `tools/hunters/hunt-*.sh`。
- 需要完整 recon orchestration → 寫成 Osmedeus profile / wrapper 流程。

Nuclei 結果處理：
- raw output 留在 `workshop/<target>/hunters/nuclei*/` 或 `workshop/<target>/scan_results/nuclei/`。
- 命中後先跑 dedupe review，不直接開 Finding。
- template false positive 要回寫到 Vault Lessons；可穩定修正時同步修 bbflow template。

## Nuclei template lifecycle

新增或修改 template 時走固定 lifecycle，避免把未測過的 pattern 丟進外部自動化：

1. draft：從 Finding / Pattern / Lessons 回寫成通用 template，移除 target-specific 資料。
2. syntax：跑 `nuclei -validate -t tools/nuclei-templates/bb-recon`。
3. null case：用 `example.com null-case` 或等價無害 host 確認沒有 obvious false-positive。
4. scoped live canary：只在明確授權 target、低 `rate-limit`、單 template 或小類別上試跑。
5. false-positive review：命中後先進 Attempt / candidate，不直接升級 Finding。
6. promote：通過後才放入 `bb-recon` 預設集合，並更新 README / wiki / CHANGELOG。
7. 回寫：把命中條件、失敗條件、false-positive 過濾規則回寫到 Vault Pattern / Lessons 與 bbflow wiki。

## Osmedeus profile 選擇

| profile | 用途 | 預設 |
|---|---|---|
| `lite` | 快速 passive enum + probe | scope 明確且需快速盤點時 |
| `standard` / `bbflow-safe` | passive enum + probe + fingerprint + archive + screenshots，無 nuclei / content fuzz / DNS brute | 推薦預設 |
| `vulnscan` | domain-standard，包含 nuclei | 只有 program 明確允許掃描時 |
| `extensive` | DNS brute-force / 更大噪音 | 預設不用；需明確 scope 允許 |

`tools/vps/osmedeus/bbflow-safe.yaml` 是目前推薦安全 profile：不跑 nuclei、不跑 content/directory fuzzing、不跑 DNS brute-force。

## 經驗更新

這些規則來自既有 workspace 事故與 hunter 使用經驗，之後調整 bbflow 時以此為優先：

| 經驗 | bbflow 規則 |
|---|---|
| 本機 IP 不應承擔掃描與誤操作風險 | `bbflow recon` / `bbflow hunt` / `bbflow flow` 預設 VPS required |
| 多數 program 對 nuclei、content fuzz、DNS brute-force 敏感 | 先 `standard / bbflow-safe`，後 `vulnscan`；只有 scope 明確允許才跑 high-noise profile |
| raw log 太大且容易污染 repo | raw output 留在 `workshop/<target>/scan_results/` 或 gitignored 大檔，commit 結論摘要 |
| hunter 命中常有 false positive | `recon_report_dedupe_review.sh` 逐條去重後，才升級 Finding |
| POST / payload 類 hunter 可能有副作用 | GET-first；有寫入/觸發/副作用的 hunter 只能在 VPS 且先寫 Operation Log |
| 舊 `research/` / `recon/` 路徑容易讓 agent 放錯檔 | 全部改用 `workshop/<target>/`；跨 target 才用 `workshop/_all/` |

執行順序口訣：**先 standard，後 vulnscan；先 dedupe，後 Finding；先摘要，後 commit raw artifact 例外。**
