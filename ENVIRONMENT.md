# bbflow ENVIRONMENT — 路徑慣例 / 安裝方式 / 工具清單

bbflow 依賴 ~13 個外部 CLI（recon/掃描）。本檔定義**它們裝在哪、怎麼裝、版本怎麼釘**，避免再出現雙 binary / PATH 看不到 / 版本漂移。

## 路徑慣例（canonical）

| 平台 | canonical 位置 | PATH 優先 | 安裝法 |
|------|---------------|-----------|--------|
| **VPS（Hermes 自動跑）** | **`/usr/local/bin`** | `/usr/local/bin` 在 PATH 前段；`~/go/bin` **不在** | `setup_pinned_tools.sh --system`（go install → 自動 promote 到 `/usr/local/bin`，不留 go/bin 孤兒）|
| **本地（macOS 手動挖）** | 依現有 PATH | `/opt/homebrew/bin` → `~/go/bin` → `/usr/local/bin` | brew / go / pdtm 混用（見下；不強制統一）|

**鐵則**：bbflow.sh 多數工具用 `command -v` 解析 → **只裝在 `~/go/bin` 而 `~/go/bin` 不在 VPS PATH = bbflow 看不到**（曾害 dalfox/gf 裝了用不到）。VPS 一律 promote 到 `/usr/local/bin`。

## 版本釘死

- `tools.lock` = 真相來源（版本 + go module path）。
- `scripts/setup_pinned_tools.sh [--system]` = 依 lock 安裝/對齊。
- `scripts/check_tool_versions.sh` = 比對安裝 vs lock（`bbflow doctor` 結尾呼叫），漂移 warn。
- 更新政策：**刻意更新，絕不自動**。templates 週級可勤更；binary 月級 review → 改 lock → setup → `bbflow test` 回歸 → commit。

## 工具清單

**核心（lock 釘死，必裝）**：subfinder · httpx · nuclei · katana · dnsx · gau · waybackurls · ffuf · dalfox · gf
**recon 引擎（VPS）**：bbot（缺則降級 curl/crt.sh）· osmedeus（`--osmedeus`，VPS required）
**optional（缺則對應 hunter 降級）**：hakrawler(8 hunters) · uro(8) · qsreplace(1) · arjun · trufflehog · rustscan · nmap · paramspider · waymore · git-dumper · uro

## 平台現況（2026-06-11）

**VPS** — 全部 `/usr/local/bin`，`bbflow doctor` drift=0 / 無 missing：
- 核心 10 工具齊全 + osmedeus ✓ + optional 補齊：hakrawler/qsreplace/uro/git-dumper/waymore/paramspider + SecLists（`~/Tools/SecLists`，sparse Discovery/Web-Content+Fuzzing/XSS，379 wordlists）
- 僅缺 bbot（大型 recon 引擎；Hermes 用 bb_subdomain_enum 6 源不依賴）
- `~/go/bin` 已清空（487M 孤兒移除）；.bak 已刪
- **Python 工具安裝法 = 一律 uv（政策）**：不用 pip/pipx/brew。`python-tools.txt` 列清單，`scripts/setup_python_tools.sh [--system]` 用 `uv tool install` 裝（隔離 venv，自動避系統 urllib3 衝突，不碰 Hermes 系統 Python）。VPS 加 `--system` symlink `~/.local/bin/<t>` → `/usr/local/bin/<t>`（uv shim 預設 ~/.local/bin 不在非互動 PATH）。涵蓋:uro/waymore/git-dumper/arjun/paramspider（後者 `git+https://github.com/devanshbatham/paramspider.git`，不在 PyPI）。兩台皆 uv 管理（`uv tool list` 可查）。

### 終端/PATH 設定（2026-06-11 檢查）
- **VPS 登入 shell = zsh**。互動 zsh 有 `~/go/bin`（.zshrc L106），但 **`ssh host 'cmd'` 非互動 + systemd 都不 source .zshrc** → 環境只有 `/usr/local/bin`。**∴ 自動化/Hermes 只認 `/usr/local/bin`**（再次印證 canonical 決策）。`.bashrc` L141 的 PATH 加 `~/go/bin`+`/usr/local/go/bin` 對 zsh-login 是 dead config（go 實際在 `/usr/bin/go`），無害。
- **本地 macOS** zsh：`.zshrc` 用 `typeset -U path` 陣列（含 pdtm `~/.pdtm/go/bin` + `~/go/bin`），PATH 乾淨無重複。`gf` 被 oh-my-zsh git plugin alias 成 `git fetch`（互動 shell；bbflow 非互動 bash 不受影響）。

**本地（macOS）** — 已對齊 lock，`check_tool_versions` drift=0：
- go install @lock → `~/go/bin`：nuclei v3.8.0 / httpx v1.9.0 / dnsx v1.2.3 / hakrawler / gau / waybackurls / qsreplace
- brew（`/opt/homebrew/bin`，版本已符合 lock）：subfinder v2.14.0 / katana v1.6.1 / ffuf v2.1.0 / dalfox / nmap
- Python 工具 uv（`~/.local/bin`）：uro/waymore/git-dumper/arjun/paramspider
- SecLists：`~/Tools/SecLists`（sparse，379 wordlists）
- 不裝：osmedeus（VPS-required）、bbot
- **坑（已修/已知）**：
  - `httpx` 曾被 brew 的 **Python httpx**（httpie 系，壞的）遮蔽 PD httpx → 已移除 orphan、go install PD httpx v1.9.0
  - nuclei/httpx 原 pdtm 管（`~/.pdtm/go/bin`，給舊版 v3.4.7/v1.7.1）→ 移除 pdtm shadow，改 go install @lock 生效
  - `gf` 被 oh-my-zsh git plugin alias 成 `git fetch`（互動 shell）；bbflow 非互動 bash 不受影響，仍解析 `~/go/bin/gf`

## 常見坑

1. **雙 binary**：同工具在 `/usr/local/bin` + `~/go/bin` 兩份版本不同 → `command -v` 抓到哪個看 PATH。VPS 已統一 `/usr/local/bin`。
2. **`~/go/bin` 不在 VPS PATH**：go install 的工具 promote 才可見。
3. **gf alias**：互動 shell `gf` = `git fetch`，非真工具。
4. **gau/waybackurls/dnsx 無 `-version`**：lock 標 `noverify`，check 跳過驗證。
5. **dalfox v3 = breaking**：lock major-lock `/v2`。
