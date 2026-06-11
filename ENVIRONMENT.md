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

**VPS** — 全部 `/usr/local/bin`，`bbflow doctor` 版本檢查 drift=0：
- 核心 10 工具齊全 + bbot? / osmedeus ✓
- `~/go/bin` 已清空（487M 孤兒移除）；舊版備份 `/usr/local/bin/{nuclei.v337,katana.v110}.bak`

**本地（macOS）** — 四種安裝法混用（works，未強制統一）：
- brew：subfinder/httpx/katana/ffuf/dalfox/nmap（`/opt/homebrew/bin`）
- pdtm：nuclei（`~/.pdtm/go/bin`，ProjectDiscovery Tool Manager）
- go：gau/waybackurls（`~/go/bin`）
- **坑**：`gf` 被 shell alias 成 `git fetch`（互動 shell）；bbflow 非互動 bash 不受影響，仍解析 `~/go/bin/gf`
- 缺：dnsx（subfinder companion，非 hunter 必需）

## 常見坑

1. **雙 binary**：同工具在 `/usr/local/bin` + `~/go/bin` 兩份版本不同 → `command -v` 抓到哪個看 PATH。VPS 已統一 `/usr/local/bin`。
2. **`~/go/bin` 不在 VPS PATH**：go install 的工具 promote 才可見。
3. **gf alias**：互動 shell `gf` = `git fetch`，非真工具。
4. **gau/waybackurls/dnsx 無 `-version`**：lock 標 `noverify`，check 跳過驗證。
5. **dalfox v3 = breaking**：lock major-lock `/v2`。
