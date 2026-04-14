# Contributing to bbflow

感謝你對 bbflow 感興趣。這個工具鏈的核心價值是 **target-agnostic pattern hunters**，所以貢獻規範比一般 OSS 嚴格一點。

## 貢獻流程

### 1. 先讀 [`CONVENTIONS.md`](CONVENTIONS.md)

核心規則：
- **Hunter 是類型工具，不是案例記事本** — 不要寫「來源：某某公司」，要寫「來源：公開 writeup / 通用 pattern」
- **不要 commit 真實 credential、staging hostname、cart GUID、AWS account ID**
- **不要 commit 你自己還沒送的 bug bounty 發現**

### 2. Fork + clone + install

```bash
gh repo fork guan4tou2/bbflow --clone
cd bbflow
./install.sh --check    # 確認依賴
./ci.sh                 # baseline 應該 47 pass / 0 fail
```

### 3. 寫新 hunter 或修 bug

- 新 hunter 放 `hunters/hunt-<name>.sh`，follow 既有檔案的結構：
  - 檔頭 comment：`# 來源：<pattern 類別 + 公開 writeup 引用>`
  - `set -uo pipefail`
  - 標準 `log/hit/warn` 函式
  - 輸出到 `$OUT_DIR`
- 更新對照表：
  - `bbflow.sh` 的 `cmd_hunt` dispatch + `usage` 的 hunter 清單
  - `WORKFLOW.md` 的 hunter 表格
  - `README.md` 的 hunter 表格
  - `hunters/README.md` 加對照表列 + 範例輸出 + 決策規則
- 更新 `bbflow.sh test` 的 `cmd_test` 加 null case smoke test
- 跑 `./ci.sh` 全綠才能 PR

### 4. Pull Request

- 一個 PR 一個 pattern
- 在 PR description 說明：
  - 這個 pattern 對應的公開 writeup / CVE / 已披露案例（提供 URL）
  - 真實命中的驗證目標（如果是你自己的授權目標，說「local validation pass」即可，不要貼 hostname）
  - FP rate estimate
- PR checklist：
  - [ ] `./ci.sh` 47+ pass
  - [ ] 範例輸出用 placeholder（`AIza[REDACTED]` / `<GUID>` / `target.example.com`）
  - [ ] 檔案裡沒有品牌名（除了公開 writeup 引用）
  - [ ] CONVENTIONS.md 規則全部遵守

## 不接受的 PR

- 含真實 credential 或 token 的 PR（會立即 close，請你先 revoke 再 reopen）
- 硬編碼你研究過的 bug bounty target URL
- 加入 destructive / rate-limit bypass / DoS 功能的 hunter
- 目標特定（只對某個 vendor 才有意義）的 hunter，除非 vendor 是開源/公開 SaaS

## Bug 回報

開 GitHub issue，包含：
- 執行的 hunter + 命令
- 觀察 vs 預期行為
- `./ci.sh` 輸出
- OS + bash version

**不要**在 issue 裡貼：
- 真實 target hostname
- API key / token / JWT
- PoC 命中時的敏感 response

## 安全回報

如果發現 bbflow 本身的漏洞（例如 hunter 腳本有 shell injection），請直接 email 維護者（見 GitHub profile），不要開公開 issue。

## Coding style

- Bash: 4-space indent, `set -uo pipefail`, 大寫 constants
- Python: PEP 8, `python3 stdlib only`（不要加 pip deps）
- Shell quoting: 全部 quote，`"$VAR"` not `$VAR`
- curl: `-sk --max-time <N>` 避免 hang
- Markdown: 標題使用 `##`，繁中 + 英文技術術語混合 OK

## Hunter 命名慣例

`hunt-<pattern-kebab-case>.sh`:
- `hunt-<vuln-class>` 例：`hunt-cors-reflect`、`hunt-jwt`
- `hunt-<target-type>-<pattern>` 例：`hunt-hybris-occ`、`hunt-devops-unauth`
- `hunt-<ecosystem>-<pattern>` 例：`hunt-mcp-oauth-scope`

不要用：
- `hunt-<brand>.sh` — 違反 target-agnostic 原則
- `hunt-<exploit>.sh` — 我們做偵測不做 exploit
