# bbflow — Bug Bounty Flow Toolchain

統一的 bug bounty 偵察 + pattern hunter 工具鏈。**零 LLM 依賴**，純 `bash + curl + python3 stdlib + dig`。

BBOT / Osmedeus 負責 recon（asset discovery），16 個 pattern hunter 負責驗證（confirmed-bounty patterns）。

## 快速開始

```bash
# 1. 安裝依賴
./install.sh                    # 互動式
./install.sh --all              # 非互動全安裝
./install.sh --check            # 只檢查不裝

# 2. 檢查環境
./bbflow.sh doctor              # 依賴 + 16 hunters 路徑
./bbflow.sh test                # regression null-case (14 hunter × example.com)

# 3. 對新 target 跑
./bbflow.sh init target.com     # 建 SCOPE.md 模板（scope-first 強制）
./bbflow.sh flow target.com     # init + recon + hunt 一條龍
./bbflow.sh list                # 所有 target 狀態
./bbflow.sh dedupe target.com   # 比對已送報告找重複
```

## 16 個 Hunters

對應過往 confirmed bounty 案例或已知高 ROI pattern：

| Hunter | 驗證 | 案例 |
|---|---|---|
| `hunt-hybris-occ.sh` | SAP Hybris OCC default creds + cart IDOR | SAP Hybris OCC pattern |
| `hunt-envdata.sh` | `window.envData` + AWS/Google/Sentry keys | SPA inline window config pattern ✅ |
| `hunt-sourcemap-secrets.sh` | `.js.map` → sourcesContent 密鑰 grep | multi-brand SSO / inline config |
| `hunt-hardcoded-js-secrets.sh` | live `.js` bundle 19 種密鑰 pattern | SPA hardcoded client secret pattern |
| `hunt-cors-reflect.sh` | 四層反射 + credentials:true 判斷 | reflective CORS pattern |
| `hunt-graphql-idor.sh` | 無認證 + introspection + integer ID IDOR | public GraphQL IDOR writeup ✅ |
| `hunt-user-enum.sh` | validate_email differential + rate limit | multi-brand / differential response |
| `hunt-git-exposure.sh` | `.git` 多路徑 + remote URL + `--dump` | nested .git CMS pattern ✅ |
| `hunt-subdomain-takeover.sh` | CNAME + 20+ vendor fingerprint | CNAME fingerprint pattern / UA F1 |
| `hunt-open-redirect.sh` | 20 param × 9 bypass + OAuth chain | OAuth redirect_uri chain (public pattern) |
| `hunt-jwt.sh` | decode + alg:none + weak HS256 + kid/jku | generic |
| `hunt-devops-unauth.sh` | 40+ DevOps 工具無認證 | public DevOps console leak pattern ✅ |
| `hunt-actuator-deep.sh` | Spring Boot Actuator + heapdump | Spring Boot Actuator deep probe |
| `hunt-mcp-oauth-scope.sh` | MCP OAuth consent vs token 差異 | MCP OAuth scope pattern ✅ |
| `hunt-google-api-key.sh` | `AIza*` → 16 個 Google 服務 validation | multi-service Google API key pattern ✅ |
| `hunt-nxdomain-corpus.sh` | 歷史 hostname → NXDOMAIN payload | Starbucks writeup |

✅ = 已對真實目標實測重現

詳見 [`hunters/README.md`](hunters/README.md)（每個 hunter 有範例輸出 + P1–P5 決策規則）。

## bbflow Subcommands

```
bbflow doctor                    檢查依賴與 hunter 路徑
bbflow test                      regression null-case test
bbflow init <target>             建 research/<target>/SCOPE.md 模板
bbflow recon <target> [--osmedeus]   BBOT 或 Osmedeus VPS recon
bbflow hunt <target> [--only h1,...]  對 live_hosts.txt 跑 hunters
bbflow flow <target>             一條龍 (init + recon + hunt)
bbflow dedupe <target>           比對已送報告找重複 (DUP / NEW 標記)
bbflow status [<target>]         狀態查詢
bbflow list                      列所有 target
bbflow report <target>           重跑 hunt 產生新 report
bbflow scope <target>            顯示 SCOPE.md
```

## 目錄結構

```
tools/                       (這個 repo)
├── bbflow.sh                主 CLI
├── install.sh               跨平台依賴安裝器
├── ci.sh                    本地 CI (bash syntax + doctor + test + docs align)
├── bbot_preset_bugbounty.yml   BBOT preset
├── WORKFLOW.md              完整工作流程文件
├── README.md                這個檔案
├── hunters/
│   ├── README.md            每個 hunter 的範例輸出 + 決策規則
│   ├── hunt-hybris-occ.sh
│   ├── hunt-envdata.sh
│   ├── ...  (16 個)
│   └── hunt-nxdomain-corpus.sh
└── (deprecated) hunt_all.sh / auto_hunt.sh

外部（父層）：
research/<target>/
├── SCOPE.md                 必填，scope-first 強制
├── bbot/{subdomains.txt, live_hosts.txt}
├── hunters/<name>/<slug>.txt
├── nxdomain/nxdomain_corpus.txt
└── HUNTERS_REPORT_YYYYMMDD_HHMM.md
```

## 設計原則

1. **零 LLM 依賴** — 所有 hunters 純 `bash + curl + python3 stdlib + dig`。可 cron / VPS / offline 跑。
2. **Scope-first 強制** — `bbflow recon` 沒 SCOPE.md 會拒絕。避免意外超出 scope。
3. **類型 hunter，不是特定標的** — 每個 hunter 對**任何** target 都能跑；成功案例只是靈感 + 第一個驗證目標。
4. **Differential / state-based 驗證** — 不做盲 fuzzing，只做條件判斷。FP 率低。
5. **累積樣本** — 遇到新 wrapper / 新變體，patch hunter regex，不新增新檔案。

## CI

本 repo 沒有 GitHub remote，使用本地 CI：

```bash
./ci.sh                       # 全 check（含 bbflow test 網路呼叫）
./ci.sh --fast                # 跳過網路呼叫
./ci.sh --install-hook        # 安裝 .git/hooks/pre-push
```

CI 檢查 6 類：
1. 所有 shell script bash syntax
2. hunter 內嵌 Python heredoc py_compile
3. `bbflow doctor` 全通過
4. `bbflow test` regression (14 null case 0 FP)
5. 所有 hunter 檔案 executable
6. README/WORKFLOW/實際檔案的 hunter 數量一致

## 授權 / 使用範圍

- 只對你有授權測試的 target 跑（bug bounty program scope / 自己的基礎設施 / CTF）
- `bbflow init <target>` 會強制建 SCOPE.md — 先填完整 scope 再 recon
- 不做 rate-limit bypass / DoS / mass exfil / 任何 destructive action
- 每個 hunter 的決策規則章節有「危險訊號」— 請遵守
