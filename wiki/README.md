---
type: wiki-index
status: active
last-updated: 2026-04-21
---

# Bug Bounty 武器庫 — Wiki

> 這個 wiki 是 **bbflow + 全工具鏈的完整操作手冊**。每個文件都能獨立照著做，不需要外部資料。
> 設計為 WAF / 防火牆後網站（政府站、金融、電信）的低噪音 bug hunting 流程。

## 🧭 Flow（照順序看）

| # | 文件 | 說明 |
|---|------|------|
| **00** | [bbflow 完整操作流程](00-bbflow-complete-flow.md) | 從 init → recon → hunt → report 一條龍，每個 subcommand 的用法 |
| **01** | [WAF / 防火牆繞過 Playbook](01-waf-bypass-playbook.md) | 政府站、Cloudflare、Akamai、Imperva 後面怎麼打 |
| **02** | [政府站 / 低風險獎金 Quick Wins](02-gov-site-quick-wins.md) | 台灣政府案常見肥肉，每項都標 ROI |
| **03** | [xray 規則本地化速查](03-xray-rules-reference.md) | ChaitinTech/xray 穩定規則對照，哪些能用 curl 重現 |

## 💣 攻擊指令速查（Attack Commands）

| # | 文件 | 說明 |
|---|------|------|
| **14** | [WAF Bypass 指令集](14-waf-bypass-commands.md) | 15+ 自動化 + 手動 WAF 繞過（header/path/method/smuggling/origin）|
| **15** | [Nuclei 攻擊 Template 全覆蓋](15-nuclei-attack-templates.md) | XSS/SQLi/SSRF/LFI/RCE/Redirect/SSTI/XXE/Takeover 每類對應指令 |
| **16** | [OAuth 2.0 / OIDC 攻擊鏈](16-oauth-attack-chains.md) | 12 種：redirect_uri bypass / PKCE / scope escalation / MCP scope / JWT alg / jku |
| **17** | [GraphQL 深度攻擊](17-graphql-deep-attacks.md) | 10 種：introspection / integer IDOR / alias overload / unauth mutation / DoS |
| **18** | [Payload 速查冊](18-payload-cheatsheet.md) | XSS polyglot / SQLi / SSTI（Jinja2/Twig/Freemarker/Velocity/ERB）/ LFI / CmdInj / SSRF / XXE / NoSQLi |

## 🧪 進階攻擊 Walkthrough

| # | 文件 | 說明 |
|---|------|------|
| **19** | [Subdomain Recon 深度擴充](19-subdomain-recon-deep.md) | passive + active + permutation + 3rd-party + ASN 全鏈 |
| **31** | [JWT 攻擊 Walkthrough](31-jwt-attack-walkthrough.md) | alg:none / HS256 brute / alg confusion / kid/jku injection + jwt_tool |
| **32** | [Cloud Key / Credential 濫用](32-cloud-key-abuse.md) | AWS/GCP/Azure + SaaS key 驗證守則（只 list 不 modify）|
| **33** | [Nuclei 自寫 Template 教學](33-nuclei-custom-templates.md) | matchers/extractors/payloads/headless/DSL + 實戰範例 |

## 🎯 Hunters（bbflow 內建 hunter 詳解）

| # | Hunter | 目的 | 文件 |
|---|--------|------|------|
| 10 | `config-leak` | xray 式 config 洩漏（.git/.env/actuator/swagger/100+ paths） | [詳細](10-hunter-config-leak.md) |
| 11 | `weak-login` | 常見管理介面 default creds 單次探測（nacos/druid/grafana/...） | [詳細](11-hunter-weak-login.md) |
| 12 | `backup-files` | 備份 / dump 檔（zip/tar.gz/sql/bak） | [詳細](12-hunter-backup-files.md) |
| 13 | `crawl-chain` | katana+gau+paramspider → uro+gf → arjun → nuclei DAST → dalfox | [詳細](13-hunter-crawl-chain.md) |
| 14 | `waf-bypass` | 15+ 自動化 WAF 繞過（header/path/method/origin IP） | [指令集](14-waf-bypass-commands.md) |
| 15 | `nuclei-deep` | 擴充 18 類別攻擊面（XSS/SQLi/SSRF/LFI/RCE/SSTI/XXE/...） | [指令集](15-nuclei-attack-templates.md) |
| — | 其他既有 hunters | envdata / sourcemap / js-secrets / cors / graphql / userenum / ... | 見 [hunters/README.md](../../../tools/hunters/README.md) |

## 🔧 Tools（個別工具操作手冊）

**Recon / 存活偵測**

| # | 工具 | 用途 | 文件 |
|---|------|------|------|
| 20 | `katana` | 現代 JS-aware crawler（SPA 友善） | [詳細](20-tool-katana.md) |
| 21 | `gau` | 歷史 URL（wayback + commoncrawl + otx + urlscan） | [詳細](21-tool-gau.md) |
| 22 | `subfinder` + `httpx` | 子域名 + 存活 | [詳細](22-tool-subfinder-httpx.md) |

**Discovery / Fuzzing**

| # | 工具 | 用途 | 文件 |
|---|------|------|------|
| 23 | `arjun` | 隱藏 HTTP parameter discovery | [詳細](23-tool-arjun.md) |
| 24 | `nuclei` | YAML-based template scanner（含 DAST） | [詳細](24-tool-nuclei.md) |
| 25 | `dalfox` | 深度 XSS scanner | [詳細](25-tool-dalfox.md) |
| 26 | `ffuf` + `feroxbuster` | 目錄 / 檔案 fuzzing | [詳細](26-tool-ffuf.md) |

**Secrets / Source**

| # | 工具 | 用途 | 文件 |
|---|------|------|------|
| 27 | `trufflehog` + `gitleaks` | 100+ 種 secret detector | [詳細](27-tool-trufflehog.md) |
| 28 | `git-dumper` + `GitTools` + `GitHack` | `.git/` 洩漏還原 | [詳細](28-tool-git-dumper.md) |

**SQL Injection / Manual Testing**

| # | 工具 | 用途 | 文件 |
|---|------|------|------|
| 29 | `sqlmap` | SQL Injection 自動化（B/U/T/E/S/Q + tamper + WAF bypass） | [詳細](29-tool-sqlmap.md) |
| 30 | Burp Suite / Caido | 手動 Intercept / Repeater / MITM | [詳細](30-tool-burp-caido.md) |

## 📋 Checklist（對著表單打勾）

| # | Checklist | 用途 |
|---|-----------|------|
| 40 | [初次接觸新標的 Checklist](40-checklist-new-target.md) | 24 小時內把 attack surface 鋪開 |
| 41 | [送件前 Checklist](41-checklist-before-submit.md) | 避免低級退件（VRT 分類、誇大、dupe） |

## 🧠 常見問答

- **Q: WAF 擋住掃描怎麼辦？** → 看 [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) + [14-waf-bypass-commands.md](14-waf-bypass-commands.md)
- **Q: Nuclei 預設 template 掃不到東西？** → 看 [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md)（18 類別實戰）+ [24-tool-nuclei.md](24-tool-nuclei.md) + [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md)
- **Q: 政府站哪些漏洞最容易中？** → 看 [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- **Q: gau 怎麼設定 API key？** → 看 [21-tool-gau.md](21-tool-gau.md) §「設定檔」
- **Q: 找到 SQLi 想 dump DB？** → 看 [29-tool-sqlmap.md](29-tool-sqlmap.md)
- **Q: 新標的 24h 內要打哪裡？** → 看 [40-checklist-new-target.md](40-checklist-new-target.md)（10 階段）
- **Q: OAuth/SSO 怎麼測？** → [16-oauth-attack-chains.md](16-oauth-attack-chains.md)（12 類攻擊 + PoC）
- **Q: GraphQL endpoint 該測什麼？** → [17-graphql-deep-attacks.md](17-graphql-deep-attacks.md)（introspection → IDOR → alias overload）
- **Q: 手動測時的 payload 口袋本？** → [18-payload-cheatsheet.md](18-payload-cheatsheet.md)（XSS/SQLi/SSTI/LFI/CmdInj/SSRF/XXE）
- **Q: subfinder 覆蓋率不夠怎麼辦？** → [19-subdomain-recon-deep.md](19-subdomain-recon-deep.md)（passive + active + permutation + ASN 5 層）
- **Q: JWT 找到了要怎麼攻？** → [31-jwt-attack-walkthrough.md](31-jwt-attack-walkthrough.md)（12 種實作缺陷 + jwt_tool 指令）
- **Q: 找到 AWS/GCP key 怎麼驗證又不會踩線？** → [32-cloud-key-abuse.md](32-cloud-key-abuse.md)（安全原則 + SaaS key 對照表）
- **Q: Nuclei 想自寫 template？** → [33-nuclei-custom-templates.md](33-nuclei-custom-templates.md)（matchers/extractors/DSL 全解 + 4 實戰範例）

## 相關資源

- `bbflow.sh` — 全部 hunter 的 orchestrator（本 repo 根目錄）
- `hunters/` — 個別 hunter 原始碼
- `configs/gau.toml` — gau 設定檔
- 可選：將此 wiki 與個人 Pattern / Playbook 筆記搭配使用
