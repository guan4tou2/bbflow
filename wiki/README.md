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

## 🔥 大獎高頻攻擊

| # | 文件 | 說明 |
|---|------|------|
| **60** | [HTTP Request Smuggling](60-request-smuggling.md) | CL.TE / TE.CL / TE.TE / H2.CL / H2.TE + smuggler.py + Burp workflow |
| **61** | [Race Condition / Single-Packet Attack](61-race-condition.md) | TOCTOU + Turbo Intruder + 8 classic pattern（coupon/MFA/withdraw/...）|
| **62** | [File Upload Exploitation](62-file-upload-exploitation.md) | ext/MIME/magic/SVG/ZIP slip/polyglot + 各語言 shell + ImageMagick/Ghostscript |
| **63** | [Prototype Pollution](63-prototype-pollution.md) | Client-side gadget + Server-side via lodash/merge + DOM Invader + CVE table |
| **64** | [Web Cache Poisoning / Deception](64-cache-poisoning.md) | Unkeyed header / Param Miner / Cache key 測試 + Omer Gil deception |

## 🛡️ OWASP Top 10 深度攻擊

| # | 文件 | 說明 |
|---|------|------|
| **65** | [CSRF 完整指南](65-csrf-deep.md) | SameSite 2026 + JSON CSRF（text/plain trick） + referer bypass + 2FA/email change chain |
| **66** | [SSRF 深度](66-ssrf-deep.md) | Cloud metadata（AWS/GCP/Azure/K8s）+ gopher→Redis RCE + DNS rebinding + SSRFmap/Gopherus |
| **67** | [Insecure Deserialization](67-deserialization.md) | Java ysoserial + PHP phpggc(phar) + .NET ysoserial.net + Python pickle + Node.js |
| **68** | [WebSocket / CSWSH](68-websocket-cswsh.md) | Origin check bypass + CSWSH hijack + subscription IDOR + message-layer injection |
| **69** | [Mass Assignment & HPP](69-mass-assignment-hpp.md) | role/isAdmin 自提權 + HPP WAF bypass + 各框架（Rails/Django/Spring/Laravel）gotcha |
| **70** | [Host Header + CRLF Injection](70-host-header-crlf.md) | Password reset poisoning（ATO 鏈）+ X-Forwarded-Host + CRLF response splitting |

## 🧨 傳統 Top 10 深度

| # | 文件 | 說明 |
|---|------|------|
| **71** | [XSS 深度](71-xss-deep.md) | DOM sink 清單 + postMessage XSS + CSP bypass + Mutation XSS（DOMPurify CVE）+ Trusted Types bypass + CSTI per framework + blind XSS |
| **72** | [SQLi 深度](72-sqli-deep.md) | 2nd-order + OOB per-DB + 校準 blind timing + stacked 支援表 + NoSQLi（Mongo/ES/GraphQL）+ WAF bypass |
| **73** | [SSTI 深度](73-ssti-deep.md) | 指紋差異化 probe 表 + 9 個引擎 RCE gadget（Jinja2/Twig/Freemarker/Velocity/Thymeleaf/ERB/EJS/Handlebars/Smarty）+ sandbox escape |
| **74** | [Command Injection 深度](74-command-injection.md) | Sink per language + Unix/Windows 語法 + filter bypass（${IFS}/quote/encoding）+ blind OOB + argv injection |
| **75** | [XXE 深度](75-xxe-deep.md) | Blind + external DTD + parameter entity exfil + Java jar:// + PHP 全 wrapper + XInclude + SVG/DOCX/EPUB/SOAP + 防禦 config |
| **76** | [LFI / Path Traversal](76-lfi-path-traversal.md) | PHP wrapper（filter/input/data/zip/phar）+ log poisoning（apache/ssh/session）+ K8s pod token + prefix-check bypass |

## 🎯 API / Business Logic

| # | 文件 | 說明 |
|---|------|------|
| **77** | [IDOR / BOLA / BFLA](77-idor-bola-bfla.md) | OWASP API #1+#5+#3 + UUID v1 time attack + GraphQL alias batch + node interface + Autorize/AuthMatrix |
| **78** | [Open Redirect 30+ Bypass + 攻擊鏈](78-open-redirect.md) | 30+ bypass 按防禦分類 + scheme bypass + URL parser 不一致（Orange Tsai）+ OAuth code theft chain |
| **79** | [Subdomain / Cloud Takeover](79-subdomain-cloud-takeover.md) | can-i-take-over-xyz 對照 + S3/Azure/Heroku/GitHub Pages + apex session scope 高信任鏈 |
| **80** | [MFA / 2FA Bypass 手冊](80-mfa-bypass.md) | Rate limit miss / race / response manipulation / backup code enum / push bombing / trust cookie / SSO bypass |

## 🚀 2026 新熱門攻擊面

| # | 文件 | 說明 |
|---|------|------|
| **81** | [MCP Server Security](81-mcp-server-security.md) | MCP OAuth scope mismatch + tool injection + indirect prompt injection + BOLA + transport |
| **82** | [AI / LLM Security](82-ai-llm-security.md) | OWASP LLM Top 10 + direct/indirect injection + output handling + jailbreak + RAG poisoning |
| **83** | [SAML / OIDC 攻擊](83-saml-oidc-attacks.md) | XSW 8 變體 + signature stripping + comment truncation + OIDC alg/kid/JWKS/state/nonce/PKCE |

## 🛠️ Operational（流程與工具深用）

| # | 文件 | 說明 |
|---|------|------|
| **84** | [Source Code Review Flow](84-source-code-review-flow.md) | 每語言 regex + sink + framework 檔案 + semgrep/ast-grep + 2h 打洞 checklist |
| **85** | [Burp Pro 進階用法](85-burp-pro-advanced.md) | Collaborator + Turbo Intruder + Logger++ + BCheck + Bambda + DOM Invader + Match&Replace + Session |
| **86** | [Dupe Hunting + Report Writing](86-dupe-hunting-report-writing.md) | 3 平台 dupe 搜尋 + VRT 現實對照 + 報告結構 + 誇大 N/A 避免 + follow-up 規範 |

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
- **Q: 覺得有 desync / backend 解析異常？** → [60-request-smuggling.md](60-request-smuggling.md)（CL.TE/TE.CL/H2 全變體）
- **Q: 業務邏輯像會 race？** → [61-race-condition.md](61-race-condition.md)（single-packet attack + 8 pattern）
- **Q: 找到 upload endpoint 怎麼打？** → [62-file-upload-exploitation.md](62-file-upload-exploitation.md)（ext/MIME/SVG/ZIP slip 全繞法）
- **Q: 看到 lodash.merge / Object.assign user input？** → [63-prototype-pollution.md](63-prototype-pollution.md)（client + server PP）
- **Q: 有 CDN，想讓 reflected XSS 變 stored？** → [64-cache-poisoning.md](64-cache-poisoning.md)（unkeyed header + deception）
- **Q: SameSite=Lax 的 CSRF 還能打嗎？** → [65-csrf-deep.md](65-csrf-deep.md)（2-sec window + text/plain JSON CSRF + method override）
- **Q: 有 webhook/url 參數想打 SSRF？** → [66-ssrf-deep.md](66-ssrf-deep.md)（IMDS + gopher Redis RCE + DNS rebinding）
- **Q: 看到 aced0005 / unserialize / pickle？** → [67-deserialization.md](67-deserialization.md)（ysoserial/phpggc 全語言）
- **Q: 看到 wss:// WebSocket endpoint？** → [68-websocket-cswsh.md](68-websocket-cswsh.md)（Origin 不擋 → hijack）
- **Q: 註冊/profile update 有 role 欄位？** → [69-mass-assignment-hpp.md](69-mass-assignment-hpp.md)（isAdmin:true 直接提權）
- **Q: Password reset link 有 evil.com？** → [70-host-header-crlf.md](70-host-header-crlf.md)（X-Forwarded-Host ATO）
- **Q: XSS 進階（CSP/DOM/mXSS/Trusted Types）？** → [71-xss-deep.md](71-xss-deep.md)
- **Q: SQLi blind / OOB / NoSQLi？** → [72-sqli-deep.md](72-sqli-deep.md)
- **Q: 看到 ${} {{}} <%%> ${{}} 疑似 SSTI？** → [73-ssti-deep.md](73-ssti-deep.md)（9 engine RCE gadget）
- **Q: 命令注入 blind 怎麼抓？** → [74-command-injection.md](74-command-injection.md)（interactsh OOB）
- **Q: XML endpoint 要怎麼 XXE？** → [75-xxe-deep.md](75-xxe-deep.md)
- **Q: `?file=` 參數看起來可 LFI？** → [76-lfi-path-traversal.md](76-lfi-path-traversal.md)
- **Q: IDOR 怎麼系統化打？** → [77-idor-bola-bfla.md](77-idor-bola-bfla.md)
- **Q: Open redirect 怎麼提升到 P2+？** → [78-open-redirect.md](78-open-redirect.md)（OAuth chain）
- **Q: 看到 dangling CNAME？** → [79-subdomain-cloud-takeover.md](79-subdomain-cloud-takeover.md)
- **Q: 想繞 2FA / 測 MFA 強度？** → [80-mfa-bypass.md](80-mfa-bypass.md)
- **Q: 發現 MCP server endpoint？** → [81-mcp-server-security.md](81-mcp-server-security.md)
- **Q: LLM chatbot / code assistant 想測？** → [82-ai-llm-security.md](82-ai-llm-security.md)
- **Q: SAML / OIDC SSO 要怎麼測？** → [83-saml-oidc-attacks.md](83-saml-oidc-attacks.md)
- **Q: 拿到 source code 怎麼 2 小時內打出洞？** → [84-source-code-review-flow.md](84-source-code-review-flow.md)
- **Q: Burp Pro 想升級用法？** → [85-burp-pro-advanced.md](85-burp-pro-advanced.md)
- **Q: 避免 dupe / N/A 的流程？** → [86-dupe-hunting-report-writing.md](86-dupe-hunting-report-writing.md)

## 相關資源

- `bbflow.sh` — 全部 hunter 的 orchestrator（本 repo 根目錄）
- `hunters/` — 個別 hunter 原始碼
- `configs/gau.toml` — gau 設定檔
- 可選：將此 wiki 與個人 Pattern / Playbook 筆記搭配使用
