---
type: wiki
category: flow
tool: hackerone,bugcrowd,intigriti
status: active
last-updated: 2026-04-21
---

# Dupe Hunting + Report Writing（2026 版）

> **用途：** 2026 現實：熱門 program 的常見 pattern 幾乎都被報過（source map / Actuator / CORS / user enum）。**送件前 15 分鐘的 dupe 搜尋** 能救你很多信譽。本文整合：dupe 搜尋流程 + VRT 校準 + 報告結構 + N/A 避免。

## 0. 三條底線

1. **能證明才寫**：impact 必須有 PoC 支持（不寫「可能」）
2. **現實 VRT**：大廠 Unrestricted API key = P4，不寫 P2
3. **先查 dupe**：大廠熱門 pattern 1 人至少報過

違反任一條 → N/A / Informative / Severity↓ / 信譽扣。

## 1. Dupe 搜尋流程（必跑）

### 1.1 HackerOne Hacktivity

```
https://hackerone.com/hacktivity?querystring=<domain>
https://hackerone.com/<program>/hacktivity    (公開 disclosure)
```

Filter：
- Program: 目標 program
- Keyword: 漏洞名 / endpoint / CVE
- Status: Resolved / Informative

### 1.2 Bugcrowd Crowdstream

```
https://bugcrowd.com/crowdstream?category=<target>
```

### 1.3 Intigriti

```
https://www.intigriti.com/public/trending
搜尋 program 的 accepted 報告
```

### 1.4 Google dork

```
site:hackerone.com "target.com" "<漏洞關鍵字>"
site:bugcrowd.com "target.com"
"target.com" "Triaged" OR "Resolved" filetype:pdf
```

### 1.5 Twitter / blog

```
site:twitter.com "target.com" bounty
site:medium.com "target.com" bug bounty
```

### 1.6 Pentester-land / bug bounty writeups

https://pentester.land/ — 整理所有 public writeup

```
搜尋 target / 類似 pattern
```

### 1.7 GitHub search

```
site:github.com "target.com" "vulnerability"
site:github.com "target.com" "P1" OR "P2"
```

### 1.8 檢查 CVE

```
https://nvd.nist.gov/vuln/search
搜 target.com vendor
```

### 1.9 程式的 disclosed.md

很多 program 維護自己的 acknowledged list，掃一下。

## 2. VRT 現實對照（避免誇大）

### 2.1 Bugcrowd VRT 2026

https://bugcrowd.com/vulnerability-rating-taxonomy

### 2.2 常見誇大 → 合理對照

| 類別 | 通常誇大 | 合理等級 | 備註 |
|------|---------|---------|------|
| Info disclosure / source map | P2 | P5 / N/A | 除非含 sensitive secret + 可 exploit |
| Unrestricted API key (Maps/Firebase) | P2 | P4 | 除非能量化財務影響 |
| User enumeration 單獨 | P3 | P5 Informational | 串 ATO 才升級 |
| Missing header (X-Frame-Options etc.) | P4 | N/A | 多數 program 明列 OOS |
| Spring Boot Actuator /health | P2 | P3-P4 | 看洩漏內容；/env 有 secret = P2 |
| Clickjacking 無 impact | P4 | P5 / OOS | |
| Open redirect 單獨 | P3 | P5 / N/A | 串 OAuth code = P1-P2 |
| CSRF 無 impact endpoint | P3 | N/A | |
| Reflective XSS in POST only | P3 | P3-P4 | |
| Stored XSS auth-user 自己頁 | P3 | P4 | |
| CORS wildcard with credentials=true | P2 | P2 | 仍成立 |
| IDOR 讀取 public info | P3 | P4 | |
| IDOR 讀取 PII | P2 | P2 | |
| IDOR 寫入 | P1-P2 | P1-P2 | 真的高 |
| Hardcoded secret (test env) | P2 | P5 / P4 | 看 prod 可用否 |
| Subdomain takeover (no session scope) | P2 | P3 | 看載體 |
| Subdomain takeover (session scope) | P1 | P1-P2 | |

### 2.3 VRT 分類陷阱

```
錯：Source map exposure → 選 "Disclosure of Secrets"（VRT 建議 P1）
對：選「Publicly Accessible Asset — Minor Info Leak」→ P4-P5

錯：Public Google OAuth client_id → "Disclosure of Secrets"
對：不報，或報「為了完整性」註明 Informational

錯：User enumeration → "Broken Authentication"（P1）
對：「Business Logic — User Enumeration」→ P5
```

**2026 大廠抱怨：triager 看到誇大 VRT 會直接判 N/A（視為 noise）。**

## 3. 何時送、何時 hold

### 3.1 送

- 可 exploit 的高嚴重度（RCE, ATO, SQLi, IDOR write）
- 能產生具體財務 / 使用者影響
- PoC 可 5 分鐘重現
- Dupe 搜尋無類似報告

### 3.2 Hold

- 靜態分析發現但無 live exploit
- 前提條件未滿足（subdomain takeover 未實測、OAuth state 可能可猜測）
- 只有 info disclosure 無 chain
- 該 target 這類 pattern 已有 disclosed report

### 3.3 不送

- 撞 OOS（scope 明寫排除）
- 理論攻擊（無 PoC）
- Known issue / already documented
- Best-practice violation 無實際 risk

## 4. 報告結構（H1 / Bugcrowd 通用）

```markdown
## Summary
[1-2 句話：漏洞是什麼 + 怎麼 exploit + 最大影響]

## Severity
[VRT 分類 + Severity + 對應 CVSS]

## Vulnerable Endpoint
[URL / method / parameter]

## Steps to Reproduce
1. [具體步驟]
2. [具體步驟]
...

### PoC
```bash
curl ... -d '...'
```

Response:
```
HTTP/1.1 200 OK
...
```

## Impact
[只寫已驗證 impact。每個 bullet 對應 PoC step]

## Remediation
[具體修補建議，給開發可執行的 action]

## References
[相關 CVE / OWASP / PortSwigger 連結]
```

### 4.1 Summary 寫法

```
Bad: "I found XSS"
Good: "Stored XSS in /profile endpoint via name field allows code execution in other users' browsers when they view the victim's profile, enabling session theft."
```

Formula: `{漏洞名} in {endpoint} via {parameter} allows {who} to {action}, enabling {impact}.`

### 4.2 Impact 寫法

**分層寫：**

```markdown
## Impact

**Verified impact:**
- [Bullet 只列已驗證的]
- 攻擊者可讀取任意其他使用者 email（IDOR 讀 /api/users/{id}）
- 包含 PII（name, email, phone, address）

**Potential impact (需額外條件):**
- 若目標有 email confirmation flow bypass → ATO（需另外驗證）
```

**禁用：** "full compromise", "complete takeover", "critical security risk"（除非有直接證據）

### 4.3 PoC 寫法

```
# 完整 curl / screenshot / video
# 審核方 5 分鐘內能重現

curl -X GET 'https://target.com/api/users/1' \
  -H 'Authorization: Bearer <my_token_REDACTED>'

# Response:
# {"id":1,"email":"admin@target.com","role":"admin"}

Screenshot: [attached]
Video: [link to unlisted YT / loom]
```

### 4.4 Remediation 寫法

```
Good:
1. Implement ownership check: `if (req.user.id !== req.params.id && !req.user.isAdmin) return 403;`
2. Add middleware `authorizeResource` on all /api/users/:id routes
3. Review OWASP API Top 10 BOLA section

Bad:
"Fix the authorization issue"
```

## 5. 常見 N/A 原因

### 5.1 VRT 不符

- 漏洞分類選太高嚴重度
- Triager 認為分類錯

### 5.2 OOS

- Scope 明寫排除的 asset
- Excluded vulnerability type（如 "missing headers"）

### 5.3 No impact

- 無 user impact / 理論漏洞
- Best practice violation 但無 exploit

### 5.4 Already reported

- Duplicate
- Known issue

### 5.5 Informative

- 有趣但不算漏洞
- Info disclosure 無敏感

### 5.6 Report quality

- PoC 不清楚 / 重現失敗
- Impact 誇大
- 缺 step-by-step

## 6. 寫報告前 checklist

```
[ ] Dupe 搜尋：3 個平台 + Google + Twitter + 至少 15 分鐘
[ ] VRT 分類：選精確子類別，不追求最高 severity
[ ] Severity 對照表 vs 我的等級 → 是否誇大
[ ] PoC 測 3 次確認穩定
[ ] 每個 impact bullet 對應 PoC step
[ ] Remediation 具體可執行
[ ] 是否踩 OOS（每項 OOS 比對）
[ ] 報告中沒有: full compromise / critical / severe / complete takeover
[ ] Screenshot / video REDACT 自己與他人敏感資訊
[ ] 重新讀一次：triager 5 分鐘內看懂嗎
```

## 7. Follow-up 規範

### 7.1 Triage 回覆時

```
Accepted Triaged: 
- 謝謝 + 等 final severity
- 若 severity 降太多：禮貌要求 re-evaluation（附額外 PoC）

Duplicate:
- 詢問原始 submission 日期（確認時間先後）
- 承認並移下一個 target

N/A / Informative:
- 讀 triager 理由
- 若有新 evidence：禮貌補充（不爭辯）
- 若真的不成立：學到教訓，寫入 memory

Resolved:
- 感謝 + 詢問 bounty 時程
- 若 asked to re-test → 配合
```

### 7.2 禁止

- 多次 ping 催 bounty
- 公開發布報告（大多 program NDA）
- 威脅 / 情緒化 follow up

## 8. 經驗累積

```
每次 triage 結果 → 更新：
1. memory/project_<target>.md（case)
2. Lessons Learned.md（一般教訓）
3. CLAUDE.md 的 triage 教訓區塊（若是通用的）
```

## 9. 專屬 target research

### 9.1 先讀 scope

```
Scope → in-scope assets / OOS / excluded bug types
Severity rules
Bounty range
Disclosed reports
```

### 9.2 Disclosed reports 讀 5 個

```
學 program 偏好 / 常拒絕理由 / 獨特漏洞類型
```

### 9.3 Triager 偏好

看歷史 triager 評論，學他們的 language。

## 10. 心態

- 不要把「N/A」當失敗 → 是 VRT 校準的資料
- Dupe 發生是**時間競爭**，不是你不會找洞
- 寫報告的時間 = 找洞的 30% → 分配時間
- 品質 > 數量：10 個 N/A vs 3 個 P2 → 後者信譽遠高

## 關聯文件

- [41-report-writing.md](41-report-writing.md) — 報告撰寫細節
- [40-submit-checklist.md](40-submit-checklist.md) — 送件 checklist
- [02-scope-first.md](02-scope-first.md) — Scope 驗證
- Bugcrowd VRT：https://bugcrowd.com/vulnerability-rating-taxonomy
- Pentester Land writeups：https://pentester.land/writeups
- HackerOne Hacktivity：https://hackerone.com/hacktivity
