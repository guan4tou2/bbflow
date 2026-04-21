---
type: wiki
category: checklist
status: active
last-updated: 2026-04-21
---

# 送件前最後檢查 Checklist

> 每份報告送出前都必須過一遍，避免被退件 / N/A / Duplicate。

## A. PoC 驗證

- [ ] 用純 `curl` 獨立重現過（不依賴 Burp session / cookie jar）
- [ ] 每個 curl 指令都可**直接複製貼上執行**（不含佔位符）
- [ ] 回應截圖清楚（HTTP header + body）
- [ ] 若需要登入 → 提供測試帳號 or 建議 triager 如何申請
- [ ] 對政府案 → 提供 domain WHOIS 確認受影響單位是**台灣**公司/機關

## B. Scope 對照

- [ ] 目標在 SCOPE.md 的 `in-scope` 列表
- [ ] 漏洞類型不在 OOS（Out-of-Scope）列表
- [ ] 非 OOS 攻擊面（e.g. 沒動 source asset 被 pivot 出來的 target）
- [ ] 符合該 program 最低 severity 要求

## C. 查重（最容易漏的）

- [ ] 搜尋該 program 的 **disclosed reports**
- [ ] 搜尋該 program 的 **hacktivity**（HackerOne/Bugcrowd 都有）
- [ ] Google: `site:hackerone.com target漏洞類型`
- [ ] Google: `site:bugcrowd.com target漏洞類型`
- [ ] 對 CVE 類：檢查 NVD / CVE 資料庫
- [ ] 圖譜查詢：`graphify query "目標 + 漏洞類型"`

## D. Severity 不誇大

- [ ] Severity 符合平台現實標準（見 CLAUDE.md 的 Severity 對照表）
- [ ] 沒有把 unrestricted API key 寫成 P2
- [ ] 沒有把 source map 寫成 P1
- [ ] 沒有把 CORS reflect 寫成 P2（除非 prerequisite 已驗證）
- [ ] 沒有把 Actuator /health 寫成 P2
- [ ] 若 VRT 建議的 severity 太高 → 加 severity note

## E. Impact 只寫已驗證

```markdown
## Impact

**Verified impact（已驗證）:**
- [PoC 直接證明的]

**Potential impact（需額外條件）:**
- [明確標註前提條件]
```

- [ ] 每個 Verified 條目都對應到 PoC 步驟
- [ ] Potential 條目有明確寫「需要 X / 若 Y」
- [ ] 沒有無根據的「可能導致 X」
- [ ] 沒有把靜態分析寫成「已確認漏洞」

## F. 報告完整性

報告包含以下章節（見 CLAUDE.md 強制規範）：

- [ ] **漏洞概述** — 一段話摘要
- [ ] **發現過程** — 時間序列，含失敗嘗試
- [ ] **重現步驟** — 精簡版，可直接複製執行
- [ ] **攻擊鏈** — 若多漏洞，用 → 表示
- [ ] **影響** — Verified / Potential 分離
- [ ] **使用工具** — 表格（工具 / URL / 安裝 / 指令）
- [ ] **驗證狀態** — ✅ 已驗證 / ❌ 未驗證（附原因）
- [ ] **不成立的嘗試** — 避免後續重複工作
- [ ] **修補建議** — 具體可執行

## G. VRT 分類精準

**陷阱**：選錯會自動建議 P1，被 triager 判「灌水」。

| ❌ 錯誤分類 | ✅ 正確分類 |
|------------|-----------|
| Disclosure of Secrets For Publicly Accessible Asset（任何 public 資訊） | 具體類型 |
| Sensitive Data Exposure（source map 本身） | Info Disclosure > JS Source Map |
| Broken Authentication（單純 user enum） | Enum > User |
| 預設建議 P1 但實際 P3 | 選 P3 對應子類 |

**正確原則：**
- 選最精確子類別
- 寧可低不要高
- 漏洞核心是什麼就報什麼（source map 裡找到的 XSS → 報 XSS）
- VRT 建議超過實際嚴重度 → 加 severity note

## H. 政府案 / HITCON ZeroDay 專屬

- [ ] 標題用 `{組織名稱}` 隱藏單位
- [ ] 組織欄位填完整正式名稱
- [ ] 類型選對（見 CLAUDE.md §HITCON 常用漏洞類型對照）
- [ ] 風險符合 program 標準
- [ ] 附截圖用 `{{IMG#*}}` 引用
- [ ] 若非台灣企業 → 不要送 HITCON

## I. 加分項目（可選但建議）

- [ ] 提供修補建議（讓報告更有價值）
- [ ] 提供影響範圍估算（受影響用戶數 / 資料量）
- [ ] 附加佐證（git log 開發者 / 第三方資料）
- [ ] 多個相關發現打包成攻擊鏈（組合比單點更有價值）

## J. Triage 回覆後立即更新

送出後 triage 有回覆 → 依 CLAUDE.md §Triage 回覆處理規範：

- [ ] 更新 `<memory>/project_*.md`（Claude auto-memory）
- [ ] 更新 `memory/MEMORY.md`
- [ ] 更新 `vault/Target - *.md`（frontmatter + Triage 結果）
- [ ] 若觸及普遍 pattern → 更新 `Pattern - *.md`
- [ ] 新教訓寫進 `Lessons Learned.md`
- [ ] git commit → hook 自動 rebuild graphify

## K. 常見被退件原因（避免重蹈）

| 退件類型 | 原因 | 預防 |
|---------|------|------|
| N/A | Source map 無 sensitive token | 先從 source 找可利用漏洞，別單獨報 |
| N/A | Triager 回覆「tokens not sensitive」| 精準 VRT 分類，不選「Disclosure of Secrets」|
| N/A | Triager 回覆「anonymous 是預期行為」 | 分析商業邏輯，確認是漏洞不是 feature |
| Duplicate | 熱門 pattern + 大廠 | 發現後盡快送，查 disclosed reports |
| Informative | 理論性（CORS prerequisite 未驗證） | 完整驗證攻擊鏈才送 |
| Out-of-Scope | Pivot 出 scope 外 target | 嚴守原始 scope，禁 source pivot |
| Self-XSS | 只能攻擊自己 | 先確認 impact 範圍 |

## 關聯文件

- [40-checklist-new-target.md](40-checklist-new-target.md)
- CLAUDE.md §Bug Bounty 報告反誇大規範
- CLAUDE.md §Triage 教訓
