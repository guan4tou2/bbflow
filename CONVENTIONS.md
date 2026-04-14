# CONVENTIONS — bbflow 貢獻規範

這份文件定義 bbflow repo 的撰寫規範，確保 **repo 內容是 target-agnostic 的通用 pattern**，不含任何真實 bug bounty 研究細節或 credential。

核心原則：

> **Hunter 是類型工具，不是案例記事本。**
> target-specific 內容屬於你的個人 memory / research 目錄，**不進這個 repo**。

---

## 🔴 禁止進入 repo 的內容

### 1. 真實 credentials
任何形式的真實 API key / token / password / JWT / secret：

- ❌ 真 Google API key (格式：`AIza` + 35 字元)
- ❌ 真 AWS Location key (格式：`v1.public.` + base64 blob)
- ❌ 真 JWT (格式：`eyJ...` + 兩個 `.` 分隔段)
- ❌ 真 `sk_live_...` / `ghp_...` / `xoxb-...` / `AKIA...`
- ❌ 任何 base64 / hex 字串超過 20 字元看起來像 credential 的

**改用 placeholder：**
- ✅ `AIza[REDACTED_demo_key_0000000000000000000]`（keep 字首，其餘 X）
- ✅ `<API_KEY>` / `<TOKEN>` / `<SECRET>`
- ✅ `AIzaSy[FAKE_KEY_FOR_TESTING]`

### 2. 真實 production / staging hostname
任何可以連到真實 bug bounty target 的主機名：

- ❌ 特定 SAP Commerce Cloud staging host（`*.model-t.cc.commerce.ondemand.com`）
- ❌ 特定 bug bounty target 的 FQDN（例：`*.example-target-brand.com`）
- ❌ 任何會 resolve 到 bug bounty program 基礎設施的 FQDN

**改用 placeholder：**
- ✅ `example.com` / `target.example.com`
- ✅ `api.example.com` / `cms.example.com`
- ✅ 保留 SaaS vendor 的 generic host name（e.g. `*.herokuapp.com`、`*.s3.amazonaws.com`）— 這些是 vendor domain，不是個別 target

### 3. 特定 target 品牌名稱連結到研究細節
Target 品牌名稱**單獨**出現在公開 writeup 引用時可保留，但**連結到你個人研究**的絕對禁止：

- ❌ "<Brand> P2 ready-to-submit"
- ❌ "<Brand> 6-brand validate_email"
- ❌ "<Brand> HITCON ZeroDay"
- ❌ "<Brand> N companies records"

**改用 pattern 名稱：**
- ✅ "SAP Hybris OCC default creds pattern"
- ✅ "multi-brand validate_email differential"
- ✅ "nested .git via CMS subpaths"
- ✅ "public GraphQL IDOR writeup"

**公開 writeup 可保留攻擊者歸屬**（因為已經公開）：
- ✅ "Starbucks NXDOMAIN (ArgosDNS writeup 2026)"
- ✅ "$15K IDOR writeup (InfoSec Writeups 2026-03)"
- ✅ 任何有 CVE 編號或公開揭露連結的案例

### 4. 具體識別符
任何可追溯到真實 target 或使用者的字串：

- ❌ 具體 cart GUID / shipment ID / account ID
- ❌ AWS account number（12 位數字）
- ❌ Okta clientId / Firebase projectId / GitHub org name
- ❌ 內部員工 email / 開發者名稱（從 git commit log 抓到的）

**改用 placeholder：**
- ✅ `<CART_GUID>` / `<SHIPMENT_ID>` / `<AWS_ACCOUNT_ID>`
- ✅ 明顯的 fake 值（`00000000-0000-0000-0000-000000000000`）

### 5. 「ready-to-submit」/「queued」標註
任何暗示「這是我正在積極送件的發現」：

- ❌ "✅ ready-to-submit"
- ❌ "🟠 待送件"
- ❌ "P2/High queued"
- ❌ "active submission"

**改用中性描述：**
- ✅ "pattern validated via public case"
- ✅ "implementation reference"
- ✅ "(測試通過)" / "(smoke tested)"

---

## 🟢 允許進入 repo 的內容

### ✅ Hunter 邏輯本身
- 完整的 curl 命令、regex、差異判斷
- 決策規則（P1–P5 對照表）
- 範例輸出（使用 placeholder）
- Pattern 名稱 + 公開 writeup 引用

### ✅ 通用 pattern 知識
- OWASP Top 10、CWE 列表
- SAP Hybris / Spring Boot / GraphQL 協定規格
- OAuth 2.0 / JWT / MCP RFC 引用
- `can-i-take-over-xyz` vendor fingerprint 對照

### ✅ 公開 demo / 教學站
- `example.com`（IANA 保留）
- `demo.goharbor.io`（Harbor 公開 demo）
- `httpbin.org` / `neverssl.com` 之類
- 任何 CTF / Wargame / HTB 公開練習環境

### ✅ 你自己的測試環境
- 你架在本機 / VPS 的 honeypot
- 你購買並授權測試的設備 / account

---

## 撰寫流程（避免意外洩漏）

### 新增 hunter 時

1. **先寫 pattern 說明，不寫 target**：
   ```bash
   # 來源：SAP Hybris OCC default creds pattern
   # （某 P2 pattern，details 在個人 memory）
   ```

2. **範例輸出用 placeholder**：
   ```
   🔴 F1 default OAuth creds: mobile_android:secret → token acquired
   🔴 F2 anonymous baseSites: site1,site2,site3,...
   ```
   **不要**貼你真的 PoC 的完整輸出。

3. **測試時用本地 alias**：
   ```bash
   export REAL_TARGET="https://<real-target-host>"
   ./hunt-hybris-occ.sh "$REAL_TARGET"
   ```
   用環境變數或本地 `.env`（加進 `.gitignore`），不要把真 URL 寫進檔案。

### 更新 case mapping 時

你的 target→hunter 對應表屬於 **個人 memory**，不是 bbflow repo：

- 真實案例紀錄 → `~/.claude/projects/.../memory/`
- Target 研究筆記 → `research/<target>/`（主 repo，也不進 tools/）
- bbflow 對照表 → **只寫 pattern 類別，不寫具體 target**

### Commit 前 grep 檢查

```bash
# 每次 commit 前跑一次
cd tools
grep -rnE "AIza[A-Za-z0-9_-]{35}|eyJ[A-Za-z0-9_-]{20,}\.eyJ|sk_live_|ghp_[A-Za-z0-9]{36}|v1\.public\." \
  --include="*.sh" --include="*.md" --include="*.yml" 2>/dev/null
# 應該只回 placeholder，沒有真值
```

可以把這個 grep 加進 `ci.sh` 當 secret-scanner step。

---

## 歷史資訊搬家清單

以下 target 的資訊應該留在 **個人 memory 或 research/**（不在 tools repo）：

- 特定 staging hostname
- PoC 產出的具體 GUID / ID / 截圖檔名
- 「這個 pattern 來自哪個 program」的對應
- bounty 金額 / 送件日期 / triage 狀態
- 開發者 email / 供應鏈公司名稱

反之以下可以留在 tools repo：

- 「SAP Hybris 有 default creds pattern」這個知識
- 「pattern 的判斷條件是 ...」這個邏輯
- 「送件時要注意 severity 上限是 P3」這種 triage 經驗談（去識別化後）

---

## 強制檢查

`ci.sh` 之後會新增 `secret-scan` step，以下正則任何 match 都會 CI fail：

```
AIza[A-Za-z0-9_-]{35}
eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+
sk_live_[0-9a-zA-Z]{24,}
ghp_[A-Za-z0-9]{36}
xox[baprs]-[A-Za-z0-9-]{10,}
v1\.public\.[A-Za-z0-9_-]{40,}
-----BEGIN (RSA|OPENSSH|PRIVATE)
```

想白名單：加到 `ci.sh` 的 `SECRET_SCAN_WHITELIST` 陣列並註明理由。

---

## 違規處理

如果發現 commit 已經進了敏感資訊：

1. **立即**：revoke 真實 credential（Google Cloud console / Okta / GitHub 等）
2. **30 分鐘內**：從 working tree 移除 + 新 commit
3. **當天**：如果 repo 是 private，單 squash 新歷史；如果 public 或曾 push 過，用 `git filter-repo --replace-text` 重寫歷史 + force push
4. **通報**：加進 `INCIDENTS.md`（如果有），寫入教訓
5. **更新**：擴充本檔案的禁止清單

**不要**假設「只是私有 repo 沒關係」— 未來可能轉 public、可能 leak、可能被 AI 工具 index。
