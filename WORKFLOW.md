# Bug Bounty 工作流程與工具集

## 零、一鍵自動化入口（優先嘗試）

bbflow 是統一 CLI，包裝 BBOT recon + 21 個 pattern hunter，最後產出 `research/<target>/HUNTERS_REPORT_*.md`。

### 安裝

```bash
git clone https://github.com/guan4tou2/bbflow.git
cd bbflow
./install.sh          # 互動式
./install.sh --all    # 全自動（VPS / CI）
# install.sh 會自動建立 bbflow → ~/.local/bin/bbflow symlink
```

或用 Docker（零本地依賴）：

```bash
curl -sO https://raw.githubusercontent.com/guan4tou2/bbflow/main/bbflow-docker.sh
chmod +x bbflow-docker.sh
./bbflow-docker.sh doctor
```

### 常用指令

```bash
# 第一次使用
bbflow doctor                         # 檢查依賴與 hunter 路徑

# 一條龍 (init + recon + hunt)
bbflow flow target.com

# 分階段
bbflow init target.com                # 建 research/<target>/SCOPE.md 模板（必須先填）
bbflow recon target.com               # BBOT passive recon
bbflow hunt target.com                # 對 live_hosts.txt 跑全 21 hunters

# IP / domain / URL 清單輸入（跳過 recon）
bbflow hunt --list hosts.txt
bbflow hunt --list hosts.txt --probe  # 先 httpx 探活
bbflow hunt --list hosts.txt --only cors,graphql,envdata

# Osmedeus VPS 模式
export OSMEDEUS_VPS="user@1.2.3.4"
bbflow recon target.com --osmedeus

# 認證掃描（export 後所有 hunter 會繼承）
export DALFOX_COOKIE="session=abc123"
export FFUF_COOKIE="session=abc123"
export ARJUN_HEADERS="Authorization: Bearer xxx"
bbflow hunt target.com --only dalfox-xss,ffuf-dirs,arjun-params

# 查狀態
bbflow list                           # 所有 target 概覽
bbflow status target.com              # 單一 target 詳情
bbflow dedupe target.com              # 比對已送報告找重複
bbflow nuclei-update                  # 更新 PD templates + Wordfence CVE
```

> workspace 預設為執行目錄；可 `export BBFLOW_WORKSPACE=~/work` 固定路徑。

**21 個 hunters 對應的成功案例 / 已知 pattern：**

| Hunter | 驗證什麼 | 來源案例 |
|--------|---------|---------|
| `hunt-hybris-occ.sh` | SAP Hybris OCC default OAuth creds + 匿名 cart + GUID IDOR + configParam API keys | SAP Hybris OCC pattern |
| `hunt-envdata.sh` | `window.envData` / `defineProperty` / `__INITIAL_STATE__` / `ssInlineConfig` + AWS/Google/Sentry/Mapbox 密鑰 | SPA inline window config pattern ✅ 實測重現 |
| `hunt-sourcemap-secrets.sh` | `.js.map` 暴露 + sourcesContent 內 API key / Bearer / Stripe / JWT | multi-brand SSO / disclosed source map cases |
| `hunt-hardcoded-js-secrets.sh` | live `.js` bundle grep 19 種硬編碼密鑰 pattern（AWS/AIza/GitHub/Stripe/Slack/JWT/Sentry/Mapbox/Twilio/clientSecret…）| SPA hardcoded client secret pattern |
| `hunt-cors-reflect.sh` | 四層反射：arbitrary / null / regex prefix / suffix bypass + credentials:true | reflective CORS pattern |
| `hunt-graphql-idor.sh` | 無認證 `__typename` + introspection + field suggestion + list query + integer ID IDOR | public GraphQL IDOR writeup ✅ 實測重現 |
| `hunt-user-enum.sh` | GET/POST validate_email differential + password reset + 20-req rate limit | multi-brand SSO / differential response pattern |
| `hunt-git-exposure.sh` | `.git/HEAD` 多路徑探測 + remote URL → 供應鏈 + `--dump` 三工具 + credential grep | nested .git via CMS subpaths ✅ 實測重現 |
| `hunt-subdomain-takeover.sh` | CNAME → 20+ vendor fingerprint + claimability 判斷 | CNAME → vendor fingerprint |
| `hunt-open-redirect.sh` | 20 redirect param × 9 bypass 變體 + 常見 OAuth/logout 路徑 | OAuth redirect_uri chain (public pattern) |
| `hunt-jwt.sh` | JWT decode + alg:none + weak HS256 + exp + kid/jku injection | generic |
| `hunt-devops-unauth.sh` | 40+ DevOps 工具無認證（Harbor/ArgoCD/Jenkins/Grafana/Prometheus/Kibana/Consul/etcd/K8s/Docker Registry/Gitea/GitLab/SonarQube/Nexus/Artifactory/Rancher/Portainer/Vault/Traefik/Rundeck）| public DevOps console leak pattern |
| `hunt-actuator-deep.sh` | Spring Boot Actuator 深度：`/env` / `/configprops` / `/mappings` / `/beans` / `/httptrace` / `/loggers` / `/jolokia` / `--heapdump` + strings grep | Spring Boot Actuator deep probe |
| `hunt-mcp-oauth-scope.sh` | RFC 8414 OAuth discovery + MCP JSON-RPC probe + consent vs `MCP_TOKEN` 實際 write tool 差異 | MCP OAuth scope mismatch pattern |
| `hunt-google-api-key.sh` | 對 `AIza*` key 測 16 個 Google 服務可用性 + 自動 severity hint | multi-service Google API key pattern ✅ 實測（Vision + Translate UNRESTRICTED）|
| `hunt-nxdomain-corpus.sh` | 歷史 hostname 超集 → NXDOMAIN 過濾（待遇到 Host-header controllable proxy 時當 payload）| Starbucks writeup |
| `hunt-param-fuzz.sh` | katana+gau+waybackurls URL 收集 → gf filter XSS/SQLi/SSRF → nuclei DAST templates 驗證 | DAST fuzzing |
| `hunt-dalfox-xss.sh` | gf xss filter → dalfox 掃描（blind XSS 支援）+ payloads/xss-custom.txt | reflected/blind XSS |
| `hunt-arjun-params.sh` | arjun GET/POST/JSON 隱藏參數探索 + SecLists burp-parameter-names | hidden param hunting |
| `hunt-trufflehog-secrets.sh` | trufflehog git mode `--only-verified` 100+ detector：AWS/GitHub/Stripe/GCP/Azure | git history secret scan |
| `hunt-ffuf-dirs.sh` | ffuf 三層 dir fuzzing：raft-medium + BB-ROI + 副檔名（.bak/.sql/.env/.git）；feroxbuster fallback | dir/file exposure |
| `hunt-portscan.sh` | rustscan → nmap service detection；自動標記高風險服務（Docker API/Redis/ES/Mongo/Consul）| port scan + service detection |

**單獨執行某個 hunter：**

```bash
./tools/hunters/hunt-hybris-occ.sh https://api-example.hashed-staging-s1-public.model-t.cc.commerce.ondemand.com
./tools/hunters/hunt-envdata.sh https://insight.example.com
./tools/hunters/hunt-cors-reflect.sh https://cloudaccess.svc.example.com/devices
```

每個 hunter 的 `🔴` 前綴 = 高信心命中，寫入 `./[name]_out/<slug>.txt`。詳細用法、範例輸出、如何判定真命中 vs 假陽性見 [`tools/hunters/README.md`](hunters/README.md)。

**零 LLM 依賴**：所有 hunters 都是純 `curl + python3 stdlib + bash + dig`，可離線批次執行，不需要任何 API key 或模型呼叫。

---

## 一、偵察階段 (Reconnaissance)

> ⚡ **自動化替代**：`./tools/bbflow.sh flow target.com` 已內建 BBOT passive subdomain + httpx 存活 + 全套 hunters。這章節保留作為手動控制 / 除錯用。

### 1.1 目標搜尋

```bash
# Google Dork（Chrome 手動搜尋，避免 CAPTCHA）
site:.tw inurl:".git" intitle:"Index of"
site:.tw inurl:".env" "DB_PASSWORD"
site:.tw "phpinfo()" ext:php
site:.tw inurl:"swagger" "api"
site:.tw "Index of" "sql" OR "backup" OR "dump"

# HITCON ZeroDay 過往報告研究
# https://zeroday.hitcon.org/vulnerability/disclosed

# crt.sh 子域名列舉
curl -s "https://crt.sh/?q=%.target.com.tw&output=json" | \
  python3 -c "import sys,json; [print(v) for v in sorted(set(l.strip() for d in json.loads(sys.stdin.read()) for l in d['name_value'].split('\n') if '*' not in l))]"
```

### 1.2 子域名與資產發現

```bash
# subfinder
subfinder -d target.com.tw -o subs.txt

# httpx 存活探測
cat subs.txt | httpx -title -status-code -tech-detect -o alive.txt

# nuclei 批次掃描
nuclei -l alive.txt -severity critical,high,medium -o nuclei_results.txt
```

## 二、.git 洩漏利用（四工具流水線）

### 2.1 確認 .git 可存取

```bash
curl -sk -o /dev/null -w "%{http_code}" https://target/.git/HEAD
# 200 且內容含 "ref: refs/heads/" = 可利用
```

### 2.2 四工具流水線（按順序嘗試）

```bash
TARGET="https://target.com.tw"
OUTDIR="./dump/target"

# Step 1: git-dumper（首選 — 能還原 commit 歷史）
python3 -m git_dumper "${TARGET}/.git/" ${OUTDIR}/git-dumper/

# Step 2: 檢查結果
FILE_COUNT=$(find ${OUTDIR}/git-dumper/ -type f -not -path "*/.git/*" | wc -l)
echo "git-dumper: ${FILE_COUNT} files"

# Step 3: 如果 < 10 個檔案，用 GitTools 補
if [ "$FILE_COUNT" -lt 10 ]; then
  bash tools/GitTools/Dumper/gitdumper.sh "${TARGET}/.git/" ${OUTDIR}/gittools/
  bash tools/GitTools/Extractor/extractor.sh ${OUTDIR}/gittools/ ${OUTDIR}/gittools_extracted/
fi

# Step 4: GitHack 兜底
python3 GitHack.py "${TARGET}/.git/"

# Step 5: 如果目標有目錄列表（Index of），直接 wget
# wget -r -np -nH --cut-dirs=1 ${TARGET}/.git/
```

### 2.3 .git 分析 SOP

```bash
cd ${OUTDIR}/git-dumper/

# 1. 查看 commit 歷史
git log --format="%h %ae %ai %s"

# 2. 搜尋密碼變更歷史（最重要！）
git log -p --all | grep -iE "^\+.*(password|secret|key|smtp|token|api_key)" | \
  grep -v "function\|param\|class\|interface\|vendor" | sort -u

# 3. 查看 remote（GitLab/GitHub 私有倉庫）
git config --get remote.origin.url

# 4. 查看開發者資訊
git log --format="%ae" | sort -u

# 5. 查看 reflog（部署伺服器資訊）
cat .git/logs/HEAD

# 6. 搜尋原始碼中的敏感資訊
grep -rn "password\|secret\|api_key\|token\|smtp" --include="*.php" --include="*.py" --include="*.js" --include="*.json" --include="*.env" --include="*.yml" | \
  grep -v "vendor\|node_modules\|test\|example\|README"
```

## 三、網站漏洞測試

### 3.1 資訊洩漏檢查

```bash
# 一次性檢查常見洩漏路徑
for path in /.env /.git/HEAD /phpinfo.php /server-status /phpmyadmin/ \
  /swagger/ /api-docs /robots.txt /.DS_Store /web.config /wp-config.php.bak; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -m 5 "https://target${path}")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "${path} → HTTP ${code}"
done
```

### 3.2 XSS 測試

```bash
# DOM XSS — 搜尋前端 JS 中的 .html() sink
grep -rn "\.html(\|\.innerHTML\|document\.write\|v-html" assets/js/

# 反射型 XSS — 測試 URL 參數
# 用 <img src=x onerror=document.title='XSS'> 作為安全的 PoC
```

### 3.3 SQL Injection

```bash
# 原始碼審計 — 搜尋直接拼接
grep -rn "\$_POST\|\$_GET\|\$_REQUEST" --include="*.php" | \
  grep -v "vendor\|node_modules" | \
  grep "query\|where\|select\|insert\|update\|delete\|LIKE"
```

## 四、韌體分析

### 4.1 韌體解包

```bash
# binwalk 解包
binwalk -Me firmware.bin

# 如果 binwalk 失敗，用 Docker
docker run --rm -v $(pwd):/fw debian:bookworm-slim sh -c \
  "apt-get update -qq && apt-get install -y -qq binwalk squashfs-tools && \
   cd /fw && binwalk -Me firmware.bin"
```

### 4.2 韌體靜態分析 SOP（CLAUDE.md 驗證等級）

```bash
# Level A: 直接證據
cat etc/passwd              # 硬編碼帳密
cat etc/shadow              # 密碼 hash
find . -name "*.pem" -o -name "*.key"  # SSL/SSH 私鑰
cat etc/inetd.conf          # 危險服務

# Level B: 反組譯確認呼叫鏈
strings -t x binary | grep "system\|popen\|sprintf.*%s"
objdump -d binary | grep -A5 "system@plt"

# Level C: 僅 strings（不可獨立提交）
strings binary | grep "password\|admin\|root"

# 本地 C 模擬 PoC（升級 B→A）
gcc -Wall -o poc poc.c && ./poc
```

### 4.3 Claude Code 漏洞掃描器

```bash
cd tools/vuln_scanner/
# 掃描單一檔案
python3 vuln_scanner.py --firmware target.cgi

# 批次掃描目錄
./scan_firmware.sh /path/to/extracted/cgi-bin/
```

## 五、APK 分析

### 5.1 下載與反編譯

```bash
# 下載 APK（apkeep 或 APKPure）
pip3 install apkeep
apkeep -a com.target.app .

# 反編譯
jadx -d decompiled/ target.apk
```

### 5.2 APK 安全審計 SOP

```bash
cd decompiled/sources/

# 1. 硬編碼帳密
grep -rn "password\|api_key\|secret\|token\|AES\|DES\|encrypt" --include="*.java" | \
  grep -v "test\|example\|README"

# 2. SSL/TLS 驗證
grep -rn "TrustManager\|ALLOW_ALL\|checkServerTrusted\|HostnameVerifier" --include="*.java"

# 3. 本地儲存
grep -rn "SharedPreferences\|SQLiteDatabase\|getWritableDatabase" --include="*.java"

# 4. API 端點
grep -rn "http://\|https://" --include="*.java" | grep -v "schemas\|github\|apache\|google"

# 5. Certificate Pinning
grep -rn "CertificatePinner\|ssl_pinning\|pinning" --include="*.java"
```

## 六、報告撰寫

### 6.1 HITCON ZeroDay 表單格式

```markdown
## 標題
{組織名稱} 漏洞名稱

## 組織
組織正式名稱

## 介紹
一句話摘要

## 類型
（下拉選單值）

## 風險
嚴重 / 高 / 中 / 低

## 相關網址
受影響 URL（一行一個）

## 敘述
### 漏洞概述
### 重現步驟（含 curl/URL PoC）
### 影響

## 修補建議
```

### 6.2 TWCERT CVE Email 格式

```
收件人: cve@cert.org.tw
標題: [漏洞通報] 廠商 產品 漏洞類型

內容:
- 廠商名稱
- 產品名稱
- 韌體版本
- 漏洞類型 (CWE)
- CVSS 評分
- 技術描述
- PoC
- 修補建議
```

## 七、提交前檢查清單

- [ ] 搜尋 HITCON ZeroDay 和 CVE 資料庫確認無重複
- [ ] 每個漏洞至少有 B 等級驗證
- [ ] 使用條件式描述，不主張未驗證的攻擊鏈
- [ ] 不包含真實個資（馬賽克或移除）
- [ ] 不在報告中放入實際可用的帳密（用 *** 遮蔽部分）
- [ ] 確認漏洞仍然存在（re-verify）
- [ ] 截圖證據已準備

## 八、工具安裝清單

```bash
# bbflow 一鍵安裝全部（推薦）
git clone https://github.com/guan4tou2/bbflow.git && cd bbflow
./install.sh --all

# 手動補裝個別工具（Linux/apt）
sudo apt install -y golang pipx python3-pip git curl

# ProjectDiscovery（Go）
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
export PATH="$HOME/go/bin:$PATH"

# Python
pip3 install arjun uro git-dumper waymore --break-system-packages
pipx install bbot && pipx ensurepath

# Git 洩漏工具（bbflow hunt-git-exposure 已內建 pipeline）
pip3 install git-dumper

# 韌體分析（非 bbflow 核心）
brew install binwalk jadx hashcat   # macOS
sudo apt install binwalk            # Linux

# bbflow symlink（install.sh 已處理）
ln -sf "$(pwd)/bbflow.sh" ~/.local/bin/bbflow
```

## 七、SPA Source Map 獵殺（Web Bug Bounty 專用）

### 7.1 方法論

SPA（React/Angular/Vue）在 build 時會產生 `.js.map` source map 檔案，包含完整原始碼。

> ⚠️ **2026-04-01 教訓**：Source map 暴露本身在大廠（Cisco Meraki、Anker multi-brand SSO）被視為 **Not Applicable**。Triager 回覆：「None of the tokens disclosed here are sensitive, and there is nothing inherently sensitive about the js map being public.」**不要單獨報 source map — 必須從中找到可利用的漏洞，報漏洞本身。**

若部署時未移除，可從中提取情報並尋找可利用的漏洞：
- Hardcoded secrets（真正的 secret，不是 public client ID）
- 認證流程邏輯缺陷（如 ECDH key bypass、OAuth CSRF）
- 可利用的 API 端點（直接測試，不只列舉）
- 前端 XSS vectors（v-html、dangerouslySetInnerHTML）
- 硬編碼金鑰（Sentry DSN、Firebase、AWS）

### 7.2 Step 1：找 JS bundle 檔名

```bash
curl -s "https://target.com/" | grep -oE 'src="[^"]*\.js[^"]*"'
# 看到類似：src="/static/js/main.679e946a.js"
# content-hash 格式 = webpack/Angular CLI 產出
```

### 7.3 Step 2：測試 .map 檔案

```bash
# 方法 A：直接加 .map
curl -sI "https://target.com/static/js/main.679e946a.js.map"

# 方法 B：檢查 JS 檔尾端的 sourceMappingURL
tail -c 200 main.679e946a.js | grep sourceMappingURL
```

### 7.4 Step 3：判斷結果（關鍵！）

| HTTP Code | Content-Type | 判定 |
|-----------|-------------|------|
| 200 | `application/json` 或 `application/octet-stream` | ✅ **真的 source map** |
| 200 | `text/html` | ❌ **SPA catch-all（假的）** — 回傳的是 index.html |
| 200 | `binary/octet-stream` + 檔案 > 100KB | ✅ 可能是真的，下載驗證 |
| 404 | — | ❌ 未暴露 |
| 403 | — | ❌ 被阻擋 |

**⚠️ 重要：HTTP 200 不代表是真的！必須檢查 Content-Type。**
SPA 框架的 catch-all 路由會對所有未知路徑回 200 + index.html。

### 7.5 Step 4：下載並分析

```bash
curl -s "https://target.com/main.679e946a.js.map" -o map.json

# 驗證是否為有效 source map
python3 -c "
import json
d = json.load(open('map.json'))
print(f'Sources: {len(d[\"sources\"])}')
print(f'Has sourcesContent: {bool(d.get(\"sourcesContent\"))}')
# 列出應用程式原始碼（排除 node_modules）
app = [s for s in d['sources'] if 'node_modules' not in s]
print(f'App sources: {len(app)}')
for s in app[:20]: print(f'  {s}')
"
```

### 7.6 Step 5：秘密掃描

```python
import json, re

d = json.load(open('map.json'))
text = '\n'.join(x or '' for x in d.get('sourcesContent', []) if x)

patterns = [
    (r'AIza[A-Za-z0-9_-]{35}', 'Google API Key'),
    (r'AKIA[A-Z0-9]{16}', 'AWS Access Key'),
    (r'[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io', 'Sentry DSN'),
    (r'client[_-]?secret["\s:=]+["\']([^"\']{8,})', 'Client Secret'),
    (r'sk_live_[A-Za-z0-9]{20,}', 'Stripe Secret Key'),
]

for pat, name in patterns:
    matches = re.findall(pat, text)
    if matches:
        print(f'{name}: {matches[0][:50]}...')
```

### 7.7 也檢查 config 端點

```bash
# 某些 SPA 在 runtime 載入 config
curl -s "https://target.com/config.json"     # auth.netgear.com ✅
curl -s "https://target.com/env.json"
curl -s "https://target.com/environment.json"
curl -s "https://target.com/assets/config.json"
```

### 7.8 戰績紀錄

| Target | .map | Sources | 秘密 | 報告 |
|--------|------|---------|------|------|
| portal.meraki.com | ✅ 3.9MB | 1407 (191 app) | Google OAuth ID, NR keys | P3 Bugcrowd |
| armor.netgear.com | ✅ 9.96MB | 520 | Sentry DSN, OAuth IDs, staging URLs | P2 Bugcrowd |
| central.bitdefender.com | ❌ SPA catch-all | — | — | — |
| developer.sophos.com | ❌ 404 | — | — | — |
| insight.netgear.com | ❌ stub (103B) | 0 | — | — |
| auth.netgear.com | ❌ SPA catch-all | — | config.json 暴露 (DD/Optimizely) | — |
