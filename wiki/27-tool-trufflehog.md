---
type: wiki
category: tool
tool: trufflehog
status: active
last-updated: 2026-04-21
source: https://github.com/trufflesecurity/trufflehog
---

# Tool: trufflehog（Secret scanner）

> **用途：** 掃 git 歷史 / 檔案系統 / S3 / Docker image，找**高信心 secret**（API key、token、credentials）。
> 核心優點：**驗證 secret 是否 active**（會真的用 AWS / GitHub / Slack API 試用 key）。

## 安裝

```bash
# Homebrew
brew install trufflehog

# Docker
docker run -it trufflesecurity/trufflehog github --repo https://github.com/repo

# 原生
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

## 基本用法

```bash
# Git repo（本地）
trufflehog git file:///path/to/repo --only-verified

# GitHub repo
trufflehog github --repo https://github.com/org/repo --only-verified

# 從 .git 洩漏還原後掃
git-dumper https://target/.git/ ./dump
trufflehog git file://./dump --only-verified

# 檔案系統
trufflehog filesystem --directory ./source_code --only-verified

# S3 bucket
trufflehog s3 --bucket=my-bucket --only-verified

# Docker image
trufflehog docker --image=nginx:latest --only-verified
```

## 必學 flag

| Flag | 用途 |
|------|------|
| `--only-verified` | **關鍵** — 只報 active secret（trufflehog 會測試） |
| `--json` | JSON 輸出 |
| `--no-update` | 不自動更新 |
| `--concurrency 10` | 平行度 |
| `--include-detectors 'aws,gcp,slack'` | 只掃特定 detector |
| `--exclude-detectors 'generic'` | 排除 detector |
| `--since-commit abc123` | 只掃某 commit 之後 |
| `--branch main` | 只掃某 branch |
| `--config trufflehog.yaml` | 自訂規則 |
| `--no-verification` | 不驗證（超快，高 false positive） |

## 推薦組合

### 掃 .git 洩漏還原物

```bash
# 1. 還原 .git
git-dumper https://target.gov.tw/.git/ ./dump

# 2. 掃整個 git 歷史
trufflehog git file://./dump \
  --only-verified \
  --json \
  --concurrency 10 > secrets.json

# 3. 讀 human-readable
trufflehog git file://./dump --only-verified
```

### 掃 GitHub 組織

```bash
export GITHUB_TOKEN="ghp_xxx"

# 整個 org 所有 repo
trufflehog github --org=targetorg --only-verified

# 單一 repo + 含所有 branch
trufflehog github --repo=https://github.com/org/repo --branch=all --only-verified

# 掃某個 user 的 repos
trufflehog github --user=targetuser --only-verified
```

### 掃 backup.zip 解壓後

```bash
# 1. 下載 + 解壓（見 wiki 12）
curl -O https://target.gov.tw/backup.zip
unzip backup.zip -d ./backup

# 2. 掃整個目錄
trufflehog filesystem --directory=./backup --only-verified
```

### 掃 Docker image（Jenkins/Harbor）

```bash
# 掃 Harbor 公開 image
trufflehog docker --image=public.harbor.example.com/ops/prod-backup:latest --only-verified

# 掃 docker hub
trufflehog docker --image=username/private-image:tag --only-verified
```

### 掃 S3 bucket（誤開權限）

```bash
# 匿名 mode
trufflehog s3 --bucket=my-public-bucket --only-verified

# 帶 AWS creds
AWS_ACCESS_KEY_ID=xxx AWS_SECRET_ACCESS_KEY=yyy \
  trufflehog s3 --bucket=my-bucket --only-verified
```

## 輸出範例

```
✅ Found verified result

Detector Type: AWS
Decoder Type: PLAIN
Raw Result: AKIAIOSFODNN7EXAMPLE
Raw Verification: https://sts.amazonaws.com (200 OK)
File: /dump/config/aws_prod.yml
Line: 42
Commit: abc123def
Verified: true
Account: 123456789012
```

`Verified: true` → 這個 key **真的還能用**。

## Detector 支援（部分）

trufflehog 內建 700+ detector，分為：

- Cloud：AWS / GCP / Azure / Alibaba / DigitalOcean / Cloudflare
- VCS：GitHub / GitLab / Bitbucket / Gitea
- DB：MongoDB / MySQL / PostgreSQL / Redis 連線字串
- Messaging：Slack / Discord / Teams / Telegram
- API：Stripe / Twilio / SendGrid / Mailgun / Paypal
- Crypto：Private keys / JWT secrets

## 攻擊鏈範例

### Chain A：.git → trufflehog → AWS takeover

```bash
# 1. config-leak 找到 .git
# 2. 還原
git-dumper https://target.gov.tw/.git/ ./dump

# 3. 掃歷史
trufflehog git file://./dump --only-verified --json > secrets.json

# 4. 找 AWS key
jq 'select(.DetectorName == "AWS")' secrets.json

# 5. 若 Verified=true → aws sts get-caller-identity 確認權限
export AWS_ACCESS_KEY_ID=$(jq -r '.Raw' secrets.json | head -1)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.RawV2' secrets.json | head -1)
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name $(aws sts get-caller-identity --query 'Arn' --output text | cut -d/ -f2)
```

### Chain B：Docker image → trufflehog → hard-coded creds

```bash
# 1. 從 Harbor / ACR 抓 image
docker pull targetharbor.example.com/prod/api:latest

# 2. 掃
trufflehog docker --image=targetharbor.example.com/prod/api:latest --only-verified
```

### Chain C：backup.zip → trufflehog

```bash
# 1. backup-files hunter 找到 backup.zip
# 2. 下載解壓
curl -O https://target/backup.zip && unzip backup.zip -d ./backup

# 3. 掃
trufflehog filesystem --directory=./backup --only-verified
```

## 自訂 Detector

`trufflehog.yaml`：

```yaml
detectors:
  - name: CompanyInternalAPIKey
    keywords:
      - "COMP_API_"
    regex:
      key: "COMP_API_[A-Z0-9]{32}"
    verify:
      - endpoint: "https://internal.company.com/api/v1/verify"
        unsafe: false
        headers:
          - 'Authorization: Bearer {raw}'
        successRanges:
          - 200-299
```

## 降噪技巧

### 1. 只看 Verified

```bash
# trufflehog 預設會報 unverified，加 --only-verified 只看真的 active
trufflehog git file://./dump --only-verified
```

### 2. 排除 generic detector

```bash
# generic detector 誤報最多
trufflehog git file://./dump --exclude-detectors=generic --only-verified
```

### 3. 限制 detector

```bash
# 只掃高信心類別
trufflehog git file://./dump \
  --include-detectors='aws,gcp,azure,github,slack,stripe,twilio' \
  --only-verified
```

## bbflow 整合

```bash
# hunt-trufflehog-secrets hunter
bbflow hunt target --only trufflehog
```

## 報告建議

- **Verified: true** → P1 (active secret)
- **Verified: false** → P3-P4（可能是已 rotate 的 key，但還是洩漏）
- 附上 commit hash + 檔案路徑 + 哪個 detector hit
- **絕對不要**在報告裡附完整 secret，只附前 4 + 後 4 字元

範例：
```markdown
AWS Access Key: AKIA****EXAMPLE
AWS Account: 123456789012 (verified via STS)
Found in: .git commit abc123 → config/aws_prod.yml:42
IAM Permissions: read-only s3 + write logs
```

## 關聯文件

- [28-tool-git-dumper.md](28-tool-git-dumper.md)
- [12-hunter-backup-files.md](12-hunter-backup-files.md)
- [10-hunter-config-leak.md](10-hunter-config-leak.md)
