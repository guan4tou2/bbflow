# bb-recon Nuclei Templates — 直接可利用漏洞

自訂 nuclei template，只收**直接可利用**的漏洞類型（不含需要前提條件的 info disclosure）。

## Templates

| 檔案 | 偵測目標 | 嚴重度 | 直接影響 |
|------|---------|--------|---------|
| `exposed-env-secrets.yaml` | .env / config 檔案含明文密碼 | high | 直接取得 DB/API 憑證 |
| `git-exposure.yaml` | .git 目錄暴露 | high | 還原原始碼 + commit 歷史中的密碼 |
| `devops-unauth.yaml` | Jenkins/ArgoCD/Grafana/Harbor 未認證 | high | 直接存取 CI/CD + 可能 RCE |
| `default-credentials.yaml` | Jenkins/Grafana/Harbor 預設帳密 | critical | admin 登入 → RCE / 資料存取 |
| `graphql-introspection.yaml` | GraphQL introspection 開啟 | medium | 取得完整 API schema |
| `open-redirect.yaml` | Open redirect | medium | OAuth code 竊取 / 釣魚 |
| `oauth-redirect-uri.yaml` | OAuth redirect_uri bypass | high | 竊取 authorization code → ATO |
| `jwt-vulnerabilities.yaml` | JWT none algorithm / 弱 secret | critical | 偽造任意用戶 token → ATO |
| `s3-bucket-exposed.yaml` | S3 bucket listable / writable | high | 直接讀取 / 寫入雲端儲存 |
| `subdomain-takeover.yaml` | CNAME 指向未認領服務 | high | 控制子域名 → cookie 竊取 |
| `actuator-exposure.yaml` | Spring Boot /actuator/env | medium | 讀取環境變數中的 secrets |
| `hybris-occ.yaml` | SAP Hybris OCC API + 匿名 token | medium | 取得 OAuth token，測試 IDOR |
| `private-ip-dns.yaml` | DNS 解析到私有 IP | info | 洩漏內部網路拓撲 |
| `sourcemap-exposure.yaml` | JS source map 暴露 | info | 原始碼審計 → 找更多漏洞 |
| `firebase-rtdb-exposed.yaml` | Firebase RTDB open read/write | high/critical | 直接 dump PII 或覆寫資料 |
| `kubernetes-unauth.yaml` | K8s API server + Dashboard 未認證 | critical | 列舉 namespace/secret → 可能容器逃逸 |
| `elasticsearch-exposed.yaml` | Elasticsearch/OpenSearch 未認證 | high | 完整資料庫 dump |
| `terraform-state-exposed.yaml` | terraform.tfstate 暴露 | high | 取得 AWS/GCP/Azure 明文憑證 |
| `docker-registry-exposed.yaml` | Docker registry 未認證 | high | 拉取 image → 提取內嵌 secrets |
| `backup-files-exposed.yaml` | .sql/.zip/.tar.gz 備份檔暴露 | high | DB dump 含明文密碼 + 完整 PII |
| `php-debug-exposed.yaml` | phpinfo / Laravel / Django / Symfony debug | medium/high | 洩漏 env var secrets + 完整 config |
| `ssrf-url-param.yaml` | URL param SSRF（in-band + OOB + POST body） | high | 雲端 metadata 存取 → IMDS 憑證竊取 |

## 使用方式

```bash
TOOLS=/Users/guantou/Desktop/BugBounty/tools
TEMPLATES=$TOOLS/nuclei-templates/bb-recon

# 單一目標（手動確認用）
$TOOLS/nuclei -u https://target.com -t $TEMPLATES -silent -severity medium,high,critical

# 多目標批次掃描
$TOOLS/nuclei -l live_hosts.txt -t $TEMPLATES -severity medium,high,critical \
  -rate-limit 5 -timeout 10 -silent -o results.txt

# 只跑直接高風險的
$TOOLS/nuclei -l live_hosts.txt \
  -t $TEMPLATES/default-credentials.yaml \
  -t $TEMPLATES/jwt-vulnerabilities.yaml \
  -t $TEMPLATES/s3-bucket-exposed.yaml \
  -t $TEMPLATES/git-exposure.yaml \
  -t $TEMPLATES/terraform-state-exposed.yaml \
  -t $TEMPLATES/firebase-rtdb-exposed.yaml \
  -rate-limit 3 -silent

# SSRF（需要 interactsh server）
$TOOLS/nuclei -l live_hosts.txt \
  -t $TEMPLATES/ssrf-url-param.yaml \
  -iserver https://interact.sh \
  -rate-limit 3 -silent

# 只跑 DNS 類（subdomain takeover + private IP）
$TOOLS/nuclei -l subdomains.txt \
  -t $TEMPLATES/subdomain-takeover.yaml \
  -t $TEMPLATES/private-ip-dns.yaml \
  -silent

# bbflow 整合：全跑
bbflow hunt <target>
# 只跑 nuclei-secrets（官方 tokens+configs）
bbflow hunt <target> --only nuclei-secrets
```

## ⚠️ 注意

- 大多數 Bugcrowd / HackerOne 程式**禁止自動掃描工具**
- 這些 template 用來加速 recon，**發現後必須手動驗證再送件**
- nuclei 結果本身不能直接作為 PoC — 需要補充截圖/curl 驗證步驟
- rate-limit 保持低數值，避免觸發 WAF 或違反 scope
- SSRF OOB template 需要 nuclei 配置 interactsh，或手動替換 `{{interactsh-url}}` 為自己的 callback server
