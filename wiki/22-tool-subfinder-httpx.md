---
type: wiki
category: tool
tool: subfinder,httpx,amass
status: active
last-updated: 2026-04-21
---

# Tool: subfinder + httpx + amass（子域名列舉 + 存活探測）

> **用途：** 任何 BB 的第一步 — 找到所有子域名 + 確認哪些還活著 + 抓 tech stack。

## 安裝

```bash
# subfinder（被動 OSINT）
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# httpx（HTTP probe）
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# amass（更深入，含主動 bruteforce）
brew install amass
# 或
go install github.com/owasp-amass/amass/v4/...@master
```

## subfinder — 被動子域名

```bash
# 最簡單
subfinder -d target.com -silent

# 吃 list
subfinder -dL domains.txt -silent -o subs.txt

# 遞迴（子域名的子域名）
subfinder -d target.com -recursive -silent

# 所有 source
subfinder -d target.com -all -silent

# 只用指定 source（有 API key 的）
subfinder -d target.com -sources censys,shodan,virustotal -silent
```

### API key 設定

```bash
# 把 API keys 加進 ~/.config/subfinder/provider-config.yaml
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml <<EOF
censys:
  - abc123:xyz789
shodan:
  - your_api_key
virustotal:
  - your_api_key
securitytrails:
  - your_api_key
github:
  - your_pat_token
chaos:
  - your_chaos_key
EOF
```

**免費 API 推薦：**
- **Chaos**（projectdiscovery）：https://chaos.projectdiscovery.io
- **Censys**（研究版）：https://search.censys.io
- **Shodan**（教育版）：$5/lifetime
- **SecurityTrails**：50 queries/month 免費
- **VirusTotal**：免費

## httpx — 存活探測 + tech fingerprint

```bash
# 基本存活檢查
subfinder -d target.com -silent | httpx -silent

# 帶 status code + title + tech
subfinder -d target.com -silent | \
  httpx -silent -status-code -title -tech-detect -web-server

# 輸出格式：
# https://api.target.com [200] [OK] [Cloudflare] [Nginx] [React]

# 從 list 讀
httpx -l subs.txt -silent -status-code -title -tech-detect > alive.txt

# 只保留特定 status
httpx -l subs.txt -silent -mc 200,301,302,401,403

# 排除某 status
httpx -l subs.txt -silent -fc 404

# 帶 screenshot（需要 headless Chrome）
httpx -l subs.txt -silent -screenshot -srd screenshots/

# 輸出 JSON
httpx -l subs.txt -silent -json > alive.jsonl
```

### 必學 flag

| Flag | 用途 |
|------|------|
| `-status-code` `-sc` | 回 HTTP code |
| `-title` | 抓 HTML title |
| `-tech-detect` `-td` | Wappalyzer fingerprint |
| `-web-server` `-server` | Server header |
| `-content-length` `-cl` | Content-Length |
| `-location` | Redirect location |
| `-response-time` `-rt` | 回應時間 |
| `-mc 200,301` | Match code |
| `-fc 404,403` | Filter code |
| `-ml 500` | Match content length min |
| `-ms "keyword"` | Match string in response |
| `-fs "keyword"` | Filter string |
| `-o file.txt` | 輸出 |
| `-json` | JSON output |
| `-screenshot` | 抓畫面 |
| `-follow-redirects` `-fr` | 跟著 redirect |
| `-threads 50` `-t 50` | 平行度 |
| `-rl 150` | Rate limit |
| `-timeout 10` | Per-request timeout |
| `-H "Header: value"` | 加 header |
| `-ports 80,443,8080,8443,8888` | 掃多 port |

## amass — 主動 + 被動（更深）

```bash
# 被動模式（類似 subfinder）
amass enum -passive -d target.com -silent > subs.txt

# 主動模式（會跑 DNS bruteforce）
amass enum -active -d target.com -silent

# 極深模式（結合被動 + DNS + cert）
amass enum -active -brute -d target.com -silent

# 用自訂字典 bruteforce
amass enum -active -brute -w /path/wordlist.txt -d target.com

# 連續掃描（會紀錄歷史變化）
amass intel -addr 1.2.3.0/24
```

## 標準工作流程（bbflow recon 做的事）

```bash
# 1. 被動收集
(
  subfinder -d target.com -silent
  amass enum -passive -d target.com -silent
  curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | tr -d '"' | sort -u
  curl -s "https://chaos.projectdiscovery.io/api/v1/dns/target.com/subdomains" \
    -H "Authorization: $CHAOS_KEY" | jq -r '.subdomains[]' | sed "s/$/.target.com/"
) | sort -u > subs.txt

# 2. 存活探測
httpx -l subs.txt -silent -sc -title -td -server -o alive.txt

# 3. 分類
# 根據 Title / Tech stack 分 prod / staging / dev / test
grep -iE "staging|stg|dev|test|uat|beta|demo" alive.txt > non_prod.txt
grep -viE "staging|stg|dev|test|uat|beta|demo" alive.txt > prod.txt
```

## 進階技巧

### 1. 找特定廠商的子域名

```bash
# 所有 SSL cert 包含 target 的
curl -s "https://crt.sh/?q=target.com&output=json" | \
  jq -r '.[].common_name' | sort -u

# 用 Shodan 找憑證
shodan search 'ssl.cert.subject.cn:"target.com"'
```

### 2. 找 origin IP（繞 CDN）

```bash
# 查子域名的 A 記錄 → 沒指向 CDN 的就是 origin
for sub in $(cat subs.txt); do
  ip=$(dig +short "$sub" | head -1)
  if [[ ! "$ip" =~ ^(104\.|172\.|173\.|198\.)  ]]; then
    echo "$sub → $ip (candidate origin)"
  fi
done
```

### 3. Port 掃描（非標 port）

```bash
# 用 httpx 掃多 port
httpx -l subs.txt -ports 80,443,8080,8443,8888,7001,9000,9090 -silent -sc

# 更激進用 rustscan
rustscan -a target.com --ulimit 5000 -- -sV
```

### 4. 判斷 WAF

```bash
httpx -l alive.txt -silent -td -server -H "X-Forwarded-For: 127.0.0.1" | \
  grep -iE "cloudflare|akamai|imperva|sucuri|safeline"
```

## bbflow 整合

```bash
# bbflow recon 就是在跑 subfinder + amass + crt.sh + httpx
bbflow recon target

# 輸出：research/target/recon/
# - subs.txt
# - alive.txt（含 tech stack）
# - non_prod.txt
```

## 注意事項

### Chaos 需要免費註冊 API key

```bash
# https://chaos.projectdiscovery.io
export CHAOS_KEY="your_key"
```

bbflow 會自動用它。

### amass -brute 會發很多 DNS 查詢

- 小標的 OK
- 大標的建議用 `-w` 自訂短字典

### httpx 預設不跟 redirect

- 加 `-fr` 才會 follow
- 但 follow 會多倍的請求量

## 關聯文件

- [01-waf-bypass-playbook.md](01-waf-bypass-playbook.md) §策略 3：找 non-prod
- [14-waf-bypass-commands.md](14-waf-bypass-commands.md)
- [00-bbflow-complete-flow.md](00-bbflow-complete-flow.md) §recon
