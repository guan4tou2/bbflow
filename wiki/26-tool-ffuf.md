---
type: wiki
category: tool
tool: ffuf
status: active
last-updated: 2026-04-21
source: https://github.com/ffuf/ffuf
---

# Tool: ffuf（Web fuzzer）

> **用途：** 快速 fuzz **路徑 / 參數名 / 參數值 / header / Host / vhost**。
> 比 gobuster 快，比 feroxbuster 更靈活。

## 安裝

```bash
go install github.com/ffuf/ffuf/v2@latest
brew install ffuf
```

## 基本用法

```bash
# 目錄 fuzz
ffuf -u https://target.com/FUZZ -w wordlist.txt

# 顯示只有 200 / 301 的結果
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,403

# 參數 fuzz
ffuf -u 'https://target.com/?FUZZ=test' -w params.txt

# 參數 value fuzz
ffuf -u 'https://target.com/?id=FUZZ' -w nums.txt
```

## 必學 flag

| Flag | 用途 |
|------|------|
| `-u URL` | 含 `FUZZ` 的 URL |
| `-w file` | Wordlist |
| `-w file:KEY` | 多 wordlist 用不同 key |
| `-mc 200,301` | Match code |
| `-fc 404` | Filter code |
| `-ml 100` | Match line count（最小） |
| `-ms 1000` | Match size |
| `-fs 1234` | Filter size |
| `-mr 'regex'` | Match regex |
| `-fr 'regex'` | Filter regex |
| `-ac` | Auto-calibrate（自動 filter SPA 假 200） |
| `-acc 'custom1,custom2'` | Auto-calibrate 自訂 |
| `-t 40` | Threads |
| `-p 2` | Delay（秒） |
| `-rate 100` | Rate limit (req/s) |
| `-e .php,.bak` | Extension fuzz |
| `-H 'Cookie: xxx'` | 加 header |
| `-d 'a=FUZZ'` | POST data |
| `-X POST` | HTTP method |
| `-o out.json -of json` | JSON output |
| `-of html` | HTML output |
| `-replay-proxy http://127.0.0.1:8080` | 發現後送 Burp |
| `-mode clusterbomb` | 多 wordlist cartesian（慢） |
| `-mode pitchfork` | 多 wordlist 一一對應 |

## 推薦組合

### 目錄 fuzz（經典）

```bash
# SecLists 經典字典
WORDLIST=/usr/share/seclists/Discovery/Web-Content/common.txt

ffuf -u https://target.com/FUZZ \
  -w $WORDLIST \
  -mc 200,301,302,401,403 \
  -fs 0 \
  -ac \
  -t 50 \
  -o ffuf.json -of json
```

### 副檔名 fuzz

```bash
# 同時試多種 extension
ffuf -u https://target.com/FUZZ \
  -w words.txt \
  -e .php,.bak,.old,.zip,.json,.xml,.txt,.log \
  -mc 200,301 \
  -ac
```

### 子目錄 + 副檔名（政府案常用）

```bash
# 建字典：admin, backup, config, test, ...
cat > gov-paths.txt <<EOF
admin
administrator
backup
config
test
debug
internal
api
phpinfo
info
swagger
actuator
EOF

ffuf -u https://target.gov.tw/FUZZ \
  -w gov-paths.txt \
  -e .php,.aspx,.jsp,.html \
  -mc 200,301,401,403 \
  -ac \
  -t 10 \
  -p 1
```

### 參數名 fuzz（類似 arjun）

```bash
ffuf -u 'https://target.com/api?FUZZ=test' \
  -w params.txt \
  -fr 'Not Found' \
  -mc 200 \
  -mr 'test'
```

### vhost fuzz（找隱藏 subdomain）

```bash
ffuf -u https://target.com/ \
  -H "Host: FUZZ.target.com" \
  -w subs.txt \
  -fs 1234 \
  -mc 200,301
```

### 多 wordlist（clusterbomb）

```bash
# 同時 fuzz directory + file
ffuf -u https://target.com/W1/W2 \
  -w dirs.txt:W1 \
  -w files.txt:W2 \
  -mc 200 \
  -ac \
  -mode clusterbomb
```

### POST fuzz（login brute force）

```bash
ffuf -u https://target.com/login \
  -X POST \
  -d 'user=admin&pass=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -w passwords.txt \
  -fr 'Invalid credentials' \
  -mc 200,302
```

## 字典推薦

| 用途 | Wordlist |
|------|---------|
| 通用目錄 | `SecLists/Discovery/Web-Content/common.txt` |
| 大型字典 | `SecLists/Discovery/Web-Content/raft-medium-directories.txt` |
| 隱藏檔案 | `SecLists/Discovery/Web-Content/raft-medium-files.txt` |
| API endpoint | `SecLists/Discovery/Web-Content/api/api-endpoints.txt` |
| 參數名 | `SecLists/Discovery/Web-Content/burp-parameter-names.txt` |
| 政府站（自製） | `tools/payloads/gov-paths.txt`（見 wiki [02](02-gov-site-quick-wins.md)） |
| Backup 檔名 | `SecLists/Discovery/Web-Content/BackupFuzzy.fuzz.txt` |

### 快速安裝 SecLists

```bash
# macOS
brew install seclists

# Linux
sudo apt install seclists
# 或
git clone https://github.com/danielmiessler/SecLists ~/SecLists
```

## 後處理

### JSON 結果過濾

```bash
# 只看 200
jq -r '.results[] | select(.status == 200) | .url' ffuf.json

# 找新發現的 interesting endpoint
jq -r '.results[] | select(.status == 200 and .length > 500) | "\(.status) \(.length) \(.url)"' ffuf.json
```

### 發現後再探測

```bash
# ffuf 發現的 endpoint 餵進 nuclei
jq -r '.results[].url' ffuf.json | nuclei -l - -silent
```

## WAF 友善

```bash
# 降低平行 + 加 delay
ffuf -u https://target/FUZZ -w words.txt \
  -t 3 \
  -p 2 \
  -rate 10 \
  -H "X-Forwarded-For: 127.0.0.1" \
  -timeout 15
```

## bbflow 整合

bbflow 有 `hunt-ffuf-dirs` hunter：

```bash
bbflow hunt target --only ffuf-dirs
```

自訂字典：

```bash
WORDLIST=/path/to/custom.txt bbflow hunt target --only ffuf-dirs
```

## 替代工具

| 工具 | 優點 | 用時機 |
|------|------|--------|
| **ffuf** | 最靈活（fuzz 任何位置） | 通用 |
| feroxbuster | 遞迴好（自動深入） | 目錄發現 |
| gobuster | 簡單 | 快速目錄 |
| wfuzz | 經典 | 舊工作流程 |
| dirsearch | Python，輸出美觀 | 寫報告 |

## 關聯文件

- [02-gov-site-quick-wins.md](02-gov-site-quick-wins.md) §政府案 payload 字典
- [10-hunter-config-leak.md](10-hunter-config-leak.md) — 更低噪音的替代方案
