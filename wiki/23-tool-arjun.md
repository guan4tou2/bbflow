---
type: wiki
category: tool
tool: arjun
status: active
last-updated: 2026-04-21
source: https://github.com/s0md3v/Arjun
---

# Tool: arjun（隱藏參數發現）

> **用途：** 對已知 endpoint **挖掘隱藏的 HTTP parameters**（像 `?admin=true`、`?debug=1`、`?user_id=`）。
> 很多漏洞藏在沒 document 的 param，arjun 就是拿來挖這些。

## 安裝

```bash
# pip
pip3 install arjun

# 或從 GitHub
git clone https://github.com/s0md3v/Arjun
cd Arjun && pip3 install -r requirements.txt
```

## 基本用法

```bash
# 單一 endpoint
arjun -u https://target.com/api/user

# URL list
arjun -i urls.txt

# 輸出
arjun -u https://target.com/api/user -oT arjun.txt      # text
arjun -u https://target.com/api/user -oJ arjun.json     # json
```

## 必學 flag

| Flag | 用途 |
|------|------|
| `-u URL` | 單一目標 |
| `-i file.txt` | URL list |
| `-m GET` | HTTP method（`GET`/`POST`/`JSON`/`XML`） |
| `-w wordlist.txt` | 自訂參數字典 |
| `-t 10` | 平行度 |
| `-d 3` | Delay（秒） |
| `-T 10` | Timeout |
| `-c 5` | Chunk size（一次測 5 個 param） |
| `--headers 'Cookie: sess=xxx'` | 加 header |
| `--passive` | 被動模式（從 JS/HTML 抽 param） |
| `--include` | 只保留 status code |
| `--exclude` | 排除 status code |
| `--stable` | 用 stable diff（比較乾淨） |
| `-oT file` | Text output |
| `-oJ file` | JSON output |

## 推薦組合

### 單一 endpoint 深挖

```bash
arjun -u "https://target.com/api/user" \
  -m GET \
  -t 25 \
  --stable \
  -oT arjun.txt
```

### 被動模式（不送 request，從 response 抽）

```bash
arjun -u "https://target.com/" --passive -oT arjun_passive.txt
```

### 對 bbflow 產生的 endpoints list 跑

```bash
# 先用 katana + gau 產生 endpoints.txt
bbflow hunt target --only crawl-chain

# 對每個 endpoint 挖 param（只看 200/301/302）
arjun -i crawl_chain_out/target/06_merged.txt \
  --include-status 200,301,302,403 \
  -t 25 \
  -oT arjun.txt
```

### POST JSON body 的 endpoint

```bash
arjun -u "https://target.com/api/login" \
  -m JSON \
  -t 10 \
  -oT arjun_json.txt
```

## 字典推薦

arjun 內建字典 ~25K 參數，已很全。補充：

```bash
# PortSwigger paramalist
wget https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/params.txt
arjun -u target -w params.txt

# SecLists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt
```

## 常見發現

### Debug / admin 參數

```
arjun 發現：?debug=1, ?admin=true, ?test=1
→ 試著帶這個 param 看 response 差異
curl "https://target.com/page?debug=1" → 可能洩漏 stack trace
```

### Feature flag

```
?beta=1, ?preview=true, ?experimental=1
→ 可能開啟未公開功能
```

### Auth bypass

```
?auth=1, ?authenticated=true, ?user_id=1
→ 可能繞過 auth check
```

### IDOR

```
?user_id=, ?userId=, ?uid=, ?account_id=
→ 換成別人的 ID 看是否能看到別人資料
```

### SSRF / Redirect

```
?url=, ?redirect=, ?target=, ?callback=, ?next=
→ 送 http://oast.me 看是否發請求
```

### File / LFI

```
?file=, ?path=, ?name=, ?doc=, ?page=
→ 試 ../../../etc/passwd
```

## 後處理

### 只保留 reflected params（可能 XSS）

```bash
# arjun 找到 ?q 後，檢查是否反射
found_params=$(arjun -u target --passive -oJ /dev/stdout 2>/dev/null | jq -r '.[0].parameters[]' 2>/dev/null)
for p in $found_params; do
  if curl -s "https://target/page?${p}=ARJUN_TEST_$(date +%s)" | grep -q "ARJUN_TEST"; then
    echo "[REFLECTED] $p"
  fi
done
```

### 對發現的 param 跑 dalfox / nuclei DAST

```bash
# 把 arjun 發現的 param 做成 URL 餵進 dalfox
while read -r endpoint params; do
  url="$endpoint?${params// /=test&}=test"
  echo "$url"
done < arjun.txt | dalfox pipe --silence
```

## bbflow 整合

### 透過 `hunt-arjun-params` hunter

```bash
bbflow hunt target --only arjun-params
```

### 透過 `hunt-crawl-chain` 的 Stage 8

```bash
bbflow hunt target --only crawl-chain
# 會自動跑 arjun 對 merged endpoints
```

## 效能注意

### arjun 會發大量 request

- 每個 endpoint 默認 25K params / chunks of 300 → 約 83 個 request
- 100 個 endpoint → 8300 request
- 對 WAF 目標建議：
  - `-d 2`（2 秒 delay）
  - `-t 5`（降平行度）
  - `--include-status 200`（減少無意義 request）

### 政府站建議

```bash
arjun -i endpoints.txt \
  -d 3 \
  -t 3 \
  -T 15 \
  --include-status 200,301,302 \
  -oT arjun.txt
```

## 配合工具

```
arjun → 找到 ?redirect=
     → hunt-open-redirect 驗證
     
arjun → 找到 ?file=
     → hunt-nuclei-deep CATEGORY=lfi
     
arjun → 找到 ?user_id=
     → 手動 IDOR 測試
```

## 關聯文件

- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) §Stage 8
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md) §DAST
- [25-tool-dalfox.md](25-tool-dalfox.md)
