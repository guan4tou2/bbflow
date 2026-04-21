---
type: wiki
category: recon
status: active
last-updated: 2026-04-21
---

# Subdomain Recon 深度擴充

> **用途：** 大型目標（fintech/telecom/cloud）用 subfinder 單打常漏 30-50%。這篇把「被動 → 主動 → 變異 → 第三方 → ASN」全鏈串起來。
> 最終目標：把所有 `*.target.com` 丟進 httpx 前，先把 subdomain 列表做到 95%+ 覆蓋。

## 0. 整體流程

```
[被動 passive] → [主動 active resolve] → [變異 permutation] → [第三方 API] → [ASN/CIDR]
       ↓                   ↓                       ↓                  ↓                 ↓
  subfinder           dnsx/puredns            alterx/dnsgen     securitytrails   asnmap
  amass               shuffledns              gotator           chaos            whoisxml
  github-sub                                                    virustotal        censys
  ctfr                                                          shodan
       ↓
 [merged + dedup] → httpx 存活偵測 → 標記新 vs 已知
```

## 1. 被動（passive）

### subfinder（基本版）

```bash
subfinder -d target.com -all -silent -o sub_subfinder.txt

# -all = 啟用所有 sources（慢但覆蓋廣）
# -silent = 只輸出 subdomain，管線用
# -recursive = 遞迴對找到的 subdomain 繼續找
```

**設定 API keys（重要）**：`~/.config/subfinder/provider-config.yaml`

```yaml
binaryedge:
  - BINARYEDGE_KEY
censys:
  - CENSYS_ID:CENSYS_SECRET
chaos:
  - CHAOS_KEY
github:
  - GITHUB_PAT_1
  - GITHUB_PAT_2
passivetotal:
  - USER:KEY
securitytrails:
  - ST_KEY
shodan:
  - SHODAN_KEY
virustotal:
  - VT_KEY
zoomeye:
  - USER:KEY
```

無 key 覆蓋率約 60%，全 key 配齊可達 85-90%。

### amass（互補）

```bash
amass enum -passive -d target.com -o sub_amass.txt

# 啟用更多 sources
amass enum -passive -d target.com -src -o sub_amass.txt

# 也可以做 intel
amass intel -org "Target Corp" -o intel.txt
amass intel -asn 16509 -o asn_intel.txt
```

Amass 與 subfinder 結果**重疊約 60%**，但各有獨家 source，兩個都跑。

### assetfinder（快速備援）

```bash
assetfinder --subs-only target.com > sub_assetfinder.txt

# 輕量，5 秒內跑完，補漏用
```

### github-subdomains

```bash
# 從 GitHub 公開 repo 找 subdomain
go install github.com/gwen001/github-subdomains@latest

GITHUB_TOKEN=ghp_xxx github-subdomains -d target.com -o sub_github.txt
```

GitHub sources 特別會找到 **staging / dev / internal** 的 hostname（通常在 `.env.example` 或 docker-compose）。

### chaos（ProjectDiscovery 提供）

```bash
# chaos-client = Project Discovery 持續收集的 subdomain DB
# https://chaos.projectdiscovery.io/ 免費申請 key

chaos -d target.com -o sub_chaos.txt

# 下載整個 program 的歷史資料
chaos -dl "target_program" -o chaos_full.zip
```

### ctfr（憑證透明度日誌）

```bash
# https://github.com/UnaPibaGeek/ctfr
python3 ctfr.py -d target.com -o sub_ctfr.txt
```

或直接 curl crt.sh：

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > sub_crt.txt

# 注意 crt.sh 偶爾 timeout，重試
```

### 合併被動結果

```bash
cat sub_*.txt | sort -u > passive_raw.txt
wc -l passive_raw.txt
```

## 2. 主動 resolve（濾出真的 DNS 解析到 IP 的）

被動找到的 subdomain 很多是 wildcard 污染或歷史遺留，要 DNS 驗證。

### dnsx（單次驗證）

```bash
# 基本：A 紀錄驗證
dnsx -l passive_raw.txt -silent -o alive.txt

# 加速：自訂 resolver（避免本地 DNS 被 rate limit）
dnsx -l passive_raw.txt -silent -r resolvers.txt -o alive.txt

# 全記錄 + CNAME 提取（找 takeover 候選）
dnsx -l passive_raw.txt -silent -a -cname -resp -o alive_detail.txt
```

**resolvers.txt**（trusted 列表）：

```
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
```

或用 ProjectDiscovery 的：

```bash
wget https://raw.githubusercontent.com/projectdiscovery/dnsx/main/resolvers.txt
```

### puredns（大量 brute + wildcard 濾除）

puredns 最強的點是 **自動處理 wildcard DNS 回應**。

```bash
# 安裝
go install github.com/d3mondev/puredns/v2@latest

# 從字典暴力猜
puredns bruteforce ~/Tools/SecLists/Discovery/DNS/namelist.txt target.com \
  -r resolvers.txt \
  -w sub_brute.txt

# 驗證 passive 列表（去 wildcard）
puredns resolve passive_raw.txt \
  -r resolvers.txt \
  -w sub_resolved.txt
```

### shuffledns（ProjectDiscovery 版 brute）

```bash
shuffledns -d target.com \
  -w ~/Tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -r resolvers.txt \
  -o sub_shuffle.txt
```

## 3. Permutation / Alteration（變異）

對現有 subdomain 做變異（dev/stg/api/old/新/舊 suffix/prefix）。

### alterx（ProjectDiscovery）

```bash
# 基本變異
alterx -l resolved.txt -o permuted.txt

# 自訂 payload
alterx -l resolved.txt -p '{{word}}-{{suffix}}' -enrich -o permuted.txt

# 搭配 enrich（用 wordlist 擴充）
alterx -l resolved.txt -enrich | dnsx -silent -o permuted_alive.txt
```

### dnsgen

```bash
pip3 install dnsgen
dnsgen resolved.txt > permuted_dnsgen.txt
dnsx -l permuted_dnsgen.txt -silent -o dnsgen_alive.txt
```

### gotator（最細緻）

```bash
# https://github.com/Josue87/gotator
go install github.com/Josue87/gotator@latest

gotator -sub resolved.txt \
  -perm permutations.txt \
  -depth 2 \
  -numbers 10 \
  -mindup \
  -adv \
  > permuted_gotator.txt
```

**permutations.txt** 常用字：

```
dev
staging
stg
qa
test
uat
internal
private
admin
old
legacy
new
v1
v2
api
console
portal
panel
corp
mgmt
```

## 4. 第三方 API（補位）

### SecurityTrails

```bash
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: YOUR_KEY" | jq -r '.subdomains[]' | \
  sed "s/$/.target.com/" > sub_st.txt
```

### VirusTotal

```bash
# 歷史解析 + subdomain
curl -s "https://www.virustotal.com/api/v3/domains/target.com/subdomains?limit=40" \
  -H "x-apikey: $VT_KEY" | jq -r '.data[].id' > sub_vt.txt
```

### Censys

```bash
# censys CLI
censys search "parsed.names: target.com" --index-type certificates | \
  jq -r '.parsed.names[]' | grep target.com > sub_censys.txt
```

### Shodan

```bash
# 從 cert 找
shodan search "ssl.cert.subject.cn:*.target.com" --fields hostnames | \
  tr ',' '\n' | grep target.com > sub_shodan.txt
```

## 5. ASN / CIDR 反查（找「忘了 DNS」的 asset）

有些 internal service 只有 IP 沒有 DNS。找組織的 ASN → 掃 CIDR。

### asnmap（ProjectDiscovery）

```bash
# 組織名稱 → ASN
asnmap -org "Target Corp" -silent

# ASN → CIDR
asnmap -a AS16509 -silent

# Domain → ASN → CIDR
echo "target.com" | asnmap -silent
```

### whoisxmlapi 反查

```bash
# IP → 同 ASN 的 hostname
curl -s "https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=$KEY&ip=1.2.3.4" | \
  jq -r '.result.records[].name'
```

### 結合 naabu / nmap 掃 CIDR

```bash
# ASN → CIDR → naabu 快速 port 掃
asnmap -a AS16509 -silent | naabu -silent -o open_ports.txt

# 只留 web port
naabu -l cidr.txt -silent -p 80,443,8080,8443 -o web_ports.txt

# 再對 open_ports 做 httpx
httpx -l open_ports.txt -silent -title -tech-detect
```

## 6. 整合 Pipeline（一條龍）

```bash
#!/bin/bash
# recon_deep.sh — deep subdomain enumeration
DOMAIN=$1
OUT=recon/$DOMAIN
mkdir -p $OUT

# 1. Passive
subfinder -d $DOMAIN -all -silent > $OUT/subfinder.txt &
amass enum -passive -d $DOMAIN -src -o $OUT/amass.txt &
assetfinder --subs-only $DOMAIN > $OUT/assetfinder.txt &
chaos -d $DOMAIN > $OUT/chaos.txt 2>/dev/null &
github-subdomains -d $DOMAIN -o $OUT/github.txt 2>/dev/null &
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' | sed 's/\*\.//g' > $OUT/crt.txt &
wait

# 2. Merge + dedup
cat $OUT/*.txt 2>/dev/null | sort -u > $OUT/passive_raw.txt

# 3. Resolve + wildcard filter
puredns resolve $OUT/passive_raw.txt \
  -r resolvers.txt \
  -w $OUT/resolved.txt

# 4. Permutation
alterx -l $OUT/resolved.txt -enrich | \
  dnsx -silent -r resolvers.txt > $OUT/permuted.txt

# 5. Final
cat $OUT/resolved.txt $OUT/permuted.txt | sort -u > $OUT/all_subdomains.txt
wc -l $OUT/all_subdomains.txt

# 6. HTTPx 存活
httpx -l $OUT/all_subdomains.txt \
  -title -tech-detect -status-code -follow-redirects \
  -silent -o $OUT/live.txt
```

## 7. 進階：被 WAF/CDN 遮罩的 origin

### 歷史 DNS（從 CDN 保護前）

```bash
# SecurityTrails 歷史
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: $ST_KEY" | jq
# 若看到 Cloudflare 之前的 origin IP → 保留

# viewdns.info
curl -s "https://viewdns.info/iphistory/?domain=target.com"
```

### Shodan SSL 反查

```bash
# 找 cert 裡有 target.com CN 的 IP
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,hostnames
# 這些 IP 可能是 origin（繞 WAF）
```

### CloudFlair

```bash
# https://github.com/christophetd/CloudFlair
pip3 install cloudflair
cloudflair target.com --censys-api-id $ID --censys-api-secret $SECRET
```

### Favicon hash

```bash
# 1. 算 favicon hash
curl -s https://target.com/favicon.ico | md5sum

# 2. Shodan 找同 hash 的 IP
shodan search 'http.favicon.hash:-1234567890'
# 很多時候能找到內部 origin
```

## 8. 常見陷阱

| 問題 | 解法 |
|------|------|
| Wildcard DNS 回一堆垃圾 | 用 puredns（自動偵測 wildcard）|
| 自己的 DNS server rate limit | 用 trusted resolvers + 限速 `-rate-limit 100` |
| Passive 找到一堆 dead subdomain | dnsx 過濾再送 httpx |
| HTTPS 憑證 CN 含 wildcard（`*.target.com`）| 不代表每個 subdomain 都存在，必須 DNS 驗證 |
| CDN 回 200 給所有 subdomain | 比對 body hash，過濾同 hash 的 |

## 9. bbflow 整合

```bash
# bbflow 預設跑 subfinder + httpx（10 分鐘）
bbflow recon target.com

# 若想深挖，手動補 script 再 merge
./recon_deep.sh target.com

# 把新找到的 subdomain 餵回 bbflow
bbflow hunt --list recon/target.com/live.txt --name target --probe
```

## 關聯文件

- [22-tool-subfinder-httpx.md](22-tool-subfinder-httpx.md) — 基礎版
- [40-checklist-new-target.md](40-checklist-new-target.md) § Phase 1
- Pentester Land Subdomain Enumeration Guide: https://pentester.land/cheatsheets/2018/11/14/subdomains-enumeration-cheatsheet.html
