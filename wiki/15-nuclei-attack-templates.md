---
type: wiki
category: playbook
status: active
last-updated: 2026-04-21
---

# nuclei 攻擊面完整覆蓋指南

> 解決「nuclei 預設 template 掃完沒洞」的痛點：預設只跑 `cves/` + 一小部分 `vulnerabilities/`，**實際有 100+ 個 tag 可以用**。
> 搭配 `tools/hunters/hunt-nuclei-deep.sh` 一鍵覆蓋所有類別。

## 自動化（推薦）

```bash
# 全類別掃（~5-15 分鐘）
tools/hunters/hunt-nuclei-deep.sh https://target.com

# 只跑 XSS + SQLi + SSRF + LFI
CATEGORY=xss,sqli,ssrf,lfi tools/hunters/hunt-nuclei-deep.sh https://target.com

# 只跑 high/critical（省時）
FAST=1 tools/hunters/hunt-nuclei-deep.sh https://target.com

# 開啟 DAST fuzz mode（對 URL 參數做 payload fuzz）
DAST=1 CATEGORY=xss,sqli URL_LIST=endpoints.txt tools/hunters/hunt-nuclei-deep.sh

# 低噪音版（政府/有 WAF 的目標）
RATE=10 CONC=5 tools/hunters/hunt-nuclei-deep.sh https://target.com
```

## 手動按類別掃

### XSS

```bash
# Reflected / stored / DOM
nuclei -u https://target -tags xss,dom -silent

# DAST 模式（對 URL params fuzz）
nuclei -l endpoints.txt -tags xss -dast -silent
nuclei -u "https://target/search?q=FUZZ" -tags xss -dast -silent

# 只跑官方 exposure/xss/
nuclei -u https://target -t http/vulnerabilities/xss/ -silent
```

### SQL Injection

```bash
# 錯誤類型（error-based）
nuclei -u https://target -tags sqli -silent

# DAST（對每個 param 注 payload）
nuclei -l endpoints.txt -tags sqli -dast -silent

# 只跑已知 CVE 的 SQLi
nuclei -u https://target -tags sqli,cve -silent
```

### SSRF

```bash
# 需要 OAST（interact.sh）
nuclei -u https://target -tags ssrf -silent

# Blind SSRF 需 -oast
nuclei -u https://target -tags ssrf,oast -silent

# 指定 interactsh server
nuclei -u https://target -tags ssrf -iserver oast.pro -silent
```

### LFI / Path Traversal

```bash
# LFI + file traversal
nuclei -u https://target -tags lfi,file,traversal -silent

# DAST
nuclei -l endpoints.txt -tags lfi,traversal -dast -silent

# 特定 LFI：/etc/passwd、/proc/self/environ
# 這些在 http/vulnerabilities/generic/ 裡
```

### RCE（最有價值）

```bash
# 全 RCE tag
nuclei -u https://target -tags rce,cmd -silent

# 特定 framework
nuclei -u https://target -tags log4j,spring,struts,fastjson,shiro,thinkphp,weblogic,tomcat -silent

# OAST RCE（blind）
nuclei -u https://target -tags rce,oast -silent

# CVE-2021-44228 Log4j
nuclei -u https://target -t http/cves/2021/CVE-2021-44228.yaml -silent
```

### 權限/認證

```bash
# Default login（vendor 預設帳密）
nuclei -u https://target -tags default-login,default-logins -silent

# Weak credentials
nuclei -u https://target -tags weak-credential -silent

# Panel 偵測（再跑 default-login）
nuclei -u https://target -tags panel,exposed-panel -silent
```

### 資訊洩漏

```bash
# Disclosure / exposure / token / key
nuclei -u https://target -tags exposure,exposed,disclosure,token,key -silent

# 只看 .git / .svn / .env
nuclei -u https://target -t http/exposures/ -silent

# Secret / API key 暴露
nuclei -u https://target -tags secret,apikey -silent
```

### Debug endpoints

```bash
# /debug /actuator /phpinfo /server-status /prometheus /jmx
nuclei -u https://target -tags debug,phpinfo,actuator,springboot,jmx,prometheus,trace -silent

# Spring Boot Actuator 深挖
nuclei -u https://target -t http/misconfiguration/springboot/ -silent
```

### CORS

```bash
# CORS misconfig
nuclei -u https://target -tags cors -silent

# 只看 reflective CORS
nuclei -u https://target -t http/misconfiguration/cors/ -silent
```

### Open Redirect

```bash
nuclei -u https://target -tags redirect,open-redirect -silent

# DAST
nuclei -l endpoints.txt -tags redirect -dast -silent
```

### SSTI（Server-Side Template Injection）

```bash
nuclei -u https://target -tags ssti -silent
nuclei -l endpoints.txt -tags ssti -dast -silent
```

### XXE

```bash
nuclei -u https://target -tags xxe -silent
```

### Subdomain Takeover

```bash
nuclei -l subdomains.txt -tags takeover -silent

# 單獨驗證
nuclei -u https://sub.target.com -t http/takeovers/ -silent
```

### Cloud Misconfig（AWS / Azure / GCP）

```bash
nuclei -u https://target -tags aws,azure,gcp,s3,cloud -silent

# S3 bucket
nuclei -u https://target -t http/cves/ -tags s3 -silent
```

## CVE 按年份 / 嚴重度

```bash
# 最近一年 CVE（critical only）
nuclei -u https://target -tags cve,2024 -severity critical -silent
nuclei -u https://target -tags cve,2025 -severity critical -silent
nuclei -u https://target -tags cve,2026 -severity critical -silent

# 高價值 CVE 快速掃
nuclei -u https://target \
  -tags log4j,spring4shell,shiro,fastjson,struts,weblogic,thinkphp,tomcat,ghost \
  -severity high,critical \
  -silent
```

## DAST 模式詳解

nuclei 的 `-dast` flag 會對 URL 的 query param 做 payload fuzz，類似 sqlmap。

```bash
# 對單一 URL
nuclei -u "https://target/search?q=test&lang=en" -dast -silent

# 對 URL list（推薦搭配 gf 分類的結果）
nuclei -l gf_xss.txt -dast -tags xss -silent
nuclei -l gf_sqli.txt -dast -tags sqli -silent
nuclei -l gf_ssrf.txt -dast -tags ssrf -silent
nuclei -l gf_lfi.txt -dast -tags lfi -silent

# 從 bbflow crawl-chain 的 07_gf_* 結果餵進來
for pat in xss sqli ssrf lfi redirect ssti; do
  nuclei -l crawl_chain_out/target/07_gf_${pat}.txt \
    -tags $pat -dast -silent \
    -o nuclei_deep_out/dast_${pat}.txt
done
```

## 自訂模板（bb-recon）

自訂 template 放在 `tools/nuclei-templates/bb-recon/`，`hunt-nuclei-deep.sh` 會自動掃。

```yaml
# tools/nuclei-templates/bb-recon/custom-cms-config.yaml
id: custom-cms-config
info:
  name: CustomCMS config exposure
  author: bbflow
  severity: high
  tags: exposure,cms
http:
  - method: GET
    path:
      - "{{BaseURL}}/customcms/config.inc"
    matchers:
      - type: word
        words:
          - "db_password"
          - "db_user"
        condition: or
      - type: status
        status: [200]
```

## Template 管理

```bash
# 更新 official templates
nuclei -update-templates

# 列出所有 tag
nuclei -tl | head -100

# 看某 tag 有哪些 template
nuclei -tl -tags xss | head -20

# 只用新 template（最近 30 天）
nuclei -u target -tags cve -newer-than 30d
```

## 低噪音組合（WAF 友善）

```bash
# 針對 high/critical + 低速 + 少併發
nuclei -u https://target \
  -severity high,critical \
  -rate-limit 5 \
  -c 5 \
  -timeout 15 \
  -retries 1 \
  -silent
```

## 政府站推薦 tag 組合

```bash
# 政府站（低風險也有獎金）
nuclei -u https://target.gov.tw \
  -tags exposure,disclosure,phpinfo,actuator,springboot,default-login,xxe,lfi,xss,redirect \
  -severity low,medium,high,critical \
  -rate-limit 10 \
  -silent \
  -o gov_findings.txt
```

## 與 bbflow 整合

```bash
# 加入 bbflow
bbflow hunt target --only nuclei-deep

# CATEGORY 可傳入
CATEGORY=xss,sqli bbflow hunt target --only nuclei-deep
```

## 關聯文件

- [24-tool-nuclei.md](24-tool-nuclei.md) — nuclei 工具詳解
- [13-hunter-crawl-chain.md](13-hunter-crawl-chain.md) — crawl-chain 產生 gf_*.txt 餵 DAST
- [03-xray-rules-reference.md](03-xray-rules-reference.md)
