#!/usr/bin/env bash
# tool-profiles.sh — 集中化工具最佳參數配置
#
# 用法：在 hunter 開頭 source
#   source "$(dirname "$0")/../configs/tool-profiles.sh"
#
# 兩個 profile：
#   BBFLOW_PROFILE=safe    (預設) 保守掃描，適合第一次 recon
#   BBFLOW_PROFILE=deep    深度掃描，已知 scope 內且允許較多流量

BBFLOW_PROFILE="${BBFLOW_PROFILE:-safe}"

# ═══════════════════════════════════════════════════════════════
# Nuclei
# ═══════════════════════════════════════════════════════════════
if [ "$BBFLOW_PROFILE" = "deep" ]; then
  NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-15}"
  NUCLEI_BULK_SIZE="${NUCLEI_BULK_SIZE:-50}"
  NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-25}"
  NUCLEI_RETRIES="${NUCLEI_RETRIES:-3}"
else
  NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-5}"
  NUCLEI_BULK_SIZE="${NUCLEI_BULK_SIZE:-25}"
  NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-10}"
  NUCLEI_RETRIES="${NUCLEI_RETRIES:-2}"
fi
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-10}"

nuclei_base_flags(){
  echo "-rate-limit $NUCLEI_RATE_LIMIT"
  echo "-bulk-size $NUCLEI_BULK_SIZE"
  echo "-c $NUCLEI_CONCURRENCY"
  echo "-retries $NUCLEI_RETRIES"
  echo "-timeout $NUCLEI_TIMEOUT"
  echo "-silent"
  # interactsh for OOB detection (SSRF/XXE/blind inject)
  [ -n "${INTERACTSH_SERVER:-}" ] && echo "-iserver $INTERACTSH_SERVER"
  [ -n "${INTERACTSH_TOKEN:-}" ] && echo "-itoken $INTERACTSH_TOKEN"
}

# ═══════════════════════════════════════════════════════════════
# Katana
# ═══════════════════════════════════════════════════════════════
if [ "$BBFLOW_PROFILE" = "deep" ]; then
  KATANA_DEPTH="${KATANA_DEPTH:-5}"
  KATANA_CRAWL_DURATION="${KATANA_CRAWL_DURATION:-15m}"
  KATANA_CONCURRENCY="${KATANA_CONCURRENCY:-20}"
  KATANA_RATE_LIMIT="${KATANA_RATE_LIMIT:-200}"
else
  KATANA_DEPTH="${KATANA_DEPTH:-3}"
  KATANA_CRAWL_DURATION="${KATANA_CRAWL_DURATION:-5m}"
  KATANA_CONCURRENCY="${KATANA_CONCURRENCY:-10}"
  KATANA_RATE_LIMIT="${KATANA_RATE_LIMIT:-150}"
fi

katana_base_flags(){
  echo "-d $KATANA_DEPTH"
  echo "-jc"                # JS crawl
  echo "-ct $KATANA_CRAWL_DURATION"
  echo "-c $KATANA_CONCURRENCY"
  echo "-rl $KATANA_RATE_LIMIT"
  echo "-silent"
  echo "-kf all"            # known files (robots.txt, sitemap, etc.)
  echo "-aff"               # automatic form fill
  echo "-ef css,png,jpg,gif,svg,ico,woff,ttf,eot,pdf,mp4"
  # headless for SPA — only in deep profile (Chrome/chromium needed)
  [ "$BBFLOW_PROFILE" = "deep" ] && echo "-headless"
  # XHR/fetch extraction
  echo "-xhr"
  # form action extraction
  echo "-form-extraction"
}

# ═══════════════════════════════════════════════════════════════
# Dalfox (XSS scanner)
# ═══════════════════════════════════════════════════════════════
if [ "$BBFLOW_PROFILE" = "deep" ]; then
  DALFOX_WORKERS="${DALFOX_WORKERS:-10}"
  DALFOX_TIMEOUT="${DALFOX_TIMEOUT:-15}"
  DALFOX_DELAY="${DALFOX_DELAY:-50}"
else
  DALFOX_WORKERS="${DALFOX_WORKERS:-5}"
  DALFOX_TIMEOUT="${DALFOX_TIMEOUT:-10}"
  DALFOX_DELAY="${DALFOX_DELAY:-100}"
fi

dalfox_base_flags(){
  echo "--silence"
  echo "--no-color"
  echo "--worker $DALFOX_WORKERS"
  echo "--timeout $DALFOX_TIMEOUT"
  echo "--delay $DALFOX_DELAY"
  echo "--follow-redirects"
  echo "--deep-domxss"       # DOM XSS 偵測
  echo "--mining-dict"       # 從 response 內容挖參數
  # skip BAV if kxss already confirmed reflection
  [ -n "${KXSS_PREFILTERED:-}" ] && echo "--skip-bav"
  # OOB for blind XSS
  [ -n "${DALFOX_BLIND_URL:-}" ] && echo "--blind $DALFOX_BLIND_URL"
}

# ═══════════════════════════════════════════════════════════════
# ffuf (directory/param fuzzing)
# ═══════════════════════════════════════════════════════════════
if [ "$BBFLOW_PROFILE" = "deep" ]; then
  FFUF_THREADS="${FFUF_THREADS:-30}"
  FFUF_RATE="${FFUF_RATE:-25}"
  FFUF_RECURSION="${FFUF_RECURSION:-2}"
else
  FFUF_THREADS="${FFUF_THREADS:-20}"
  FFUF_RATE="${FFUF_RATE:-15}"
  FFUF_RECURSION="${FFUF_RECURSION:-0}"
fi
FFUF_TIMEOUT="${FFUF_TIMEOUT:-10}"

ffuf_base_flags(){
  echo "-mc 200,201,204,301,302,307,401,403,405"
  echo "-fc 404,429,503"
  echo "-t $FFUF_THREADS"
  echo "-timeout $FFUF_TIMEOUT"
  echo "-rate $FFUF_RATE"
  echo "-ic"                 # ignore comments in wordlist
  echo "-s"                  # silent
  [ "$FFUF_RECURSION" -gt 0 ] && echo "-recursion -recursion-depth $FFUF_RECURSION"
}

# ═══════════════════════════════════════════════════════════════
# Waymore (multi-source URL collection)
# ═══════════════════════════════════════════════════════════════
WAYMORE_TIMEOUT="${WAYMORE_TIMEOUT:-30}"
WAYMORE_PROCESSES="${WAYMORE_PROCESSES:-3}"

waymore_base_flags(){
  echo "-mode U"             # URL mode only
  echo "-f"                  # filter results
  echo "-t $WAYMORE_TIMEOUT"
  echo "-p $WAYMORE_PROCESSES"
  echo "--stream"            # stream output
  echo "-nlf"                # no log file
  # keyword focus for high-value URLs (deep only)
  if [ "$BBFLOW_PROFILE" = "deep" ]; then
    echo "-ko admin,api,config,debug,internal,backup,test,staging,dev,private,secret,token,auth,oauth,login,dashboard,console,graphql,swagger"
  fi
}

# ═══════════════════════════════════════════════════════════════
# httpx (HTTP probing)
# ═══════════════════════════════════════════════════════════════
httpx_base_flags(){
  echo "-silent"
  echo "-mc 200,201,204,301,302,307,401,403,405,500"
  echo "-timeout 10"
  echo "-retries 2"
  echo "-threads 50"
  # tech detection
  echo "-td"                 # technology detection
  echo "-title"              # page title
  echo "-sc"                 # status code
  echo "-cl"                 # content length
  echo "-ct"                 # content type
  echo "-server"             # server header
  echo "-websocket"          # websocket detection
  # follow redirects
  echo "-follow-redirects"
  echo "-fr"
}

# ═══════════════════════════════════════════════════════════════
# Subfinder (passive subdomain enumeration)
# ═══════════════════════════════════════════════════════════════
subfinder_base_flags(){
  echo "-silent"
  echo "-all"                # use all sources
  echo "-recursive"          # recursive enumeration
  echo "-timeout 30"
  echo "-t 100"              # threads
  # provider config (keys should be in ~/.config/subfinder/provider-config.yaml)
}

# ═══════════════════════════════════════════════════════════════
# curl defaults (all hunters)
# ═══════════════════════════════════════════════════════════════
CURL_UA="${CURL_UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36}"

curl_base_flags(){
  echo "-sk"
  echo "-m ${CURL_TIMEOUT:-10}"
  echo "-A '$CURL_UA'"
}

# ═══════════════════════════════════════════════════════════════
# Export
# ═══════════════════════════════════════════════════════════════
export BBFLOW_PROFILE NUCLEI_RATE_LIMIT NUCLEI_TIMEOUT CURL_UA
