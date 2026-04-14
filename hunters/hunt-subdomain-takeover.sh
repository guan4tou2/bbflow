#!/usr/bin/env bash
# hunt-subdomain-takeover.sh — Subdomain takeover 候選探測
# 來源：CNAME fingerprint pattern HOLD（need to verify ownership claim）
#       can-i-take-over-xyz 官方分類
#
# 檢測：
#   1. CNAME 指向外部 vendor
#   2. HTTP 回應的 fingerprint 符合 takeover 訊息
#   3. 對照 vendor 清單確認是已知 takeover 候選
#
# 涵蓋 vendor（可被 claim 回來）：
#   Amazon S3 / GitHub Pages / Heroku / Shopify / Tumblr /
#   WordPress.com / Cargo / Fastly / Azure / Bitbucket /
#   Acquia / Helpjuice / UserVoice / Ghost / Readme.io /
#   Intercom / Zendesk / Pantheon / Wishpond / Vend / Thinkific
#
# 用法：
#   ./hunt-subdomain-takeover.sh subdomain.target.com
#   ./hunt-subdomain-takeover.sh -f subdomains.txt          # 批次
set -uo pipefail

SUB="${1:-}"
[ -z "$SUB" ] && { echo "Usage: $0 <subdomain> | -f <file>"; exit 1; }

OUT_DIR="${OUT_DIR:-./takeover_out}"
mkdir -p "$OUT_DIR"

log(){ echo "[$(date +%H:%M:%S)] $*"; }
hit(){ echo "🔴 $*"; }
warn(){ echo "🟡 $*"; }

# Fingerprint table: vendor | CNAME regex | HTTP body fingerprint | claimable?
# Based on can-i-take-over-xyz (community-maintained)
check_one() {
  local sub="$1"
  local OUT="$OUT_DIR/$(echo "$sub" | sed 's|[/:]|_|g').txt"
  : > "$OUT"

  # CNAME lookup
  local cname
  cname=$(dig +short CNAME "$sub" @1.1.1.1 2>/dev/null | head -1 | sed 's/\.$//')
  if [ -z "$cname" ]; then
    echo "$sub: no CNAME" >> "$OUT"
    return 0
  fi
  echo "$sub → CNAME: $cname" | tee -a "$OUT"

  # A record check (if no A, the CNAME is dangling)
  local arec
  arec=$(dig +short A "$sub" @1.1.1.1 2>/dev/null | head -1)

  # HTTP body check
  local body
  body=$(curl -sk --max-time 8 -L "http://$sub/" 2>/dev/null | head -c 2000)
  if [ -z "$body" ]; then
    body=$(curl -sk --max-time 8 -L "https://$sub/" 2>/dev/null | head -c 2000)
  fi

  # Vendor-specific fingerprints
  declare -a VULN_PATTERNS=(
    # vendor | cname regex | body fingerprint | claimable
    "AWS S3|\.s3[.-].*amazonaws\.com|NoSuchBucket|yes"
    "GitHub Pages|github\.io|There isn't a GitHub Pages site here|yes"
    "GitHub Pages alt|github\.io|For root URLs \\(like http://example.com/\\) you must provide an index.html|yes"
    "Heroku|herokuapp\.com|No such app|yes"
    "Heroku alt|herokudns\.com|No such app|yes"
    "Shopify|myshopify\.com|Sorry, this shop is currently unavailable|yes"
    "Tumblr|domains\.tumblr\.com|Whatever you were looking for doesn't currently exist at this address|yes"
    "WordPress|wordpress\.com|Do you want to register|yes"
    "Cargo|cargocollective\.com|404 Not Found|yes"
    "Fastly|fastly\.net|Fastly error: unknown domain|maybe"
    "Azure CloudApp|cloudapp\.net|404 Web Site not found|yes"
    "Azure Blob|blob\.core\.windows\.net|NoSuchBucket|yes"
    "Azure TrafficMgr|trafficmanager\.net|Our services aren't available|yes"
    "Bitbucket|bitbucket\.io|Repository not found|yes"
    "Acquia|acquia-sites\.com|The site you are looking for could not be found|yes"
    "Helpjuice|helpjuice\.com|We could not find what you're looking for|yes"
    "UserVoice|uservoice\.com|This UserVoice subdomain is currently available|yes"
    "Ghost|ghost\.io|The thing you were looking for is no longer here|yes"
    "Readme|readme\.io|Project doesnt exist|yes"
    "Intercom|custom\.intercom\.help|This page is reserved for artistic|yes"
    "Zendesk|zendesk\.com|Help Center Closed|no"
    "Pantheon|pantheonsite\.io|The gods are wise|yes"
    "Wishpond|wishpond\.com|https://www.wishpond.com/404\\?campaign=|yes"
    "Vend|vendecommerce\.com|Looks like you've traveled too far|yes"
    "Thinkific|thinkific\.com|You may have mistyped the address|yes"
    "Surge|surge\.sh|project not found|yes"
    "Netlify|netlify\.app|Not Found - Request ID|no"
  )

  local matched=0
  for entry in "${VULN_PATTERNS[@]}"; do
    local vendor="${entry%%|*}"
    local rest="${entry#*|}"
    local cname_re="${rest%%|*}"
    rest="${rest#*|}"
    local body_fp="${rest%%|*}"
    local claimable="${rest#*|}"

    if echo "$cname" | grep -qE "$cname_re"; then
      if echo "$body" | grep -qE "$body_fp"; then
        if [ "$claimable" = "yes" ]; then
          hit "$sub TAKEOVER candidate: vendor=$vendor  CNAME=$cname  body matches fingerprint" | tee -a "$OUT"
        else
          warn "$sub takeover candidate (non-claimable): vendor=$vendor  CNAME=$cname" | tee -a "$OUT"
        fi
        matched=1
      elif [ -z "$arec" ]; then
        warn "$sub dangling CNAME to $vendor  (no A record, no fingerprint match — needs manual verify)" | tee -a "$OUT"
        matched=1
      fi
    fi
  done

  if [ "$matched" = "0" ] && [ -z "$arec" ]; then
    warn "$sub dangling CNAME: $cname  (unknown vendor, manual verify)" | tee -a "$OUT"
  fi
}

if [ "$SUB" = "-f" ]; then
  FILE="${2:-}"
  [ -z "$FILE" ] || [ ! -f "$FILE" ] && { echo "usage: $0 -f <file>"; exit 1; }
  while read -r s; do
    [ -z "$s" ] && continue
    check_one "$s"
  done < "$FILE"
else
  check_one "$SUB"
fi
