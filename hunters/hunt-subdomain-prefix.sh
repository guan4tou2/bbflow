#!/usr/bin/env bash
# hunt-subdomain-prefix.sh — 主動前綴掃描（OSINT Arsenal §16.24）
#
# 被動 CT log 漏掉 20-40% 高價值子域（wildcard cert、HTTP-only、新佈署）。
# 本 hunter 對 100+ 高命中率前綴逐一 A record 解析，補足被動盲點。
#
# 用法（domain 模式，bbflow 從 ROOT_DOMAIN 呼叫）：
#   ./hunt-subdomain-prefix.sh example.com [known_subs_file]
#   known_subs_file: 已知子域清單（每行一個 FQDN），命中則跳過

set -uo pipefail

DOMAIN="${1:-}"
[ -z "$DOMAIN" ] && { echo "Usage: $0 <domain> [known_subs_file]"; exit 1; }
# 允許傳入 https://www.example.com 格式
DOMAIN=$(echo "$DOMAIN" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')

KNOWN_FILE="${2:-}"
OUT_DIR="${OUT_DIR:-./subdomain_prefix_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }

# ── 100+ 高命中率前綴（依 real-engagement hit-rate 排序，§16.24）──────────────
PREFIXES=(
  www mail webmail smtp imap pop owa autodiscover ftp sftp
  vpn sslvpn gateway gp globalprotect citrix fortinet anyconnect
  api app apps mobile m
  portal login sso idp iam identity accounts oauth auth adfs
  admin manage console dashboard cp cpanel
  intranet internal hr payroll finance sap erp crm helpdesk servicedesk
  support help kb status monitoring grafana kibana prometheus
  docs wiki confluence jira bitbucket gitlab jenkins sonar nexus
  git svn repo code
  dev test staging stg qa uat sandbox preprod preview demo
  careers jobs vacancies recruit eapps
  shop store ecommerce checkout payments pay billing
  old legacy archive backup beta v1 v2 classic
  cdn static assets media img files downloads public
  ns ns1 ns2 dns mx mx1 mx2
  zoom teams slack lync sip voice meet
  tender tenders suppliers vendor vendors procurement purchase
  kyc kyc-meet now-meet pix baby silver crm mgm track notify np
  api2 api3 api-stg api-dev api-uat api-prod
  auth2 login2 sso2 id accounts2
  cloud infra deploy ci cd build
  log logs logmanager metrics tracing jaeger
  redis elastic es kibana2 rabbit mq
  files upload download blob storage
  mail2 email smtp2 relay mailout
  vpn2 remote access jump bastion
  mvpn portal2 partner b2b b2c
)

log "=== subdomain prefix hunt: $DOMAIN (${#PREFIXES[@]} prefixes) ==="

# 建立已知子域 set
declare -A KNOWN_SET
if [ -n "$KNOWN_FILE" ] && [ -f "$KNOWN_FILE" ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && KNOWN_SET["${line,,}"]=1
  done < "$KNOWN_FILE"
  log "loaded $(echo "${!KNOWN_SET[@]}" | wc -w | tr -d ' ') known subdomains (will skip)"
fi

NEW_COUNT=0
FOUND_HOSTS=()

for prefix in "${PREFIXES[@]}"; do
  FQDN="${prefix}.${DOMAIN}"

  # 跳過已知子域
  [ "${KNOWN_SET[${FQDN,,}]+_}" ] && continue

  IP=$(dig +short A "$FQDN" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
  CNAME=$(dig +short CNAME "$FQDN" 2>/dev/null | head -1)

  if [ -n "$IP" ]; then
    NEW_COUNT=$((NEW_COUNT + 1))
    FOUND_HOSTS+=("$FQDN")
    hit "NEW subdomain: $FQDN → $IP"

    # ── subdomain takeover 快速檢查（§16.12）──────────────────────────────
    if [ -n "$CNAME" ]; then
      CNAME_CLEAN="${CNAME%.}"
      BODY=$(curl -sk -m 8 "https://$FQDN/" 2>/dev/null | head -c 500)
      TAKEOVER_SIG=""
      case "$CNAME_CLEAN" in
        *.github.io)          echo "$BODY" | grep -qi "There isn't a GitHub Pages site here" && TAKEOVER_SIG="GitHub Pages unclaimed" ;;
        *.herokuapp.com)      echo "$BODY" | grep -qi "No such app" && TAKEOVER_SIG="Heroku unclaimed" ;;
        *.amazonaws.com)      echo "$BODY" | grep -qi "NoSuchBucket\|NoSuchKey" && TAKEOVER_SIG="S3 bucket unclaimed" ;;
        *.azurewebsites.net)  echo "$BODY" | grep -qi "404 Web Site not found\|does not exist" && TAKEOVER_SIG="Azure App Service unclaimed" ;;
        *.webflow.io)         echo "$BODY" | grep -qi "This site is not available\|Site not found" && TAKEOVER_SIG="Webflow unclaimed" ;;
        *.zendesk.com)        echo "$BODY" | grep -qi "Help Center Closed" && TAKEOVER_SIG="Zendesk unclaimed" ;;
      esac
      if [ -n "$TAKEOVER_SIG" ]; then
        hit "TAKEOVER CANDIDATE: $FQDN → CNAME $CNAME_CLEAN ($TAKEOVER_SIG)"
      else
        info_hit "  CNAME: $FQDN → $CNAME_CLEAN ($IP)"
      fi
    fi

    # ── HTTP 快速探測 ──────────────────────────────────────────────────────
    CODE=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "https://$FQDN/" 2>/dev/null)
    SERVER=$(curl -sk -m 8 -I "https://$FQDN/" 2>/dev/null | grep -i '^server:' | cut -d: -f2- | tr -d ' \r\n' | head -c 60)
    [ -n "$CODE" ] && info_hit "  HTTP probe: $FQDN → $CODE ${SERVER:+(Server: $SERVER)}"

  elif [ -n "$CNAME" ]; then
    # CNAME 存在但無 A record → dangling CNAME，takeover 候選
    CNAME_CLEAN="${CNAME%.}"
    BODY=$(curl -sk -m 8 "https://$FQDN/" 2>/dev/null | head -c 300)
    TAKEOVER_SIG=""
    case "$CNAME_CLEAN" in
      *.github.io)     echo "$BODY" | grep -qi "There isn't a GitHub Pages" && TAKEOVER_SIG="GitHub Pages" ;;
      *.herokuapp.com) echo "$BODY" | grep -qi "No such app" && TAKEOVER_SIG="Heroku" ;;
      *.amazonaws.com) echo "$BODY" | grep -qi "NoSuchBucket" && TAKEOVER_SIG="S3" ;;
      *.surge.sh)      echo "$BODY" | grep -qi "project not found" && TAKEOVER_SIG="Surge.sh" ;;
      *.netlify.app)   echo "$BODY" | grep -qi "Not found" && TAKEOVER_SIG="Netlify" ;;
    esac
    if [ -n "$TAKEOVER_SIG" ]; then
      hit "TAKEOVER (dangling CNAME): $FQDN → $CNAME_CLEAN ($TAKEOVER_SIG unclaimed)"
    fi
  fi
done

log "=== done: $NEW_COUNT new subdomains discovered ==="

if [ ${#FOUND_HOSTS[@]} -gt 0 ]; then
  echo "" >> "$OUT"
  echo "## New Subdomains Summary" >> "$OUT"
  for h in "${FOUND_HOSTS[@]}"; do echo "  $h" >> "$OUT"; done
fi
