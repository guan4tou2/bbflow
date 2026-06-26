#!/usr/bin/env bash
# hunt-search-engines.sh — Multi-search-engine asset discovery via uncover
#
# Queries Shodan, Censys, Fofa, and crt.sh for IPs, hosts, and open ports
# associated with the target domain.  Falls back to crt.sh when uncover is
# unavailable.
#
# Usage:
#   ./hunt-search-engines.sh <domain|URL>
#   OUT_DIR=/custom/path ./hunt-search-engines.sh example.com

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

# ─── Input ───────────────────────────────────────────────────────────────────
INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <domain|URL>"; exit 1; }
DOMAIN=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')

OUT_DIR="${OUT_DIR:-./search_engine_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
DISCOVERED_IPS="$OUT_DIR/discovered_ips.txt"
DISCOVERED_HOSTS="$OUT_DIR/discovered_hosts.txt"
: > "$OUT"
: > "$DISCOVERED_IPS"
: > "$DISCOVERED_HOSTS"

log()     { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit()     { echo "🔴 $*" | tee -a "$OUT"; }
warn()    { echo "🟡 $*" | tee -a "$OUT"; }
ok()      { echo "🟢 $*" | tee -a "$OUT"; }
section() { echo "" | tee -a "$OUT"; echo "──── $* ────" | tee -a "$OUT"; }

log "=== Search-Engine Asset Discovery: $DOMAIN ==="
log "Output: $OUT"

# ─── Admin/unexpected ports ──────────────────────────────────────────────────
ADMIN_PORTS=(8080 8443 9090 3000 5000 4000 4848 7001 8888 9200 5601 6379
             27017 2375 2376 1433 3306 5432 5900 3389 8500 8161 9000 50000)

is_admin_port() {
  local p="$1"
  for ap in "${ADMIN_PORTS[@]}"; do [[ "$p" == "$ap" ]] && return 0; done
  return 1
}

# ─── Accumulated results (associative: "IP|PORT|SERVICE|SOURCE") ─────────────
declare -a RESULTS=()
add_result() {
  local ip="$1" port="${2:--}" svc="${3:-unknown}" src="$4"
  RESULTS+=("${ip}|${port}|${svc}|${src}")
  echo "$ip" >> "$DISCOVERED_IPS"
}
add_host() {
  local h="$1"
  echo "$h" >> "$DISCOVERED_HOSTS"
}

# ─── Tool check ──────────────────────────────────────────────────────────────
HAS_UNCOVER=0
command -v uncover &>/dev/null && HAS_UNCOVER=1

HAS_JQ=0
command -v jq &>/dev/null && HAS_JQ=1

HAS_CURL=0
command -v curl &>/dev/null && HAS_CURL=1

# ─── Helper: parse uncover JSON line ─────────────────────────────────────────
# uncover -json emits one JSON object per line:
#   {"ip":"1.2.3.4","port":443,"host":"foo.example.com","url":"https://..."}
parse_uncover_line() {
  local line="$1" src="$2"
  if [ $HAS_JQ -eq 1 ]; then
    ip=$(echo "$line"   | jq -r '.ip   // empty' 2>/dev/null)
    port=$(echo "$line" | jq -r '.port // empty' 2>/dev/null)
    host=$(echo "$line" | jq -r '.host // empty' 2>/dev/null)
    svc=$(echo "$line"  | jq -r '.service // empty' 2>/dev/null)
  else
    ip=$(echo "$line"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('ip',''))"   2>/dev/null || true)
    port=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('port',''))" 2>/dev/null || true)
    host=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('host',''))" 2>/dev/null || true)
    svc=$(echo "$line"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('service',''))" 2>/dev/null || true)
  fi

  [ -n "$host" ] && add_host "$host"
  if [ -n "$ip" ]; then
    add_result "$ip" "$port" "$svc" "$src"
    if [ -n "$port" ] && is_admin_port "$port"; then
      hit "[UNEXPECTED PORT] $ip:$port ($svc) via $src — host: ${host:-?}"
    else
      [ -n "$host" ] && warn "[NEW HOST] $host → $ip:${port:-?} ($src)"
    fi
  fi
}

run_uncover() {
  local query="$1" extra_flags="$2" src="$3"
  log "  querying [$src]: $query"
  local output
  # shellcheck disable=SC2086
  output=$(uncover -q "$query" $extra_flags -silent -json 2>/dev/null || true)
  if [ -z "$output" ]; then
    log "  no results from $src"
    return
  fi
  local count=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    parse_uncover_line "$line" "$src"
    (( count++ )) || true
  done <<< "$output"
  log "  $src returned $count record(s)"
}

# ─── Phase 1: uncover queries ────────────────────────────────────────────────
if [ $HAS_UNCOVER -eq 1 ]; then
  section "1. Shodan — SSL cert"
  run_uncover "ssl:\"$DOMAIN\"" "" "shodan-ssl"

  section "2. Shodan — hostname"
  run_uncover "hostname:$DOMAIN" "-e shodan" "shodan-hostname"

  section "3. Censys"
  run_uncover "$DOMAIN" "-e censys" "censys"

  section "4. Fofa"
  run_uncover "$DOMAIN" "-e fofa" "fofa"
else
  log "[WARN] uncover not found — falling back to crt.sh + SecurityTrails"
fi

# ─── Phase 2: crt.sh fallback (always run, deduplicated later) ───────────────
section "5. crt.sh — Certificate Transparency"
if [ $HAS_CURL -eq 1 ]; then
  log "  fetching crt.sh for %.$DOMAIN"
  CRT_JSON=$(curl -sk -m 30 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null || true)
  if [ -z "$CRT_JSON" ]; then
    log "  crt.sh: no response"
  else
    CRT_HOSTS=$(echo "$CRT_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    seen = set()
    for e in data:
        for name in e.get('name_value','').splitlines():
            name = name.strip().lstrip('*.')
            if name and '.' in name and name not in seen:
                seen.add(name)
                print(name)
except Exception:
    pass
" 2>/dev/null | sort -u || true)

    if [ -n "$CRT_HOSTS" ]; then
      COUNT=$(echo "$CRT_HOSTS" | wc -l | tr -d ' ')
      log "  crt.sh: $COUNT unique hosts/subdomains found"
      while IFS= read -r h; do
        add_host "$h"
        add_result "" "" "cert-transparency" "crt.sh"
        warn "[NEW HOST via crt.sh] $h"
      done <<< "$CRT_HOSTS"
    else
      log "  crt.sh: no hosts parsed"
    fi
  fi
else
  log "  curl not found — crt.sh fallback skipped"
fi

# ─── Phase 3: SecurityTrails (if API key present) ─────────────────────────────
section "6. SecurityTrails (if SECURITYTRAILS_KEY set)"
ST_KEY="${SECURITYTRAILS_KEY:-${ST_API_KEY:-}}"
if [ -n "$ST_KEY" ] && [ $HAS_CURL -eq 1 ]; then
  log "  querying SecurityTrails for $DOMAIN subdomains"
  ST_JSON=$(curl -sk -m 30 \
    -H "APIKEY: $ST_KEY" \
    "https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains?children_only=false&include_inactive=false" \
    2>/dev/null || true)
  if [ -n "$ST_JSON" ]; then
    ST_HOSTS=$(echo "$ST_JSON" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for sub in data.get('subdomains', []):
        print(sub + '.$sys.argv[1]' if '.' not in sub else sub)
except Exception:
    pass
" "$DOMAIN" 2>/dev/null | sort -u || true)
    if [ -n "$ST_HOSTS" ]; then
      COUNT=$(echo "$ST_HOSTS" | wc -l | tr -d ' ')
      log "  SecurityTrails: $COUNT subdomains"
      while IFS= read -r h; do
        FULL_HOST="${h}.${DOMAIN}"
        add_host "$FULL_HOST"
        warn "[NEW HOST via SecurityTrails] $FULL_HOST"
      done <<< "$ST_HOSTS"
    fi
  fi
else
  log "  SECURITYTRAILS_KEY not set — skipping"
fi

# ─── Deduplicate output files ─────────────────────────────────────────────────
section "Deduplication"
sort -u "$DISCOVERED_IPS"    | grep -v '^$' > "${DISCOVERED_IPS}.tmp"   && mv "${DISCOVERED_IPS}.tmp"   "$DISCOVERED_IPS"   || true
sort -u "$DISCOVERED_HOSTS"  | grep -v '^$' > "${DISCOVERED_HOSTS}.tmp" && mv "${DISCOVERED_HOSTS}.tmp" "$DISCOVERED_HOSTS" || true

IP_COUNT=$(wc -l < "$DISCOVERED_IPS"   | tr -d ' ')
HOST_COUNT=$(wc -l < "$DISCOVERED_HOSTS" | tr -d ' ')
log "Unique IPs:   $IP_COUNT → $DISCOVERED_IPS"
log "Unique hosts: $HOST_COUNT → $DISCOVERED_HOSTS"

# ─── Summary table ───────────────────────────────────────────────────────────
section "Summary Table"
printf "\n%-18s %-7s %-20s %s\n" "IP" "Port" "Service" "Source" | tee -a "$OUT"
printf "%-18s %-7s %-20s %s\n" "------------------" "-------" "--------------------" "------" | tee -a "$OUT"

if [ ${#RESULTS[@]} -gt 0 ]; then
  # deduplicate results array
  declare -A SEEN_ROWS=()
  for row in "${RESULTS[@]}"; do
    [ "${SEEN_ROWS[$row]+_}" ] && continue
    SEEN_ROWS[$row]=1
    IFS='|' read -r ip port svc src <<< "$row"
    printf "%-18s %-7s %-20s %s\n" \
      "${ip:--}" "${port:--}" "${svc:-unknown}" "${src:-?}" | tee -a "$OUT"
  done
else
  log "(no structured records — check $DISCOVERED_HOSTS for passive results)"
fi

echo "" | tee -a "$OUT"
log "=== done: $DOMAIN ==="
