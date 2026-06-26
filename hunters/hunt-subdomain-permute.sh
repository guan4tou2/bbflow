#!/usr/bin/env bash
# hunt-subdomain-permute.sh — Subdomain permutation/mutation hunter (alterx + dnsx)
#
# 被動 CT log + 前綴掃描以外的第三條路：對已知子域做字詞突變，
# 發現 dev2、api-staging、internal-v2 等模式（OSINT Arsenal §16.25）。
#
# 策略：
#   1. 從 sibling hunter 輸出（subfinder、bbot、prefix scan）讀取已知子域清單
#   2. 用 alterx 對已知子域生成突變（word-based permutation）
#   3. 若 alterx 不存在，內建常用前綴/後綴組合作 fallback
#   4. 用 dnsx 批次解析，過濾出真正 resolve 的新子域
#   5. 標示 🔴（內部 IP）/ 🟡（新發現）；結果寫入 $OUT_DIR/new_subdomains.txt
#
# 用法：
#   ./hunt-subdomain-permute.sh example.com [known_subs_file]
#   known_subs_file: 已知子域清單（每行一個 FQDN），可選
#                    未提供時自動搜尋 sibling 輸出目錄

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

# ─── Input ───────────────────────────────────────────────────────────────────
DOMAIN="${1:-}"
[ -z "$DOMAIN" ] && { echo "Usage: $0 <domain> [known_subs_file]"; exit 1; }
DOMAIN=$(echo "$DOMAIN" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')

KNOWN_FILE="${2:-}"
OUT_DIR="${OUT_DIR:-./subdomain_permute_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
NEW_SUBS_FILE="$OUT_DIR/new_subdomains.txt"
PERMUTE_TMP="$OUT_DIR/${SLUG}_permutations.tmp"
: > "$OUT"
: > "$NEW_SUBS_FILE"
: > "$PERMUTE_TMP"

log()     { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit()     { echo "🔴 $*" | tee -a "$OUT" | tee -a "$NEW_SUBS_FILE"; }
warn()    { echo "🟡 $*" | tee -a "$OUT" | tee -a "$NEW_SUBS_FILE"; }
ok()      { echo "🟢 $*" | tee -a "$OUT"; }
section() { echo "" | tee -a "$OUT"; echo "──── $* ────" | tee -a "$OUT"; }

log "=== subdomain permutation hunt: $DOMAIN ==="
log "Output: $OUT"
log "New subdomains: $NEW_SUBS_FILE"

# ─── Tool checks ─────────────────────────────────────────────────────────────
HAS_ALTERX=0; HAS_DNSX=0; HAS_DIG=0
command -v alterx &>/dev/null && HAS_ALTERX=1
command -v dnsx   &>/dev/null && HAS_DNSX=1
command -v dig    &>/dev/null && HAS_DIG=1

log "Tools: alterx=$HAS_ALTERX  dnsx=$HAS_DNSX  dig=$HAS_DIG"
[ $HAS_ALTERX -eq 0 ] && log "[WARN] alterx not found — using built-in fallback permutation"
[ $HAS_DNSX   -eq 0 ] && log "[WARN] dnsx not found — falling back to dig per-entry resolution"

# ─── §1 Locate known subdomains ──────────────────────────────────────────────
section "1. Locate known subdomains"

KNOWN_SUBS_TMP="$OUT_DIR/${SLUG}_known.tmp"
: > "$KNOWN_SUBS_TMP"

# Priority: explicit file arg → sibling hunter outputs → synthesise from domain only
if [ -n "$KNOWN_FILE" ] && [ -f "$KNOWN_FILE" ]; then
  log "Using provided known subs file: $KNOWN_FILE"
  grep -F ".$DOMAIN" "$KNOWN_FILE" >> "$KNOWN_SUBS_TMP" 2>/dev/null || true
  grep -Fx "$DOMAIN"  "$KNOWN_FILE" >> "$KNOWN_SUBS_TMP" 2>/dev/null || true
else
  # Search sibling output directories relative to OUT_DIR parent and cwd
  SEARCH_ROOTS=()
  SEARCH_ROOTS+=("$(dirname "$OUT_DIR")")
  SEARCH_ROOTS+=("$(pwd)")
  SEARCH_ROOTS+=("${OUT_DIR%/*}")

  SIBLING_PATTERNS=(
    "subfinder_out/${SLUG}*.txt"
    "subdomain_prefix_out/${SLUG}*.txt"
    "dns_deep_out/${SLUG}*.txt"
    "bbot_out/${SLUG}*/subdomains-${SLUG}*.txt"
    "*subfinder*/${SLUG}*.txt"
    "*recon*/${SLUG}*.txt"
    "${SLUG}*.txt"
  )

  log "Searching for known subdomain lists in sibling dirs..."
  FOUND_ANY=0
  for ROOT in "${SEARCH_ROOTS[@]}"; do
    [ -d "$ROOT" ] || continue
    for PAT in "${SIBLING_PATTERNS[@]}"; do
      while IFS= read -r -d '' FPATH; do
        log "  Found: $FPATH"
        # Extract lines that look like subdomains of DOMAIN
        grep -Ei "^[a-z0-9._-]+\.${DOMAIN//./\\.}$" "$FPATH" >> "$KNOWN_SUBS_TMP" 2>/dev/null || true
        FOUND_ANY=1
      done < <(find "$ROOT" -maxdepth 4 -name "$(basename "$PAT")" -print0 2>/dev/null)
    done
  done

  if [ "$FOUND_ANY" -eq 0 ]; then
    log "No sibling outputs found — will use built-in prefixes only"
  fi
fi

# Deduplicate known subs
sort -u -o "$KNOWN_SUBS_TMP" "$KNOWN_SUBS_TMP"
KNOWN_COUNT=$(wc -l < "$KNOWN_SUBS_TMP" | tr -d ' ')
log "Known subdomains loaded: $KNOWN_COUNT"

# Build lookup set for deduplication
declare -A KNOWN_SET
if [ "$KNOWN_COUNT" -gt 0 ]; then
  while IFS= read -r line; do
    [ -n "$line" ] && KNOWN_SET["${line,,}"]=1
  done < "$KNOWN_SUBS_TMP"
fi

# ─── §2 Generate permutations ────────────────────────────────────────────────
section "2. Generate permutations"

# Built-in mutation words (prepended / appended / both directions)
MUTATION_WORDS=(
  dev staging stage test qa uat beta alpha demo sandbox
  internal admin api vpn mail ftp db backup old new temp tmp
  pre prod preview preprod pre-prod stg stg2 dev2 test2 qa2
  uat2 beta2 alpha2 staging2 stage2 sandbox2 secure private
  app apps mobile m web www portal login auth sso
  v1 v2 v3 v4 next legacy classic archive mirror cdn
  us eu ap east west north south central aws gcp azure k8s
  infra cloud ops devops ci cd build deploy release
)

if [ $HAS_ALTERX -eq 1 ] && [ "$KNOWN_COUNT" -gt 0 ]; then
  log "Running alterx on $KNOWN_COUNT known subdomains..."
  # alterx reads subdomains from stdin, outputs permutations
  cat "$KNOWN_SUBS_TMP" | alterx -silent 2>/dev/null >> "$PERMUTE_TMP" || {
    log "[WARN] alterx failed — switching to built-in fallback"
    HAS_ALTERX=0
  }
  PERMUTE_COUNT=$(wc -l < "$PERMUTE_TMP" | tr -d ' ')
  log "alterx generated $PERMUTE_COUNT permutations"
fi

if [ $HAS_ALTERX -eq 0 ]; then
  log "Built-in fallback: generating word-based permutations..."

  # Seed list: known subs + bare DOMAIN root
  SEED_BASES=()
  if [ "$KNOWN_COUNT" -gt 0 ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      # Strip the DOMAIN suffix to get the label (e.g. "api" from "api.example.com")
      LABEL="${line%.${DOMAIN}}"
      LABEL="${LABEL%.}"          # trim any trailing dot
      [ "$LABEL" != "$line" ] && [ -n "$LABEL" ] && SEED_BASES+=("$LABEL")
    done < "$KNOWN_SUBS_TMP"
  fi

  # Always include bare domain as a seed base (generates pure prefix words)
  if [ ${#SEED_BASES[@]} -eq 0 ]; then
    SEED_BASES=("${DOMAIN%%.*}")
  fi

  for WORD in "${MUTATION_WORDS[@]}"; do
    # Bare word as new subdomain
    echo "${WORD}.${DOMAIN}" >> "$PERMUTE_TMP"

    for BASE in "${SEED_BASES[@]}"; do
      # prepend: dev-api, staging-api
      echo "${WORD}-${BASE}.${DOMAIN}" >> "$PERMUTE_TMP"
      # append: api-dev, api-staging
      echo "${BASE}-${WORD}.${DOMAIN}" >> "$PERMUTE_TMP"
      # numeric suffixes: api2, api3
      for N in 2 3; do
        echo "${BASE}${N}.${DOMAIN}" >> "$PERMUTE_TMP"
      done
    done
  done

  sort -u -o "$PERMUTE_TMP" "$PERMUTE_TMP"
  PERMUTE_COUNT=$(wc -l < "$PERMUTE_TMP" | tr -d ' ')
  log "Built-in fallback generated $PERMUTE_COUNT permutations"
fi

# Remove already-known entries from permutation list
CANDIDATES_TMP="$OUT_DIR/${SLUG}_candidates.tmp"
: > "$CANDIDATES_TMP"
while IFS= read -r line; do
  [ -z "$line" ] && continue
  # Ensure permutation ends with .DOMAIN (some alterx output may not)
  [[ "$line" == *".$DOMAIN" || "$line" == "$DOMAIN" ]] || continue
  [ "${KNOWN_SET[${line,,}]+_}" ] && continue
  echo "$line" >> "$CANDIDATES_TMP"
done < "$PERMUTE_TMP"
sort -u -o "$CANDIDATES_TMP" "$CANDIDATES_TMP"
CANDIDATE_COUNT=$(wc -l < "$CANDIDATES_TMP" | tr -d ' ')
log "Candidates after deduplication: $CANDIDATE_COUNT"

# ─── §3 DNS resolution ───────────────────────────────────────────────────────
section "3. DNS resolution via dnsx / dig"

is_internal_ip() {
  local ip="$1"
  [[ "$ip" =~ ^10\. ]]          && return 0
  [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
  [[ "$ip" =~ ^192\.168\. ]]    && return 0
  [[ "$ip" =~ ^127\. ]]         && return 0
  [[ "$ip" =~ ^169\.254\. ]]    && return 0
  [[ "$ip" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]] && return 0
  return 1
}

NEW_COUNT=0

if [ $HAS_DNSX -eq 1 ] && [ "$CANDIDATE_COUNT" -gt 0 ]; then
  log "Resolving $CANDIDATE_COUNT candidates with dnsx..."
  DNSX_OUT="$OUT_DIR/${SLUG}_dnsx.tmp"
  # dnsx -a -resp prints: subdomain [ip1,ip2,...]
  cat "$CANDIDATES_TMP" | dnsx -silent -a -resp -retry 3 2>/dev/null > "$DNSX_OUT" || true

  while IFS= read -r line; do
    [ -z "$line" ] && continue
    # Parse dnsx output: "sub.example.com [1.2.3.4]"
    SUB=$(echo "$line" | awk '{print $1}')
    IPS=$(echo "$line" | grep -oE '\[([0-9.,]+)\]' | tr -d '[]')
    FIRST_IP=$(echo "$IPS" | cut -d, -f1)

    [ -z "$SUB" ] && continue
    NEW_COUNT=$((NEW_COUNT + 1))

    if [ -n "$FIRST_IP" ] && is_internal_ip "$FIRST_IP"; then
      hit "NEW (internal IP): $SUB → $FIRST_IP"
    else
      warn "NEW subdomain: $SUB → ${FIRST_IP:-NXDOMAIN/CNAME}"
    fi

    echo "$SUB" >> "$NEW_SUBS_FILE"
  done < "$DNSX_OUT"

else
  # Fallback: resolve one-by-one with dig
  log "Resolving $CANDIDATE_COUNT candidates with dig (fallback — may be slow)..."

  while IFS= read -r FQDN; do
    [ -z "$FQDN" ] && continue

    IP=$(dig +short A "$FQDN" @1.1.1.1 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    CNAME=$(dig +short CNAME "$FQDN" @1.1.1.1 2>/dev/null | head -1 | sed 's/\.$//')

    if [ -n "$IP" ]; then
      NEW_COUNT=$((NEW_COUNT + 1))
      if is_internal_ip "$IP"; then
        hit "NEW (internal IP): $FQDN → $IP"
      else
        warn "NEW subdomain: $FQDN → $IP${CNAME:+ (CNAME: $CNAME)}"
      fi
      echo "$FQDN" >> "$NEW_SUBS_FILE"
    elif [ -n "$CNAME" ]; then
      # CNAME resolved but no A — still a live name
      CNAME_IP=$(dig +short A "$CNAME" @1.1.1.1 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
      if [ -n "$CNAME_IP" ]; then
        NEW_COUNT=$((NEW_COUNT + 1))
        warn "NEW subdomain (via CNAME): $FQDN → $CNAME → $CNAME_IP"
        echo "$FQDN" >> "$NEW_SUBS_FILE"
      fi
    fi
  done < "$CANDIDATES_TMP"
fi

# ─── §4 Summary ──────────────────────────────────────────────────────────────
section "4. Summary"
sort -u -o "$NEW_SUBS_FILE" "$NEW_SUBS_FILE"
FINAL_COUNT=$(wc -l < "$NEW_SUBS_FILE" | tr -d ' ')
log "=== Done ==="
log "  Permutations tested : $CANDIDATE_COUNT"
log "  New subdomains found: $FINAL_COUNT"
log "  Results saved to    : $NEW_SUBS_FILE"

if [ "$FINAL_COUNT" -gt 0 ]; then
  ok "New subdomains:"
  while IFS= read -r s; do
    ok "  $s"
  done < "$NEW_SUBS_FILE"
else
  ok "No new subdomains found via permutation"
fi

# Clean up temp files
rm -f "$KNOWN_SUBS_TMP" "$PERMUTE_TMP" "$CANDIDATES_TMP" \
       "$OUT_DIR/${SLUG}_dnsx.tmp" 2>/dev/null || true
