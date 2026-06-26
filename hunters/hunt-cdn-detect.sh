#!/usr/bin/env bash
# hunt-cdn-detect.sh — CDN/WAF detection via cdncheck + header fingerprinting
#
# Detects CDN and WAF presence to inform payload strategy:
#   🟡 CDN detected  → origin IP bypass may be needed (Shodan/censys)
#   🔴 WAF detected  → payloads may be blocked; bypass techniques required
#
# cdncheck (projectdiscovery): echo HOST | cdncheck -silent -resp -json
# Fallback: curl header fingerprinting (CF-Ray, X-Amz-Cf-Id, etc.)
#
# Usage (single):
#   ./hunt-cdn-detect.sh example.com
#   ./hunt-cdn-detect.sh https://api.example.com
#
# Usage (bulk — reads from sibling live_hosts / subdomains files if no arg):
#   TARGET="" ./hunt-cdn-detect.sh
#   cat live_hosts.txt | xargs -I{} ./hunt-cdn-detect.sh {}

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

# ─── Input resolution ────────────────────────────────────────────────────────
TARGET="${1:-}"
OUT_DIR="${OUT_DIR:-./cdn_detect_out}"
mkdir -p "$OUT_DIR"

# Bulk host list fallback (no argument supplied)
BULK_MODE=0
HOSTS_FILE=""
if [ -z "$TARGET" ]; then
  for candidate in \
    "$OUT_DIR/../httpx_out/live_hosts.txt" \
    "$OUT_DIR/../recon_out/live_hosts.txt" \
    "$(dirname "$OUT_DIR")/live_hosts.txt" \
    "./live_hosts.txt" \
    "./subdomains.txt"; do
    if [ -f "$candidate" ]; then
      HOSTS_FILE="$candidate"
      BULK_MODE=1
      break
    fi
  done
  if [ $BULK_MODE -eq 0 ]; then
    echo "Usage: $0 <host|URL>"
    echo "       Or place live_hosts.txt / subdomains.txt alongside OUT_DIR."
    exit 1
  fi
fi

# ─── Shared output ───────────────────────────────────────────────────────────
CDN_INFO="$OUT_DIR/cdn_info.txt"
SUMMARY="$OUT_DIR/summary.txt"
: > "$CDN_INFO"
: > "$SUMMARY"

log()     { echo "[$(date +%H:%M:%S)] $*"; }
hit()     { echo "🔴 $*"; }
warn()    { echo "🟡 $*"; }
ok()      { echo "🟢 $*"; }
section() { echo ""; echo "──── $* ────"; }

# ─── Tool detection ──────────────────────────────────────────────────────────
HAS_CDNCHECK=0
HAS_CURL=0
command -v cdncheck &>/dev/null && HAS_CDNCHECK=1
command -v curl     &>/dev/null && HAS_CURL=1
[ $HAS_CURL -eq 0 ] && { echo "[ERROR] curl not found — required for fallback"; exit 1; }

# ─── Per-host detection function ─────────────────────────────────────────────
detect_host() {
  local raw_target="$1"

  # Normalise: strip protocol, trailing slash, extract host
  local host url
  host=$(echo "$raw_target" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
  # Prefer HTTPS for header probing
  url="https://${host}"

  local out_file
  out_file="$OUT_DIR/$(echo "$host" | tr '.' '_').txt"
  : > "$out_file"

  tee_out() { echo "$*" | tee -a "$out_file"; }

  # Result accumulators
  local cdn_provider="" waf_provider="" cloud_provider="" flags=""

  log "=== CDN/WAF Detection: $host ===" | tee -a "$out_file"

  # ── A. cdncheck path ────────────────────────────────────────────────────────
  if [ $HAS_CDNCHECK -eq 1 ]; then
    section "cdncheck scan" | tee -a "$out_file"
    local cdncheck_raw
    cdncheck_raw=$(echo "$host" | cdncheck -silent -resp -json 2>/dev/null || true)

    if [ -n "$cdncheck_raw" ]; then
      echo "$cdncheck_raw" | tee -a "$out_file"

      # Parse JSON fields (portable; no jq dependency)
      local cdn waf cloud
      cdn=$(echo   "$cdncheck_raw" | grep -o '"cdn":[^,}]*'   | grep -oE '"[^"]+"$' | tr -d '"' || true)
      waf=$(echo   "$cdncheck_raw" | grep -o '"waf":[^,}]*'   | grep -oE '"[^"]+"$' | tr -d '"' || true)
      cloud=$(echo "$cdncheck_raw" | grep -o '"cloud":[^,}]*' | grep -oE '"[^"]+"$' | tr -d '"' || true)

      [ -n "$cdn"   ] && cdn_provider="$cdn"
      [ -n "$waf"   ] && waf_provider="$waf"
      [ -n "$cloud" ] && cloud_provider="$cloud"
    else
      echo "   cdncheck returned no output — falling through to header probe" | tee -a "$out_file"
    fi
  fi

  # ── B. Header fingerprinting fallback (always runs if cdncheck had no CDN hit) ──
  if [ -z "$cdn_provider" ] && [ -z "$waf_provider" ]; then
    section "Header fingerprinting" | tee -a "$out_file"

    local headers
    headers=$(curl -skI --max-time 10 \
      -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
      "$url" 2>/dev/null)

    if [ -z "$headers" ]; then
      # Try HTTP if HTTPS failed
      headers=$(curl -skI --max-time 10 "http://${host}" 2>/dev/null)
    fi

    if [ -n "$headers" ]; then
      echo "$headers" | head -30 | tee -a "$out_file"

      # ── CDN header checks ─────────────────────────────────────────────────
      # Cloudflare
      if echo "$headers" | grep -qi "^cf-ray:\|^cf-cache-status:\|^server: cloudflare"; then
        cdn_provider="Cloudflare"
      fi

      # CloudFront (AWS)
      if echo "$headers" | grep -qi "^x-amz-cf-id:\|^x-amz-cf-pop:\|^x-cache:.*cloudfront"; then
        cdn_provider="AWS CloudFront"
        cloud_provider="${cloud_provider:-AWS}"
      fi

      # Akamai
      if echo "$headers" | grep -qi "^x-akamai-\|^server:.*akamaighost\|^x-check-cacheable:"; then
        cdn_provider="Akamai"
      fi

      # Fastly
      if echo "$headers" | grep -qi "^x-fastly-\|^x-served-by:.*cache-\|^fastly-io-warning:"; then
        cdn_provider="Fastly"
      fi

      # Varnish (generic CDN)
      if echo "$headers" | grep -qi "^x-varnish:\|^via:.*varnish"; then
        cdn_provider="${cdn_provider:-Varnish/Generic CDN}"
      fi

      # Generic X-CDN header
      if echo "$headers" | grep -qi "^x-cdn:"; then
        local xcdn
        xcdn=$(echo "$headers" | grep -i "^x-cdn:" | head -1 | awk '{print $2}' | tr -d '\r')
        cdn_provider="${cdn_provider:-CDN (X-CDN: $xcdn)}"
      fi

      # Cloudflare also via CNAME check
      if echo "$headers" | grep -qi "^server: cloudflare"; then
        cdn_provider="${cdn_provider:-Cloudflare}"
      fi

      # Bunny CDN
      if echo "$headers" | grep -qi "^x-bunnycdn-\|^server:.*bunny"; then
        cdn_provider="${cdn_provider:-BunnyCDN}"
      fi

      # Azure CDN / Front Door
      if echo "$headers" | grep -qi "^x-msedge-ref:\|^x-azure-ref:\|^x-fd-healthprobe:"; then
        cdn_provider="${cdn_provider:-Azure CDN/Front Door}"
        cloud_provider="${cloud_provider:-Azure}"
      fi

      # ── WAF header checks ─────────────────────────────────────────────────
      # Sucuri WAF
      if echo "$headers" | grep -qi "^x-sucuri-id:\|^x-sucuri-cache:"; then
        waf_provider="Sucuri WAF"
      fi

      # Fortinet FortiWeb
      if echo "$headers" | grep -qi "^x-fw-server:\|^x-fw-hash:"; then
        waf_provider="${waf_provider:+$waf_provider, }FortiWeb"
      fi

      # Imperva / Incapsula
      if echo "$headers" | grep -qi "^x-iinfo:\|^x-cdn:.*incapsula\|incapsula" ; then
        waf_provider="${waf_provider:+$waf_provider, }Imperva/Incapsula"
      fi

      # AWS WAF
      if echo "$headers" | grep -qi "^x-amzn-waf-\|awselb"; then
        waf_provider="${waf_provider:+$waf_provider, }AWS WAF"
        cloud_provider="${cloud_provider:-AWS}"
      fi

      # Cloudflare also acts as WAF
      if echo "$headers" | grep -qi "^cf-ray:" && echo "$headers" | grep -qi "^server: cloudflare"; then
        waf_provider="${waf_provider:+$waf_provider, }Cloudflare WAF"
      fi

      # F5 BIG-IP ASM
      if echo "$headers" | grep -qi "^x-wa-info:\|^bigipserver\|^set-cookie:.*BIGipServer"; then
        waf_provider="${waf_provider:+$waf_provider, }F5 BIG-IP ASM"
      fi

      # Barracuda WAF
      if echo "$headers" | grep -qi "^barra_counter_session:\|^set-cookie:.*barra"; then
        waf_provider="${waf_provider:+$waf_provider, }Barracuda WAF"
      fi

      # Cloudflare WAF block page check (403 with CF)
      if echo "$headers" | grep -qi "^cf-ray:" && echo "$headers" | grep -qi "^HTTP.*403"; then
        waf_provider="${waf_provider:+$waf_provider, }Cloudflare WAF (blocking)"
      fi
    else
      echo "   [WARN] No HTTP response from $url or http://${host}" | tee -a "$out_file"
    fi
  fi

  # ── C. Flag emission ─────────────────────────────────────────────────────────
  section "Result" | tee -a "$out_file"

  local result_line="$host"

  if [ -n "$cdn_provider" ]; then
    warn "CDN detected: $cdn_provider" | tee -a "$out_file"
    echo "   → May need origin IP bypass (Shodan: ssl:\"$host\", Censys, historical DNS)" | tee -a "$out_file"
    result_line+=" | CDN: $cdn_provider"
    flags+="CDN "
  fi

  if [ -n "$waf_provider" ]; then
    hit "WAF detected: $waf_provider" | tee -a "$out_file"
    echo "   → WAF may block payloads; apply bypass techniques before active testing" | tee -a "$out_file"
    result_line+=" | WAF: $waf_provider"
    flags+="WAF "
  fi

  if [ -n "$cloud_provider" ]; then
    ok "Cloud provider: $cloud_provider" | tee -a "$out_file"
    result_line+=" | Cloud: $cloud_provider"
  fi

  if [ -z "$cdn_provider" ] && [ -z "$waf_provider" ] && [ -z "$cloud_provider" ]; then
    ok "No CDN/WAF/Cloud detected (direct origin or unknown)" | tee -a "$out_file"
    result_line+=" | DIRECT"
    flags="NONE"
  fi

  # ── D. Write cdn_info.txt entry ──────────────────────────────────────────────
  {
    echo "HOST=$host"
    [ -n "$cdn_provider"   ] && echo "CDN=$cdn_provider"
    [ -n "$waf_provider"   ] && echo "WAF=$waf_provider"
    [ -n "$cloud_provider" ] && echo "CLOUD=$cloud_provider"
    [ -n "$flags"          ] && echo "FLAGS=${flags% }"
    echo "---"
  } >> "$CDN_INFO"

  # Return summary line for bulk table
  printf '%s\n' "$result_line" >> "$SUMMARY"

  log "Output: $out_file" | tee -a "$out_file"
}

# ─── Main: single vs bulk ────────────────────────────────────────────────────
if [ $BULK_MODE -eq 0 ]; then
  detect_host "$TARGET"
  log "cdn_info written → $CDN_INFO"
else
  log "=== Bulk CDN/WAF detection from: $HOSTS_FILE ==="
  total=0 cdn_count=0 waf_count=0

  while IFS= read -r line; do
    line="${line//[$'\t\r\n']}"
    [ -z "$line" ] && continue
    [[ "$line" =~ ^# ]] && continue
    detect_host "$line"
    total=$((total + 1))
  done < "$HOSTS_FILE"

  # ── Summary table ──────────────────────────────────────────────────────────
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║              CDN/WAF Detection — Summary Table               ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  printf "║  %-58s ║\n" "Hosts scanned : $total"
  cdn_count=$(grep -c "CDN=" "$CDN_INFO" 2>/dev/null || echo 0)
  waf_count=$(grep -c "WAF=" "$CDN_INFO" 2>/dev/null || echo 0)
  printf "║  %-58s ║\n" "CDN detected  : $cdn_count"
  printf "║  %-58s ║\n" "WAF detected  : $waf_count"
  echo "╠══════════════════════════════════════════════════════════════╣"
  echo "║  HOST                             │ CDN          │ WAF       ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  if [ -f "$SUMMARY" ]; then
    while IFS= read -r sline; do
      local_host=$(echo "$sline" | awk -F' | ' '{print $1}' | cut -c1-30)
      local_cdn=$(echo "$sline" | grep -oP '(?<=CDN: )[^|]+' | head -1 | cut -c1-12 || echo "-")
      local_waf=$(echo "$sline" | grep -oP '(?<=WAF: )[^|]+' | head -1 | cut -c1-9 || echo "-")
      printf "║  %-30s │ %-12s │ %-9s ║\n" "$local_host" "${local_cdn:--}" "${local_waf:--}"
    done < "$SUMMARY"
  fi
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  log "cdn_info written → $CDN_INFO"
  log "Summary   written → $SUMMARY"
fi
