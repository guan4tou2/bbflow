#!/usr/bin/env bash
# hunt-waf-fingerprint.sh — WAF / security-infrastructure fingerprinting
#
# Identifies WAF vendor via wafw00f (-a) + optional cdncheck, then surfaces
# actionable bypass strategies specific to each detected product.
#
#   🟡 WAF detected  → bypass hints printed + written to waf_info.txt
#   🟢 No WAF        → direct testing safe
#
# Usage:
#   ./hunt-waf-fingerprint.sh example.com
#   ./hunt-waf-fingerprint.sh https://api.example.com
#   ./hunt-waf-fingerprint.sh          # bulk: reads live_hosts.txt

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

TARGET="${1:-}"
OUT_DIR="${OUT_DIR:-./waf_fingerprint_out}"
mkdir -p "$OUT_DIR"

# ── Bulk mode fallback ───────────────────────────────────────────────────────
BULK_MODE=0; HOSTS_FILE=""
if [ -z "$TARGET" ]; then
  for f in "$OUT_DIR/../httpx_out/live_hosts.txt" \
            "$OUT_DIR/../recon_out/live_hosts.txt" \
            "$(dirname "$OUT_DIR")/live_hosts.txt" \
            "./live_hosts.txt" "./subdomains.txt"; do
    [ -f "$f" ] && { HOSTS_FILE="$f"; BULK_MODE=1; break; }
  done
  if [ "$BULK_MODE" -eq 0 ]; then
    echo "Usage: $0 <host|URL>"; echo "       Or place live_hosts.txt alongside OUT_DIR for bulk mode."; exit 1
  fi
fi

WAF_INFO="$OUT_DIR/waf_info.txt"; SUMMARY="$OUT_DIR/summary.txt"
: > "$WAF_INFO"; : > "$SUMMARY"

log()     { echo "[$(date +%H:%M:%S)] $*"; }
warn()    { echo "🟡 $*"; }
ok()      { echo "🟢 $*"; }
section() { echo ""; echo "──── $* ────"; }

HAS_WAFW00F=0; HAS_CDNCHECK=0
command -v wafw00f  &>/dev/null && HAS_WAFW00F=1
command -v cdncheck &>/dev/null && HAS_CDNCHECK=1
[ "$HAS_WAFW00F" -eq 0 ] && echo "[WARN] wafw00f not found — install: pip install wafw00f"

# ── Bypass hint lookup ───────────────────────────────────────────────────────
bypass_hints() {
  local v; v=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  case "$v" in
    *cloudflare*)
      echo "  → Origin IP: historical DNS (SecurityTrails/ViewDNS), Shodan ssl:\"DOMAIN\", Censys parsed.names"
      echo "  → Direct-to-IP requests with Host header set to target domain" ;;
    *aws*|*amazon*)
      echo "  → Alternate HTTP methods (OPTIONS/PUT/PATCH) + HTTP parameter pollution"
      echo "  → X-Forwarded-For / chunked transfer encoding to evade body inspection" ;;
    *imperva*|*incapsula*)
      echo "  → Case-mix payloads (<ScRiPt>), chunked TE, HTTP/2 mixed-case headers"
      echo "  → Null byte / unicode normalization tricks" ;;
    *akamai*)
      echo "  → Path normalisation: /./endpoint, /%2f/ ; Pragma: akamai-x-get-client-ip"
      echo "  → Host header injection; large header sets to exceed WAF inspect depth" ;;
    *f5*|*big-ip*|*bigip*)
      echo "  → BIGipServer cookie detection; X-Forwarded-For: 127.0.0.1 for internal emulation"
      echo "  → UTF-7 / double-URL encoding; Cookie name casing iRule bypass" ;;
    *fortinet*|*fortiweb*)
      echo "  → HTTP/2 request smuggling (h2.cleartext); payload fragmentation across params" ;;
    *barracuda*)
      echo "  → Path bypass: /endpoint/../target ; Content-Type: text/plain body bypass"
      echo "  → Long random prefix before payload to exceed signature depth" ;;
    *sucuri*)
      echo "  → Origin IP via Shodan/Censys; try direct-to-origin with spoofed Sucuri IP headers" ;;
    *modsecurity*|*modsec*)
      echo "  → HPP, chunked TE, multipart boundary tricks; toggle method + Content-Type" ;;
    *)
      echo "  → Generic: chunked TE, HPP, case variation, unicode normalisation"
      echo "  → sqlmap --tamper=space2comment / dalfox --waf-bypass flag" ;;
  esac
}

# ── Per-host scan ────────────────────────────────────────────────────────────
scan_host() {
  local raw_target="$1"
  local host url waf_vendor="" cdncheck_waf=""
  host=$(echo "$raw_target" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
  url="https://${host}"
  local out_file="$OUT_DIR/$(echo "$host" | tr '.' '_').txt"
  : > "$out_file"

  log "=== WAF Fingerprint: $host ===" | tee -a "$out_file"

  # Step 1: wafw00f -a (all WAFs)
  section "wafw00f -a" | tee -a "$out_file"
  if [ "$HAS_WAFW00F" -eq 1 ]; then
    local waf_raw
    waf_raw=$(wafw00f -a "$url" 2>/dev/null || true)
    echo "$waf_raw" | tee -a "$out_file"
    waf_vendor=$(echo "$waf_raw" | grep -i "is behind" | sed 's/.*is behind //' | head -1 || true)
    [ -z "$waf_vendor" ] && waf_vendor=$(echo "$waf_raw" | grep -i "detected" \
      | grep -v "No WAF" | sed 's/.*: //' | head -1 || true)
  else
    echo "   [SKIP] wafw00f not installed" | tee -a "$out_file"
  fi

  # Step 2: cdncheck (complementary)
  section "cdncheck" | tee -a "$out_file"
  if [ "$HAS_CDNCHECK" -eq 1 ]; then
    local cdn_raw
    cdn_raw=$(echo "$host" | cdncheck -silent -resp -jsonl 2>/dev/null || true)
    [ -n "$cdn_raw" ] && echo "$cdn_raw" | tee -a "$out_file" || \
      echo "   cdncheck returned no output" | tee -a "$out_file"
    cdncheck_waf=$(echo "$cdn_raw" | grep -o '"waf":[^,}]*' | grep -oE '"[^"]+"$' | tr -d '"' || true)
    [ -n "$cdncheck_waf" ] && waf_vendor="${waf_vendor:-$cdncheck_waf}"
  else
    echo "   [SKIP] cdncheck not installed" | tee -a "$out_file"
  fi

  # Steps 3-5: Parse, suggest bypass, output verdict
  section "Verdict & Bypass Hints" | tee -a "$out_file"
  if [ -n "$waf_vendor" ]; then
    warn "WAF detected: $waf_vendor" | tee -a "$out_file"
    bypass_hints "$waf_vendor" | tee -a "$out_file"
    printf '%s\n' "$host | WAF: $waf_vendor" >> "$SUMMARY"
  else
    ok "No WAF detected — direct testing safe" | tee -a "$out_file"
    printf '%s\n' "$host | NONE" >> "$SUMMARY"
  fi

  # Step 6: Write waf_info.txt entry
  {
    echo "HOST=$host"
    echo "WAF_VENDOR=${waf_vendor:-none}"
    echo "BYPASS_HINTS<<EOF"
    [ -n "$waf_vendor" ] && bypass_hints "$waf_vendor" || echo "n/a"
    echo "EOF"
    echo "---"
  } >> "$WAF_INFO"

  log "Output: $out_file" | tee -a "$out_file"
}

# ── Main: single vs bulk ─────────────────────────────────────────────────────
if [ "$BULK_MODE" -eq 0 ]; then
  scan_host "$TARGET"
  log "waf_info written → $WAF_INFO"
else
  log "=== Bulk WAF fingerprint from: $HOSTS_FILE ==="
  total=0
  while IFS= read -r line; do
    line="${line//[$'\t\r\n']}"; [ -z "$line" ] && continue; [[ "$line" =~ ^# ]] && continue
    scan_host "$line"; total=$((total + 1))
  done < "$HOSTS_FILE"

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║            WAF Fingerprint — Summary Table                    ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  printf "║  %-58s ║\n" "Hosts scanned : $total"
  waf_count=$(grep -c "^WAF_VENDOR=" "$WAF_INFO" 2>/dev/null || echo 0)
  printf "║  %-58s ║\n" "WAF detected  : $waf_count"
  echo "╠══════════════════════════════════════════════════════════════╣"
  echo "║  HOST                                  │ WAF VENDOR          ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  [ -f "$SUMMARY" ] && while IFS= read -r sline; do
    h=$(echo "$sline" | awk -F' | ' '{print $1}' | cut -c1-38)
    w=$(echo "$sline" | sed -n 's/.*WAF: \([^|]*\).*/\1/p' | head -1)
      [ -z "$w" ] && w="none"
    printf "║  %-38s │ %-19s ║\n" "$h" "${w:0:19}"
  done < "$SUMMARY"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  log "waf_info written → $WAF_INFO"
  log "Summary   written → $SUMMARY"
fi
