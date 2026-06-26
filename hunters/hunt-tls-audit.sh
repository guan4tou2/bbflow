#!/usr/bin/env bash
# hunt-tls-audit.sh — TLS certificate + config audit via tlsx/openssl
#
# 稽核 TLS 憑證與組態，發掘隱藏子網域（SAN 洩漏）、弱加密、過期/自簽憑證。
#
# Severity mapping：
#   HIGH   — 過期憑證、自簽憑證、TLS 1.0/1.1（已廢棄協議）
#   MEDIUM — 弱 cipher（RC4/DES/3DES/NULL）、SAN 跨租戶洩漏
#   LOW    — 缺少 HSTS、憑證年齡過長、wildcard+大量 SAN
#   INFO   — SAN 子網域（交給 subdomain hunters 繼續追）
#
# 用法：
#   ./hunt-tls-audit.sh example.com
#   ./hunt-tls-audit.sh https://example.com/path
#   ./hunt-tls-audit.sh -l hosts.txt          # bulk mode（tlsx only）

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

# ── Argument parsing ───────────────────────────────────────────────────────────
LIST_FILE=""
INPUT=""
if [ "${1:-}" = "-l" ]; then
  LIST_FILE="${2:-}"
  [ -z "$LIST_FILE" ] && { echo "Usage: $0 -l <hosts.txt>"; exit 1; }
  [ ! -f "$LIST_FILE" ] && { echo "File not found: $LIST_FILE"; exit 1; }
  INPUT="(bulk: $LIST_FILE)"
else
  INPUT="${1:-}"
  [ -z "$INPUT" ] && { echo "Usage: $0 <host|url>  OR  $0 -l <hosts.txt>"; exit 1; }
fi

# Normalise single-host input: strip scheme + path, keep host[:port]
if [ -z "$LIST_FILE" ]; then
  HOST=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1)
  DOMAIN=$(echo "$HOST" | cut -d: -f1)
  PORT=$(echo "$HOST" | grep -oP ':\K\d+' || echo "443")
  [ -z "$PORT" ] && PORT=443
else
  # For bulk mode, use the list filename as slug
  DOMAIN=$(basename "$LIST_FILE" | sed 's/\.[^.]*$//')
  HOST=""
  PORT=443
fi

# ── Output setup ──────────────────────────────────────────────────────────────
OUT_DIR="${OUT_DIR:-./tls_audit_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_' | tr '/' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

TLS_SANS_FILE="$OUT_DIR/tls_sans.txt"
# Preserve existing SANs from prior runs; we'll append
touch "$TLS_SANS_FILE"

log()     { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit()     { echo "🔴 $*" | tee -a "$OUT"; }
warn()    { echo "🟡 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟣 $*" | tee -a "$OUT"; }
ok()      { echo "🟢 $*" | tee -a "$OUT"; }

log "=== TLS Audit: $INPUT ==="

# ── Tool detection ─────────────────────────────────────────────────────────────
TLSX_BIN=$(command -v tlsx 2>/dev/null || true)
OPENSSL_BIN=$(command -v openssl 2>/dev/null || true)

if [ -z "$TLSX_BIN" ] && [ -z "$OPENSSL_BIN" ]; then
  echo "ERROR: Neither tlsx nor openssl found in PATH." | tee -a "$OUT"
  exit 1
fi

# ── Helper: check HSTS header ─────────────────────────────────────────────────
check_hsts(){
  local target_host="$1"
  local hsts
  hsts=$(curl -sk -m 10 -I "https://${target_host}/" 2>/dev/null \
         | grep -i '^strict-transport-security:' | head -1)
  if [ -z "$hsts" ]; then
    warn "HSTS header missing for ${target_host}"
  else
    ok  "HSTS present: ${hsts}"
  fi
}

# ── Helper: weak cipher check ─────────────────────────────────────────────────
check_weak_cipher(){
  local cipher="$1"
  if echo "$cipher" | grep -qiE 'RC4|DES|3DES|NULL|EXPORT|ANON|MD5'; then
    hit "Weak/deprecated cipher: $cipher"
    return 0
  fi
  return 1
}

# ── Helper: flag deprecated TLS versions ──────────────────────────────────────
check_tls_version(){
  local ver="$1"
  case "$ver" in
    *1.0*|*tls10*|*TLSv1.0*)
      hit "Deprecated TLS 1.0 in use: $ver" ;;
    *1.1*|*tls11*|*TLSv1.1*)
      hit "Deprecated TLS 1.1 in use: $ver" ;;
    *1.2*|*tls12*|*TLSv1.2*)
      ok  "TLS 1.2 (acceptable): $ver" ;;
    *1.3*|*tls13*|*TLSv1.3*)
      ok  "TLS 1.3 (modern): $ver" ;;
    *)
      warn "Unknown TLS version: $ver" ;;
  esac
}

# ── Helper: process a single host's cert data ──────────────────────────────────
process_cert_data(){
  local target_host="$1"
  local san_list="$2"      # space/newline-separated
  local cn="$3"
  local tls_ver="$4"
  local cipher="$5"
  local expired="$6"       # "true"/"false"/""
  local self_signed="$7"   # "true"/"false"/""
  local not_before="$8"
  local not_after="$9"
  local issuer="${10}"

  log "--- Host: $target_host ---"
  log "  CN: $cn"
  log "  Issuer: $issuer"
  log "  Not Before: $not_before"
  log "  Not After:  $not_after"
  log "  TLS Version: $tls_ver"
  log "  Cipher: $cipher"

  # Expired
  if [ "$expired" = "true" ]; then
    hit "EXPIRED CERTIFICATE — $target_host (expired: $not_after)"
  fi

  # Self-signed
  if [ "$self_signed" = "true" ]; then
    hit "SELF-SIGNED CERTIFICATE — $target_host (no trusted CA)"
  fi

  # TLS version
  [ -n "$tls_ver" ] && check_tls_version "$tls_ver"

  # Cipher
  [ -n "$cipher" ] && check_weak_cipher "$cipher"

  # SAN processing
  local san_count=0
  local new_sans=()
  while IFS= read -r san; do
    san=$(echo "$san" | tr -d '[:space:]')
    [ -z "$san" ] && continue
    san_count=$((san_count + 1))

    # Strip DNS: prefix if present
    san_clean=$(echo "$san" | sed 's/^DNS://i' | tr '[:upper:]' '[:lower:]')

    # Collect for output file (deduplicated)
    if ! grep -qxF "$san_clean" "$TLS_SANS_FILE" 2>/dev/null; then
      echo "$san_clean" >> "$TLS_SANS_FILE"
      new_sans+=("$san_clean")
    fi

    # Flag SANs different from target domain
    local target_base
    target_base=$(echo "$DOMAIN" | tr '[:upper:]' '[:lower:]')
    if ! echo "$san_clean" | grep -qE "(^|\.)${target_base//./\\.}$"; then
      # Different from target — cross-tenant / shared hosting signal
      warn "SAN domain differs from target (shared hosting/cross-tenant?): $san_clean"
    fi
  done <<< "$san_list"

  log "  SANs found: $san_count"

  # Wildcard + many SANs → info leak
  if echo "$cn" | grep -q '^\*\.'; then
    if [ "$san_count" -gt 20 ]; then
      hit "Wildcard cert with $san_count SANs — significant subdomain info leak"
    elif [ "$san_count" -gt 5 ]; then
      warn "Wildcard cert with $san_count SANs — moderate subdomain info leak"
    fi
  fi

  # Report newly discovered SANs
  if [ ${#new_sans[@]} -gt 0 ]; then
    info_hit "New SAN domains discovered (written to tls_sans.txt):"
    for s in "${new_sans[@]}"; do
      info_hit "  → $s"
    done
  fi

  # HSTS check (only if single-host mode and port 443)
  if [ -n "${HOST:-}" ]; then
    check_hsts "$target_host"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODE A: tlsx available
# ═══════════════════════════════════════════════════════════════════════════════
if [ -n "$TLSX_BIN" ]; then
  log "Tool: tlsx ($(tlsx -version 2>&1 | head -1 | tr -d '\n' || echo 'unknown version'))"

  TLSX_OUT="$OUT_DIR/${SLUG}_tlsx_raw.json"

  if [ -n "$LIST_FILE" ]; then
    log "Running tlsx in bulk mode on: $LIST_FILE"
    "$TLSX_BIN" -l "$LIST_FILE" \
      -san -cn -so -tls-version -cipher -expired -self-signed -mismatched \
      -json -silent 2>/dev/null > "$TLSX_OUT" || true
  else
    log "Running tlsx on: $HOST"
    echo "$HOST" | "$TLSX_BIN" \
      -san -cn -so -tls-version -cipher -expired -self-signed -mismatched \
      -json -silent 2>/dev/null > "$TLSX_OUT" || true
  fi

  # Parse JSON output line by line (tlsx outputs one JSON object per line)
  if [ -s "$TLSX_OUT" ]; then
    while IFS= read -r json_line; do
      [ -z "$json_line" ] && continue

      # Extract fields with python (available on macOS/Linux) or jq
      if command -v python3 &>/dev/null; then
        _host=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('host',''))" 2>/dev/null)
        _cn=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('subject_cn',''))" 2>/dev/null)
        _sans=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(d.get('subject_an',d.get('san',[]))))" 2>/dev/null)
        _tls=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tls_version',''))" 2>/dev/null)
        _cipher=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('cipher',''))" 2>/dev/null)
        _expired=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('expired',False)).lower())" 2>/dev/null)
        _self=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(str(d.get('self_signed',False)).lower())" 2>/dev/null)
        _not_before=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('not_before',''))" 2>/dev/null)
        _not_after=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('not_after',''))" 2>/dev/null)
        _issuer=$(echo "$json_line" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('issuer_cn',''))" 2>/dev/null)
      elif command -v jq &>/dev/null; then
        _host=$(echo "$json_line" | jq -r '.host // ""')
        _cn=$(echo "$json_line" | jq -r '.subject_cn // ""')
        _sans=$(echo "$json_line" | jq -r '(.subject_an // .san // []) | .[]')
        _tls=$(echo "$json_line" | jq -r '.tls_version // ""')
        _cipher=$(echo "$json_line" | jq -r '.cipher // ""')
        _expired=$(echo "$json_line" | jq -r '(.expired // false) | tostring | ascii_downcase')
        _self=$(echo "$json_line" | jq -r '(.self_signed // false) | tostring | ascii_downcase')
        _not_before=$(echo "$json_line" | jq -r '.not_before // ""')
        _not_after=$(echo "$json_line" | jq -r '.not_after // ""')
        _issuer=$(echo "$json_line" | jq -r '.issuer_cn // ""')
      else
        log "WARN: neither python3 nor jq found — writing raw JSON to $TLSX_OUT for manual review"
        break
      fi

      # For bulk mode, update DOMAIN for cross-tenant SAN comparison
      if [ -n "$LIST_FILE" ]; then
        DOMAIN=$(echo "$_host" | cut -d: -f1)
      fi

      process_cert_data \
        "$_host" "$_sans" "$_cn" "$_tls" "$_cipher" \
        "$_expired" "$_self" "$_not_before" "$_not_after" "$_issuer"

      # HSTS for each bulk host
      if [ -n "$LIST_FILE" ]; then
        check_hsts "$(echo "$_host" | cut -d: -f1)"
      fi
    done < "$TLSX_OUT"
  else
    log "WARN: tlsx produced no output for $INPUT (host unreachable or TLS not available)"
  fi

# ═══════════════════════════════════════════════════════════════════════════════
# MODE B: openssl fallback (single host only)
# ═══════════════════════════════════════════════════════════════════════════════
else
  log "Tool: openssl (tlsx not available)"

  if [ -n "$LIST_FILE" ]; then
    log "Bulk mode requires tlsx; processing each host with openssl..."
    while IFS= read -r raw_host; do
      [ -z "$raw_host" ] && continue
      fhost=$(echo "$raw_host" | sed -E 's|^https?://||' | cut -d/ -f1)
      fport=$(echo "$fhost" | grep -oP ':\K\d+' || echo "443")
      fhost_name=$(echo "$fhost" | cut -d: -f1)
      [ -z "$fport" ] && fport=443
      DOMAIN="$fhost_name"

      log "Processing: $fhost_name:$fport"
      CERT_RAW=$("$OPENSSL_BIN" s_client \
        -connect "${fhost_name}:${fport}" \
        -servername "$fhost_name" \
        </dev/null 2>/dev/null || true)

      if [ -z "$CERT_RAW" ]; then
        log "WARN: openssl could not connect to $fhost_name:$fport"
        continue
      fi

      # Parse from s_client output
      CERT_TEXT=$(echo "$CERT_RAW" | "$OPENSSL_BIN" x509 -noout -text 2>/dev/null || true)
      _cn=$(echo "$CERT_TEXT" | grep -oP '(?<=CN\s=\s)[^\n,]+' | head -1 || true)
      _issuer=$(echo "$CERT_TEXT" | grep 'Issuer:' | head -1 | sed 's/.*Issuer://' | xargs || true)
      _not_before=$(echo "$CERT_TEXT" | grep 'Not Before' | sed 's/.*Not Before\s*:\s*//' | xargs || true)
      _not_after=$(echo "$CERT_TEXT"  | grep 'Not After'  | sed 's/.*Not After\s*:\s*//'  | xargs || true)
      _sans=$(echo "$CERT_TEXT" | grep -A1 'Subject Alternative Name' | tail -1 \
              | tr ',' '\n' | grep -oP '(?<=DNS:)[^\s,]+' || true)
      _tls=$(echo "$CERT_RAW" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1 || true)
      _cipher=$(echo "$CERT_RAW" | grep -oP 'Cipher\s*:\s*\K\S+' | head -1 || true)

      # Expired: compare dates
      _expired="false"
      if [ -n "$_not_after" ]; then
        expire_epoch=$(date -d "$_not_after" +%s 2>/dev/null \
                       || date -j -f "%b %d %T %Y %Z" "$_not_after" +%s 2>/dev/null || echo 0)
        now_epoch=$(date +%s)
        [ "$expire_epoch" -lt "$now_epoch" ] && _expired="true"
      fi

      # Self-signed: issuer == subject
      _self="false"
      _subject=$(echo "$CERT_TEXT" | grep 'Subject:' | head -1 || true)
      _issuer_line=$(echo "$CERT_TEXT" | grep 'Issuer:' | head -1 || true)
      [ "$_subject" = "$_issuer_line" ] && _self="true"

      process_cert_data \
        "$fhost_name" "$_sans" "$_cn" "$_tls" "$_cipher" \
        "$_expired" "$_self" "$_not_before" "$_not_after" "$_issuer"

      check_hsts "$fhost_name"
    done < "$LIST_FILE"

  else
    # Single host
    log "Running openssl s_client on: $HOST:$PORT"
    CERT_RAW=$("$OPENSSL_BIN" s_client \
      -connect "${DOMAIN}:${PORT}" \
      -servername "$DOMAIN" \
      </dev/null 2>/dev/null || true)

    if [ -z "$CERT_RAW" ]; then
      log "WARN: openssl could not connect to ${DOMAIN}:${PORT} — host unreachable or no TLS"
      exit 0
    fi

    CERT_TEXT=$(echo "$CERT_RAW" | "$OPENSSL_BIN" x509 -noout -text 2>/dev/null || true)

    _cn=$(echo "$CERT_TEXT" | grep -oP '(?<=CN\s=\s)[^\n,]+' | head -1 || true)
    _issuer=$(echo "$CERT_TEXT" | grep 'Issuer:' | head -1 | sed 's/.*Issuer://' | xargs || true)
    _not_before=$(echo "$CERT_TEXT" | grep 'Not Before' | sed 's/.*Not Before\s*:\s*//' | xargs || true)
    _not_after=$(echo "$CERT_TEXT"  | grep 'Not After'  | sed 's/.*Not After\s*:\s*//'  | xargs || true)
    _sans=$(echo "$CERT_TEXT" | grep -A1 'Subject Alternative Name' | tail -1 \
            | tr ',' '\n' | grep -oP '(?<=DNS:)[^\s,]+' || true)
    _tls=$(echo "$CERT_RAW" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1 || true)
    _cipher=$(echo "$CERT_RAW" | grep -oP 'Cipher\s*:\s*\K\S+' | head -1 || true)

    # Expired
    _expired="false"
    if [ -n "$_not_after" ]; then
      expire_epoch=$(date -d "$_not_after" +%s 2>/dev/null \
                     || date -j -f "%b %d %T %Y %Z" "$_not_after" +%s 2>/dev/null || echo 0)
      now_epoch=$(date +%s)
      [ "$expire_epoch" -lt "$now_epoch" ] && _expired="true"
    fi

    # Self-signed
    _self="false"
    _subject_line=$(echo "$CERT_TEXT" | grep 'Subject:' | head -1 || true)
    _issuer_line=$(echo "$CERT_TEXT" | grep 'Issuer:' | head -1 || true)
    [ "$_subject_line" = "$_issuer_line" ] && _self="true"

    process_cert_data \
      "$DOMAIN" "$_sans" "$_cn" "$_tls" "$_cipher" \
      "$_expired" "$_self" "$_not_before" "$_not_after" "$_issuer"

    check_hsts "$DOMAIN"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
SAN_COUNT=$(wc -l < "$TLS_SANS_FILE" 2>/dev/null || echo 0)
log ""
log "=== Summary ==="
log "  Output:        $OUT"
log "  SAN domains:   $TLS_SANS_FILE ($SAN_COUNT entries total)"
log "  Feed tls_sans.txt to: hunt-subdomain-takeover.sh / subdomain recon"
log ""
log "Severity legend: 🔴 HIGH  🟡 MEDIUM/LOW  🟣 INFO  🟢 OK"
