#!/usr/bin/env bash
# ============================================================================
# hunt-screenshot.sh — Visual recon via gowitness screenshots
#
# Usage:
#   hunt-screenshot.sh https://target.com     # single target
#   hunt-screenshot.sh                        # bulk: reads $OUT_DIR/live_hosts.txt
#
# Env:
#   OUT_DIR   output directory (required for bulk; default: ./screenshot-out)
#   TIMEOUT   seconds per page (default: 10)
# ============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

TARGET="${1:-}"
OUT_DIR="${OUT_DIR:-./screenshot-out}"
TIMEOUT="${TIMEOUT:-10}"
SCREENSHOT_DIR="$OUT_DIR/screenshots"
DB_FILE="$OUT_DIR/gowitness.sqlite3"

INTERESTING_TITLES="Dashboard|Admin|Login|phpMyAdmin|Kibana|Jenkins|Grafana|Swagger|Portal|Management|Console|Monitor|Webmin|GitLab|Tomcat|Manager"

usage() {
  echo "Usage: $0 [URL|domain]"
  echo "  Single: $0 https://example.com"
  echo "  Bulk:   OUT_DIR=/path/to/out $0   (reads live_hosts.txt)"
  exit 1
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then usage; fi

mkdir -p "$SCREENSHOT_DIR"

GOWITNESS_BIN="$(command -v gowitness 2>/dev/null || true)"
CHROME_FLAGS="--disable-gpu --no-sandbox --disable-dev-shm-usage"

# ── Fallback: curl title grabber ─────────────────────────────────────────────
grab_titles_curl() {
  local input_file="$1"
  local title_out="$OUT_DIR/titles.txt"
  echo "[curl-fallback] gowitness not found — grabbing titles only"
  > "$title_out"
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    title=$(curl -sk --max-time "$TIMEOUT" -L "$url" \
      | grep -oiP '(?<=<title>)[^<]+' | head -1 | xargs 2>/dev/null || echo "(no title)")
    echo "$url  |  $title" | tee -a "$title_out"
  done < "$input_file"
  echo "[curl-fallback] titles saved → $title_out"
}

# ── Step 1 / 2: Screenshot ────────────────────────────────────────────────────
if [[ -n "$TARGET" ]]; then
  # Single target mode
  echo "[screenshot] Single target: $TARGET"
  if [[ -n "$GOWITNESS_BIN" ]]; then
    "$GOWITNESS_BIN" scan single \
      --url "$TARGET" \
      --screenshot-path "$SCREENSHOT_DIR" \
      --db-uri "sqlite://$DB_FILE" \
      --timeout "$TIMEOUT" \
      --chrome-flags "$CHROME_FLAGS" 2>&1
  else
    echo "$TARGET" > "$OUT_DIR/_single.txt"
    grab_titles_curl "$OUT_DIR/_single.txt"
    rm -f "$OUT_DIR/_single.txt"
    exit 0
  fi
else
  # Bulk mode
  HOSTS_FILE="${OUT_DIR}/live_hosts.txt"
  if [[ ! -f "$HOSTS_FILE" ]]; then
    echo "[error] Bulk mode requires $HOSTS_FILE (run hunt-portscan or httpx first)"
    usage
  fi
  HOST_COUNT=$(wc -l < "$HOSTS_FILE" | tr -d ' ')
  echo "[screenshot] Bulk mode: $HOST_COUNT hosts from $HOSTS_FILE"
  if [[ -n "$GOWITNESS_BIN" ]]; then
    # Step 3: scan with --write-db for queryable results
    "$GOWITNESS_BIN" scan file \
      --input-file "$HOSTS_FILE" \
      --screenshot-path "$SCREENSHOT_DIR" \
      --db-uri "sqlite://$DB_FILE" \
      --timeout "$TIMEOUT" \
      --chrome-flags "$CHROME_FLAGS" \
      --threads 3 2>&1
  else
    grab_titles_curl "$HOSTS_FILE"
    exit 0
  fi
fi

# ── Step 4 / 5 / 6: Summary + flagging ───────────────────────────────────────
echo ""
echo "══════════════════════════════════════════"
echo " SCREENSHOT SUMMARY"
echo "══════════════════════════════════════════"

TOTAL_SHOTS=$(find "$SCREENSHOT_DIR" -name "*.png" 2>/dev/null | wc -l | tr -d ' ')
echo "Total screenshots : $TOTAL_SHOTS"
echo "DB               : $DB_FILE"
echo ""

if [[ -f "$DB_FILE" ]] && command -v sqlite3 &>/dev/null; then
  echo "── Response code breakdown ──"
  sqlite3 "$DB_FILE" \
    "SELECT response_code, COUNT(*) as cnt FROM urls GROUP BY response_code ORDER BY cnt DESC;" \
    2>/dev/null | awk -F'|' '{
      code=$1; cnt=$2
      if (code >= 500)       flag="🔴"
      else if (code == 404)  flag="⬜"
      else if (code == 200)  flag="🟢"
      else                   flag="🔵"
      printf "  %s  HTTP %s  (%s)\n", flag, code, cnt
    }'

  echo ""
  echo "── Interesting pages (Step 5 & 6) ──"
  sqlite3 "$DB_FILE" \
    "SELECT final_url, response_code, title FROM urls WHERE title IS NOT NULL AND title != '';" \
    2>/dev/null | while IFS='|' read -r url code title; do
      flag=""
      note=""
      # Step 5: page type flagging
      if echo "$title" | grep -qiE "login|sign.?in|authenticate|auth"; then
        flag="🟡"; note="[login-page]"
      elif echo "$title" | grep -qiE "admin|administrator|management|control.?panel"; then
        flag="🟡"; note="[admin-panel]"
      elif [[ "$code" -ge 500 ]] && echo "$title" | grep -qiE "error|exception|stack|trace|debug"; then
        flag="🔴"; note="[stack-trace]"
      elif echo "$title" | grep -qiE "welcome|default|it works|test page|index of"; then
        flag="🟢"; note="[default-page]"
      fi
      # Step 6: interesting title patterns
      if echo "$title" | grep -qiE "$INTERESTING_TITLES"; then
        flag="${flag:-🟡}"; note="${note:+$note }[interesting-title]"
      fi
      [[ -n "$flag" ]] && printf "  %s  [%s] %s  — %s\n" "$flag" "$code" "$url" "$title"$'\t'"$note"
  done
  echo ""
fi

echo "Screenshots saved → $SCREENSHOT_DIR"
echo "Run: gowitness report serve --db-uri sqlite://$DB_FILE"
