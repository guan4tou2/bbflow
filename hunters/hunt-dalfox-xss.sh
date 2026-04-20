#!/usr/bin/env bash
# hunt-dalfox-xss.sh — XSS hunting: gf filter → dalfox (blind + DOM + stored)
#
# 功能:
#   1. katana + gau 收集 URL
#   2. gf xss pattern filter（只打 xss-prone params）
#   3. dalfox pipe scan:
#      - Reflected XSS（預設 payload）
#      - Blind XSS（需設 DALFOX_BLIND_URL，用 interactsh 或 xss.ht）
#      - 自訂 payload file（DALFOX_PAYLOADS）
#
# Usage:
#   OUT_DIR=/path DALFOX_BLIND_URL=https://your.oast.fun hunt-dalfox-xss.sh <url>
#   OUT_DIR=/path DALFOX_COOKIE="session=xxx" hunt-dalfox-xss.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-dalfox-$$}"
mkdir -p "$OUT_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DALFOX="$(command -v dalfox 2>/dev/null || echo '')"
KATANA="$(command -v katana 2>/dev/null || echo '')"
GAU="$(command -v gau 2>/dev/null || echo '')"
GF="$(command -v gf 2>/dev/null || echo '')"
URO="$(command -v uro 2>/dev/null || echo '')"

[ -z "$DALFOX" ] && { echo "✗ dalfox not found (brew install dalfox)"; exit 0; }

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)

# ── 環境變數設定 ─────────────────────────────────────────────
# 設 DALFOX_BLIND_URL 啟用 blind XSS (e.g. https://xxx.oast.fun 或 https://xss.ht/...)
BLIND_URL="${DALFOX_BLIND_URL:-}"
# 設 DALFOX_COOKIE 做 authenticated 掃描 (e.g. "session=abc123; token=xyz")
COOKIE="${DALFOX_COOKIE:-}"
# 設 DALFOX_HEADERS 加 custom headers (e.g. "Authorization: Bearer xxx")
EXTRA_HEADERS="${DALFOX_HEADERS:-}"
# 自訂 payload 檔案（一行一個 payload）
CUSTOM_PAYLOADS="${DALFOX_PAYLOADS:-$TOOLS_DIR/payloads/xss-custom.txt}"
# 繼承 bbflow export 或自動偵測
if [ -z "${SECLISTS:-}" ]; then
  for _sl in \
    "$HOME/Tools/SecLists" \
    "$(brew --prefix seclists 2>/dev/null)/share/seclists" \
    "/opt/homebrew/share/seclists" \
    "/usr/local/share/seclists" \
    "/usr/share/seclists"; do
    [ -d "$_sl/Discovery/Web-Content" ] && SECLISTS="$_sl" && break
  done
  SECLISTS="${SECLISTS:-}"
fi
SECLISTS_XSS="${SECLISTS:+$SECLISTS/Fuzzing/XSS/XSS-Jhaddix.txt}"

# ── URL collection ──────────────────────────────────────────
ALL_URLS="$OUT_DIR/all_urls.txt"
> "$ALL_URLS"

# 優先用已有的 param-fuzz 結果（避免重複爬取）
SIBLING_PARAMS=$(find "$(dirname "$OUT_DIR")" -name "param_urls.txt" 2>/dev/null | head -1)
if [ -n "$SIBLING_PARAMS" ] && [ -s "$SIBLING_PARAMS" ]; then
  cp "$SIBLING_PARAMS" "$ALL_URLS"
else
  if [ -n "$KATANA" ]; then
    "$KATANA" -u "$TARGET" -d 3 -jc -js-crawl -kf all \
      -ct 5m -du 10 -silent \
      -o "$OUT_DIR/katana.txt" 2>/dev/null || true
    [ -s "$OUT_DIR/katana.txt" ] && cat "$OUT_DIR/katana.txt" >> "$ALL_URLS"
  fi
  if [ -n "$GAU" ]; then
    echo "$DOMAIN" | "$GAU" --threads 5 --subs \
      --blacklist eot,svg,ttf,woff,png,jpg,gif,ico,css,pdf 2>/dev/null >> "$ALL_URLS" || true
  fi
fi

# ── gf xss filter ─────────────────────────────────────────
XSS_URLS="$OUT_DIR/xss_candidates.txt"
if [ -n "$GF" ] && [ -f "$HOME/.gf/xss.json" ]; then
  grep -E '\?' "$ALL_URLS" | sort -u | "$GF" xss 2>/dev/null > "$XSS_URLS" || true
else
  grep -iE '[?&](q|s|search|query|keyword|input|text|content|comment|message|title|name|desc|redirect|url|next|return|callback|data|value|html|body|page|view|template|theme|style|action|ref|source|target)[=]' \
    "$ALL_URLS" | sort -u > "$XSS_URLS" || true
fi

[ -n "$URO" ] && "$URO" < "$XSS_URLS" > "$OUT_DIR/xss_dedup.txt" 2>/dev/null \
  && mv "$OUT_DIR/xss_dedup.txt" "$XSS_URLS" || true

XSS_COUNT=$(wc -l < "$XSS_URLS" | tr -d ' ')
[ "$XSS_COUNT" -eq 0 ] && exit 0

# ── build dalfox flags ─────────────────────────────────────
DALFOX_FLAGS=(
  "--silence"
  "--no-color"
  "--output" "$OUT_DIR/dalfox_raw.txt"
  "--worker" "5"
  "--timeout" "10"
  "--delay" "100"
  "--follow-redirects"
)

# Blind XSS callback
[ -n "$BLIND_URL" ] && DALFOX_FLAGS+=("--blind" "$BLIND_URL")

# Authenticated scan
[ -n "$COOKIE" ] && DALFOX_FLAGS+=("--cookie" "$COOKIE")

# Extra headers (comma-separated "Key: Value" pairs)
[ -n "$EXTRA_HEADERS" ] && DALFOX_FLAGS+=("--header" "$EXTRA_HEADERS")

# Custom payloads
if [ -f "$CUSTOM_PAYLOADS" ]; then
  DALFOX_FLAGS+=("--custom-payload" "$CUSTOM_PAYLOADS")
elif [ -f "$SECLISTS_XSS" ]; then
  DALFOX_FLAGS+=("--custom-payload" "$SECLISTS_XSS")
fi

# ── dalfox scan ─────────────────────────────────────────────
"$DALFOX" pipe "${DALFOX_FLAGS[@]}" < "$XSS_URLS" 2>/dev/null || true

# ── output hits ─────────────────────────────────────────────
[ ! -s "$OUT_DIR/dalfox_raw.txt" ] && exit 0
while IFS= read -r line; do
  echo "$line" | grep -qiE '\[VULN\]|\[POC\]|\[G\]|\[BXSS\]' && echo "🔴 XSS $line"
done < "$OUT_DIR/dalfox_raw.txt" 2>/dev/null || true
