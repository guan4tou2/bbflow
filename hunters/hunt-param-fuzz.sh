#!/usr/bin/env bash
# hunt-param-fuzz.sh — URL/param discovery + nuclei DAST fuzzing
#
# 流程：
#   1. katana 爬頁面（JS-aware，depth 3）
#   2. gau / waybackurls / Wayback CDX API 抓歷史 URL
#   3. uro 去重（相同 param pattern 的 URL 只保留一個）
#   4. 過濾出有 query param 的 URL
#   5. nuclei --dast 跑 XSS / SQLi / SSRF / LFI / SSTI / Open-redirect
#
# Usage:
#   OUT_DIR=/path/to/out hunt-param-fuzz.sh <url>
#   hunt-param-fuzz.sh https://target.com
#
# 輸出：
#   $OUT_DIR/param_urls.txt       — 所有有 param 的 URL
#   $OUT_DIR/fuzz_results.txt     — nuclei hits（原始）
#   🔴 行到 stdout，由 bbflow 彙整進 REPORT

set -uo pipefail

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-param-fuzz-$$}"
mkdir -p "$OUT_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

NUCLEI="$TOOLS_DIR/nuclei"
[ ! -x "$NUCLEI" ] && NUCLEI="$(command -v nuclei 2>/dev/null || echo '')"
KATANA="$(command -v katana 2>/dev/null || echo '')"
GAU="$(command -v gau 2>/dev/null || echo '')"
WAYBACK="$(command -v waybackurls 2>/dev/null || echo '')"
URO="$(command -v uro 2>/dev/null || echo '')"
GF="$(command -v gf 2>/dev/null || echo '')"
QSREPLACE="$(command -v qsreplace 2>/dev/null || echo '')"
NUCLEI_DAST="$HOME/nuclei-templates/dast/vulnerabilities"

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
ALL_URLS="$OUT_DIR/all_urls.txt"
> "$ALL_URLS"

# ── Step 1: katana crawl（JS-aware, headless mode for SPAs）─────
if [ -n "$KATANA" ]; then
  $KATANA -u "$TARGET" \
    -d 3 \
    -jc \
    -js-crawl \
    -kf all \
    -aff \
    -ct 8m \
    -du 10 \
    -silent \
    -o "$OUT_DIR/katana.txt" 2>/dev/null || true
  [ -s "$OUT_DIR/katana.txt" ] && cat "$OUT_DIR/katana.txt" >> "$ALL_URLS"
fi

# ── Step 2: 歷史 URL (gau > waybackurls > CDX fallback) ──────
if [ -n "$GAU" ]; then
  echo "$DOMAIN" | "$GAU" \
    --threads 5 \
    --subs \
    --providers wayback,commoncrawl,otx,urlscan \
    --blacklist eot,svg,ttf,woff,png,jpg,gif,ico,css,pdf,mp4 \
    2>/dev/null >> "$ALL_URLS" || true

elif [ -n "$WAYBACK" ]; then
  echo "$DOMAIN" | "$WAYBACK" 2>/dev/null >> "$ALL_URLS" || true

else
  # Wayback CDX API fallback（不需外部工具）
  curl -sf \
    "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey&limit=5000" \
    2>/dev/null >> "$ALL_URLS" || true
fi

# ── Step 3: filter + deduplicate ─────────────────────────────
PARAM_URLS="$OUT_DIR/param_urls.txt"

grep -E '\?' "$ALL_URLS" \
  | grep -viE '\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip|mp4|webp)(\?|$)' \
  | sort -u \
  > "$OUT_DIR/param_raw.txt" || true

# ── Step 3b: gf pattern extraction（按漏洞類型分類）────────
if [ -n "$GF" ]; then
  for PATTERN in sqli ssrf lfi ssti xss redirect; do
    [ -f "$HOME/.gf/${PATTERN}.json" ] || continue
    grep -E '\?' "$OUT_DIR/param_raw.txt" \
      | "$GF" "$PATTERN" 2>/dev/null \
      > "$OUT_DIR/gf_${PATTERN}.txt" || true
    COUNT=$(wc -l < "$OUT_DIR/gf_${PATTERN}.txt" | tr -d ' ')
    [ "$COUNT" -gt 0 ] && echo "→ gf $PATTERN: $COUNT URLs" >&2
  done
fi

PARAM_COUNT=$(wc -l < "$OUT_DIR/param_raw.txt" | tr -d ' ')

if [ "$PARAM_COUNT" -eq 0 ]; then
  echo "→ no parameterized URLs found" >&2
  exit 0
fi

if [ -n "$URO" ]; then
  "$URO" < "$OUT_DIR/param_raw.txt" > "$PARAM_URLS" 2>/dev/null || cp "$OUT_DIR/param_raw.txt" "$PARAM_URLS"
else
  cp "$OUT_DIR/param_raw.txt" "$PARAM_URLS"
fi

DEDUPED_COUNT=$(wc -l < "$PARAM_URLS" | tr -d ' ')

# ── Step 4: nuclei DAST fuzzing ───────────────────────────────
if [ -z "$NUCLEI" ]; then
  echo "✗ nuclei not found, skipping fuzzing" >&2
  exit 0
fi

if [ ! -d "$NUCLEI_DAST" ]; then
  echo "✗ DAST templates not found at $NUCLEI_DAST" >&2
  echo "  run: nuclei -update-templates" >&2
  exit 0
fi

FUZZ_OUT="$OUT_DIR/fuzz_results.txt"
> "$FUZZ_OUT"

# 使用 gf 分類的 URL 做針對性掃描（更精準，減少 false positive）
run_dast() {
  local URLS="$1"; local TEMPLATES="$2"
  [ -s "$URLS" ] || return
  "$NUCLEI" -l "$URLS" $TEMPLATES \
    -dast -rate-limit 8 -timeout 15 -silent \
    -o "$FUZZ_OUT" 2>/dev/null || true
}

# 全量掃描（兜底）
run_dast "$PARAM_URLS" \
  "-t $NUCLEI_DAST/xss/reflected-xss.yaml \
   -t $NUCLEI_DAST/sqli/sqli-error-based.yaml \
   -t $NUCLEI_DAST/sqli/time-based-sqli.yaml \
   -t $NUCLEI_DAST/ssrf/response-ssrf.yaml \
   -t $NUCLEI_DAST/ssrf/blind-ssrf.yaml \
   -t $NUCLEI_DAST/lfi/linux-lfi-fuzz.yaml \
   -t $NUCLEI_DAST/lfi/windows-lfi-fuzz.yaml \
   -t $NUCLEI_DAST/ssti/reflection-ssti.yaml \
   -t $NUCLEI_DAST/redirect \
   -t $NUCLEI_DAST/crlf"

# gf 針對性補掃（若有分類結果）
[ -s "$OUT_DIR/gf_sqli.txt" ] && \
  run_dast "$OUT_DIR/gf_sqli.txt" \
    "-t $NUCLEI_DAST/sqli/sqli-error-based.yaml -t $NUCLEI_DAST/sqli/time-based-sqli.yaml"
[ -s "$OUT_DIR/gf_ssrf.txt" ] && \
  run_dast "$OUT_DIR/gf_ssrf.txt" \
    "-t $NUCLEI_DAST/ssrf/response-ssrf.yaml -t $NUCLEI_DAST/ssrf/blind-ssrf.yaml"
[ -s "$OUT_DIR/gf_lfi.txt" ] && \
  run_dast "$OUT_DIR/gf_lfi.txt" \
    "-t $NUCLEI_DAST/lfi/linux-lfi-fuzz.yaml -t $NUCLEI_DAST/lfi/windows-lfi-fuzz.yaml"
[ -s "$OUT_DIR/gf_ssti.txt" ] && \
  run_dast "$OUT_DIR/gf_ssti.txt" "-t $NUCLEI_DAST/ssti/reflection-ssti.yaml"

# ── Step 5: output hits ───────────────────────────────────────
if [ -s "$FUZZ_OUT" ]; then
  while IFS= read -r line; do
    sev=$(echo "$line" | grep -oE '\[(critical|high|medium|low)\]' | head -1 | tr -d '[]')
    tmpl=$(echo "$line" | grep -oE '^\[[^]]+\]' | head -1 | tr -d '[]')
    url=$(echo "$line" | awk '{print $NF}')
    echo "🔴 FUZZ [$sev] $tmpl → $url"
  done < "$FUZZ_OUT"
else
  echo "→ param-fuzz: $DEDUPED_COUNT URLs tested (katana+gau+wayback), 0 hits" >&2
fi
