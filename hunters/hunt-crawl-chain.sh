#!/usr/bin/env bash
# hunt-crawl-chain.sh — 完整 URL/param discovery + fuzzing 鏈
# 比 hunt-param-fuzz.sh 更完整：加入 paramspider + arjun + 多層 fallback
#
# 鏈路：
#   [1] katana        — 動態 JS-aware crawl（深度 3, headless）
#   [2] gau           — wayback + otx + commoncrawl + urlscan 歷史 URL
#   [3] waybackurls   — gau fallback
#   [4] paramspider   — 從 Wayback 抽 param-only URLs（超便宜）
#   [5] hakrawler     — (optional) SPA 快速 crawl
#   [6] 合併 → uro 去重（相同 param pattern 只留一筆）
#   [7] gf 分類 → xss/sqli/ssrf/lfi/ssti/redirect/idor
#   [8] arjun         — 對每個 endpoint 找隱藏 param
#   [9] nuclei DAST   — 按 gf 分類跑對應漏洞 templates
#   [10] dalfox       — xss.txt 的 URL 深度 XSS scan
#
# Usage:
#   OUT_DIR=/path hunt-crawl-chain.sh https://target
#   DEPTH=5 hunt-crawl-chain.sh https://target       # 更深的 katana crawl
#   FAST=1 hunt-crawl-chain.sh https://target        # 跳過 arjun + dalfox
#
# 環境變數（從 bbflow 繼承）：
#   NUCLEI_COMMUNITY / SECLISTS / GAU_CONFIG / DALFOX_BLIND_URL

set -uo pipefail

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-crawl-chain-$$}"
mkdir -p "$OUT_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# 工具定位
NUCLEI="$TOOLS_DIR/nuclei"
[ ! -x "$NUCLEI" ] && NUCLEI="$(command -v nuclei 2>/dev/null || echo '')"
KATANA="$(command -v katana 2>/dev/null || echo '')"
GAU="$(command -v gau 2>/dev/null || echo '')"
WAYBACK="$(command -v waybackurls 2>/dev/null || echo '')"
PARAMSPIDER="$(command -v paramspider 2>/dev/null || echo '')"
HAKRAWLER="$(command -v hakrawler 2>/dev/null || echo '')"
URO="$(command -v uro 2>/dev/null || echo '')"
GF="$(command -v gf 2>/dev/null || echo '')"
ARJUN="$(command -v arjun 2>/dev/null || echo '')"
DALFOX="$(command -v dalfox 2>/dev/null || echo '')"

DEPTH="${DEPTH:-3}"
FAST="${FAST:-0}"

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
ALL_URLS="$OUT_DIR/all_urls.txt"
SUMMARY="$OUT_DIR/summary.txt"
: > "$ALL_URLS"
: > "$SUMMARY"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUMMARY"; }
hit(){ echo "🔴 $*" | tee -a "$SUMMARY"; }

log "=== crawl-chain: $TARGET (depth=$DEPTH, fast=$FAST) ==="

# ═══════════════════════════════════════════════════════════════
# [1] katana — 動態 crawl (JS-aware)
# ═══════════════════════════════════════════════════════════════
if [ -n "$KATANA" ]; then
  log "[1/10] katana crawl (depth=$DEPTH, headless js-crawl)..."
  "$KATANA" -u "$TARGET" \
    -d "$DEPTH" \
    -jc -js-crawl \
    -kf all \
    -aff \
    -ct 8m \
    -c 10 \
    -rl 150 \
    -silent \
    -o "$OUT_DIR/katana.txt" 2>/dev/null || true
  K=$(wc -l < "$OUT_DIR/katana.txt" 2>/dev/null | tr -d ' ')
  log "    katana: $K URLs"
  cat "$OUT_DIR/katana.txt" >> "$ALL_URLS" 2>/dev/null || true
else
  log "[1/10] katana skipped (not installed — brew install katana)"
fi

# ═══════════════════════════════════════════════════════════════
# [2] gau — wayback + otx + commoncrawl + urlscan
# ═══════════════════════════════════════════════════════════════
if [ -n "$GAU" ]; then
  log "[2/10] gau (wayback+otx+commoncrawl+urlscan, subdomains=yes)..."
  GAU_CONF="${GAU_CONFIG:-$TOOLS_DIR/configs/gau.toml}"
  if [ -f "$GAU_CONF" ]; then
    echo "$DOMAIN" | "$GAU" --config "$GAU_CONF" 2>/dev/null > "$OUT_DIR/gau.txt" || true
  else
    echo "$DOMAIN" | "$GAU" \
      --threads 5 \
      --subs \
      --providers wayback,commoncrawl,otx,urlscan \
      --blacklist eot,svg,ttf,woff,png,jpg,gif,ico,css,pdf,mp4,webp \
      2>/dev/null > "$OUT_DIR/gau.txt" || true
  fi
  G=$(wc -l < "$OUT_DIR/gau.txt" 2>/dev/null | tr -d ' ')
  log "    gau: $G URLs"
  cat "$OUT_DIR/gau.txt" >> "$ALL_URLS" 2>/dev/null || true
else
  log "[2/10] gau skipped (not installed — go install github.com/lc/gau/v2/cmd/gau@latest)"
fi

# ═══════════════════════════════════════════════════════════════
# [3] waybackurls fallback
# ═══════════════════════════════════════════════════════════════
if [ -z "$GAU" ] && [ -n "$WAYBACK" ]; then
  log "[3/10] waybackurls (gau fallback)..."
  echo "$DOMAIN" | "$WAYBACK" 2>/dev/null > "$OUT_DIR/wayback.txt" || true
  W=$(wc -l < "$OUT_DIR/wayback.txt" 2>/dev/null | tr -d ' ')
  log "    wayback: $W URLs"
  cat "$OUT_DIR/wayback.txt" >> "$ALL_URLS" 2>/dev/null || true
elif [ -z "$GAU" ] && [ -z "$WAYBACK" ]; then
  # 純 curl 抓 CDX API（最便宜 fallback）
  log "[3/10] wayback CDX API fallback (curl)..."
  curl -sf --max-time 30 \
    "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}&output=text&fl=original&collapse=urlkey&limit=5000" \
    2>/dev/null > "$OUT_DIR/cdx.txt" || true
  cat "$OUT_DIR/cdx.txt" >> "$ALL_URLS" 2>/dev/null || true
  log "    cdx: $(wc -l < "$OUT_DIR/cdx.txt" | tr -d ' ') URLs"
fi

# ═══════════════════════════════════════════════════════════════
# [4] paramspider — 專抓帶 param 的歷史 URL
# ═══════════════════════════════════════════════════════════════
if [ -n "$PARAMSPIDER" ]; then
  log "[4/10] paramspider (param-only URLs)..."
  (cd "$OUT_DIR" && "$PARAMSPIDER" -d "$DOMAIN" -s 2>/dev/null > paramspider.txt || true)
  [ -s "$OUT_DIR/results/$DOMAIN.txt" ] && cat "$OUT_DIR/results/$DOMAIN.txt" >> "$ALL_URLS"
  [ -s "$OUT_DIR/paramspider.txt" ] && cat "$OUT_DIR/paramspider.txt" >> "$ALL_URLS"
else
  log "[4/10] paramspider skipped (pip3 install paramspider --break-system-packages)"
fi

# ═══════════════════════════════════════════════════════════════
# [5] hakrawler — 快速 SPA crawl（如果裝了）
# ═══════════════════════════════════════════════════════════════
if [ -n "$HAKRAWLER" ]; then
  log "[5/10] hakrawler..."
  echo "$TARGET" | "$HAKRAWLER" -d 2 -u -subs 2>/dev/null > "$OUT_DIR/hakrawler.txt" || true
  H=$(wc -l < "$OUT_DIR/hakrawler.txt" 2>/dev/null | tr -d ' ')
  log "    hakrawler: $H URLs"
  cat "$OUT_DIR/hakrawler.txt" >> "$ALL_URLS" 2>/dev/null || true
fi

# ═══════════════════════════════════════════════════════════════
# [6] merge + uro 去重
# ═══════════════════════════════════════════════════════════════
log "[6/10] merge + dedup..."
sort -u "$ALL_URLS" -o "$ALL_URLS"
TOTAL=$(wc -l < "$ALL_URLS" | tr -d ' ')
log "    merged: $TOTAL URLs"

PARAM_RAW="$OUT_DIR/param_raw.txt"
grep -E '\?' "$ALL_URLS" \
  | grep -viE '\.(css|js|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|pdf|zip|mp4|webp)(\?|$)' \
  | sort -u > "$PARAM_RAW" || true
P=$(wc -l < "$PARAM_RAW" | tr -d ' ')
log "    param URLs: $P"

if [ -n "$URO" ] && [ -s "$PARAM_RAW" ]; then
  "$URO" < "$PARAM_RAW" > "$OUT_DIR/param_urls.txt" 2>/dev/null || cp "$PARAM_RAW" "$OUT_DIR/param_urls.txt"
else
  cp "$PARAM_RAW" "$OUT_DIR/param_urls.txt"
fi
PU=$(wc -l < "$OUT_DIR/param_urls.txt" | tr -d ' ')
log "    after uro dedup: $PU URLs"

# ═══════════════════════════════════════════════════════════════
# [7] gf 分類 — xss / sqli / ssrf / lfi / ssti / redirect / idor
# ═══════════════════════════════════════════════════════════════
if [ -n "$GF" ] && [ -s "$OUT_DIR/param_urls.txt" ]; then
  log "[7/10] gf pattern classification..."
  for PATTERN in xss sqli ssrf lfi ssti redirect idor; do
    [ -f "$HOME/.gf/${PATTERN}.json" ] || continue
    "$GF" "$PATTERN" < "$OUT_DIR/param_urls.txt" > "$OUT_DIR/gf_${PATTERN}.txt" 2>/dev/null || true
    N=$(wc -l < "$OUT_DIR/gf_${PATTERN}.txt" 2>/dev/null | tr -d ' ')
    [ "$N" != "0" ] && log "    gf $PATTERN: $N URLs"
  done
else
  log "[7/10] gf skipped (go install github.com/tomnomnom/gf@latest && gf-patterns)"
fi

# ═══════════════════════════════════════════════════════════════
# [8] arjun — 對 param_urls 去重後的 unique endpoints 找隱藏 param
# ═══════════════════════════════════════════════════════════════
if [ "$FAST" != "1" ] && [ -n "$ARJUN" ] && [ -s "$OUT_DIR/param_urls.txt" ]; then
  log "[8/10] arjun on top 20 unique endpoints..."
  # 抽出 unique paths（不帶 param）
  sed -E 's/\?.*$//' "$OUT_DIR/param_urls.txt" | sort -u | head -20 > "$OUT_DIR/unique_endpoints.txt"
  "$ARJUN" -i "$OUT_DIR/unique_endpoints.txt" \
    -m GET,POST,JSON \
    -t 10 --stable -q \
    -oJ "$OUT_DIR/arjun.json" 2>/dev/null || true
  if [ -s "$OUT_DIR/arjun.json" ]; then
    A=$(python3 -c "import json; d=json.load(open('$OUT_DIR/arjun.json')); print(sum(len(v.get('params',[])) for v in d.values()))" 2>/dev/null || echo 0)
    log "    arjun found: $A hidden params"
    [ "$A" != "0" ] && hit "[P3-MED] arjun hidden params: $A → $OUT_DIR/arjun.json"
  fi
else
  log "[8/10] arjun skipped (FAST=1 or not installed)"
fi

# ═══════════════════════════════════════════════════════════════
# [9] nuclei DAST — 按 gf 分類跑
# ═══════════════════════════════════════════════════════════════
NUCLEI_DAST="${NUCLEI_COMMUNITY:-$HOME/nuclei-templates}/dast/vulnerabilities"
if [ -n "$NUCLEI" ] && [ -d "$NUCLEI_DAST" ]; then
  log "[9/10] nuclei DAST scan..."
  > "$OUT_DIR/dast_hits.txt"
  for PATTERN in xss sqli ssrf lfi ssti redirect; do
    [ -s "$OUT_DIR/gf_${PATTERN}.txt" ] || continue
    DAST_SUB=""
    case "$PATTERN" in
      xss)       DAST_SUB="$NUCLEI_DAST/xss" ;;
      sqli)      DAST_SUB="$NUCLEI_DAST/sqli" ;;
      ssrf)      DAST_SUB="$NUCLEI_DAST/ssrf" ;;
      lfi)       DAST_SUB="$NUCLEI_DAST/lfi" ;;
      ssti)      DAST_SUB="$NUCLEI_DAST/ssti" ;;
      redirect)  DAST_SUB="$NUCLEI_DAST/redirect" ;;
    esac
    [ -d "$DAST_SUB" ] || DAST_SUB="$NUCLEI_DAST"
    log "    nuclei DAST $PATTERN → $(wc -l < $OUT_DIR/gf_${PATTERN}.txt | tr -d ' ') URLs"
    "$NUCLEI" -l "$OUT_DIR/gf_${PATTERN}.txt" \
      -t "$DAST_SUB" \
      -dast \
      -severity low,medium,high,critical \
      -rate-limit 5 \
      -timeout 10 \
      -silent \
      -o "$OUT_DIR/dast_${PATTERN}.txt" 2>/dev/null || true
    [ -s "$OUT_DIR/dast_${PATTERN}.txt" ] && \
      cat "$OUT_DIR/dast_${PATTERN}.txt" >> "$OUT_DIR/dast_hits.txt" && \
      while IFS= read -r L; do hit "DAST [$PATTERN] $L"; done < "$OUT_DIR/dast_${PATTERN}.txt"
  done
  D=$(wc -l < "$OUT_DIR/dast_hits.txt" 2>/dev/null | tr -d ' ')
  log "    DAST total: $D hits"
else
  log "[9/10] nuclei DAST skipped (nuclei 或 dast templates 不存在)"
fi

# ═══════════════════════════════════════════════════════════════
# [10] dalfox — 深度 XSS scan（僅 gf xss 的 URL）
# ═══════════════════════════════════════════════════════════════
if [ "$FAST" != "1" ] && [ -n "$DALFOX" ] && [ -s "$OUT_DIR/gf_xss.txt" ]; then
  log "[10/10] dalfox XSS deep scan..."
  DALFOX_EXTRA=""
  [ -n "${DALFOX_BLIND_URL:-}" ] && DALFOX_EXTRA="-b $DALFOX_BLIND_URL"
  [ -n "${DALFOX_COOKIE:-}" ]    && DALFOX_EXTRA="$DALFOX_EXTRA -C '$DALFOX_COOKIE'"
  head -50 "$OUT_DIR/gf_xss.txt" | "$DALFOX" pipe $DALFOX_EXTRA \
    --skip-bav \
    --silence \
    --no-spinner \
    -o "$OUT_DIR/dalfox.txt" 2>/dev/null || true
  if [ -s "$OUT_DIR/dalfox.txt" ]; then
    X=$(grep -c '^\[V' "$OUT_DIR/dalfox.txt" 2>/dev/null || echo 0)
    log "    dalfox: $X verified XSS"
    [ "$X" != "0" ] && while IFS= read -r L; do hit "DALFOX XSS $L"; done < "$OUT_DIR/dalfox.txt"
  fi
else
  log "[10/10] dalfox skipped (FAST=1 / no XSS candidates / not installed)"
fi

log "=== done — summary: $SUMMARY ==="
echo ""
echo "Files:"
echo "  $OUT_DIR/all_urls.txt       — 所有 crawled URL"
echo "  $OUT_DIR/param_urls.txt     — 有 query param 的 URL (uro 去重)"
echo "  $OUT_DIR/gf_<pattern>.txt   — 按漏洞類型分類"
echo "  $OUT_DIR/arjun.json         — 隱藏 param 發現"
echo "  $OUT_DIR/dast_*.txt         — nuclei DAST 結果"
echo "  $OUT_DIR/dalfox.txt         — dalfox XSS 結果"
