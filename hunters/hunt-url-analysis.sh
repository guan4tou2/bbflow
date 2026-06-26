#!/usr/bin/env bash
# hunt-url-analysis.sh — unfurl URL pattern analysis + anew delta tracking
#
# 用途：對已收集的 URL 做結構化分析，萃取高價值 domain/path/param/value pattern。
# 不做主動爬蟲；吃 sibling hunter 輸出（wayback / katana / gau）作為輸入。
#
# Usage:
#   hunt-url-analysis.sh <target_url>
#   OUT_DIR=/path/to/collected_urls hunt-url-analysis.sh https://target.com
#
# 輸入（從 OUT_DIR 自動讀取）：
#   $OUT_DIR/*katana*.txt / $OUT_DIR/*wayback*.txt / $OUT_DIR/*gau*.txt
#   及任何 $OUT_DIR/all_urls.txt
#
# 輸出：
#   $OUT_DIR/unfurl_domains.txt   — unique subdomains
#   $OUT_DIR/unfurl_paths.txt     — unique paths
#   $OUT_DIR/unfurl_keys.txt      — unique param names
#   $OUT_DIR/unfurl_pairs.txt     — domain:path endpoint map
#   $OUT_DIR/url_analysis_prev.txt — anew 歷史基準（跨 run 追蹤新發現）
#   🔴 高價值 param/extension → stdout，由 bbflow 彙整

set -uo pipefail

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <target_url>"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')
OUT_DIR="${OUT_DIR:-/tmp/bb-url-analysis-$$}"
mkdir -p "$OUT_DIR"

SLUG=$(echo "$DOMAIN" | tr '.' '_')
SUMMARY="$OUT_DIR/url_analysis_${SLUG}.txt"
: > "$SUMMARY"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$SUMMARY"; }
hit(){ echo "🔴 $*" | tee -a "$SUMMARY"; }
info_hit(){ echo "🟡 $*" | tee -a "$SUMMARY"; }

# ── tool check ────────────────────────────────────────────────────────────────
UNFURL="$(command -v unfurl 2>/dev/null || echo '')"
ANEW="$(command -v anew   2>/dev/null || echo '')"

[ -z "$UNFURL" ] && log "  [warn] unfurl not found — go install github.com/tomnomnom/unfurl@latest"
[ -z "$ANEW"   ] && log "  [warn] anew not found   — go install github.com/tomnomnom/anew@latest"

log "=== URL analysis: $TARGET ==="

# ── collect input URLs from sibling hunter outputs ────────────────────────────
COMBINED="$OUT_DIR/unfurl_input.txt"
: > "$COMBINED"

INPUT_COUNT=0
for f in \
    "$OUT_DIR/all_urls.txt" \
    "$OUT_DIR/katana.txt" \
    "$OUT_DIR/gau.txt" \
    "$OUT_DIR/wayback.txt" \
    "$OUT_DIR/cdx.txt" \
    "$OUT_DIR"/waymore_*/urls.txt \
    "$OUT_DIR"/paramspider*.txt \
    "$OUT_DIR"/hakrawler.txt \
    "$OUT_DIR"/param_urls.txt \
    "$OUT_DIR"/param_raw.txt; do
    [ -f "$f" ] && [ -s "$f" ] && { cat "$f" >> "$COMBINED"; INPUT_COUNT=$((INPUT_COUNT + 1)); }
done

# grep fallback: scan any *.txt in OUT_DIR containing http
if [ "$INPUT_COUNT" -eq 0 ]; then
    grep -rlE 'https?://' "$OUT_DIR"/*.txt 2>/dev/null | head -10 | while IFS= read -r f; do
        grep -Eo 'https?://[^ ]+' "$f" >> "$COMBINED" || true
    done
fi

sort -u "$COMBINED" -o "$COMBINED"
TOTAL=$(wc -l < "$COMBINED" | tr -d ' ')
log "  input: $TOTAL unique URLs (from $INPUT_COUNT source files)"

if [ "$TOTAL" -eq 0 ]; then
    log "  No URLs found in OUT_DIR=$OUT_DIR — run wayback/katana/gau hunters first"
    exit 0
fi

if [ -z "$UNFURL" ]; then
    log "  unfurl not available — skipping analysis"
    exit 0
fi

# ── unfurl extraction ─────────────────────────────────────────────────────────
log "  Running unfurl extractions..."

"$UNFURL" -u domains < "$COMBINED" | sort -u > "$OUT_DIR/unfurl_domains.txt" 2>/dev/null || true
"$UNFURL" -u paths   < "$COMBINED" | sort -u > "$OUT_DIR/unfurl_paths.txt"   2>/dev/null || true
"$UNFURL" -u keys    < "$COMBINED" | sort -u > "$OUT_DIR/unfurl_keys.txt"    2>/dev/null || true
"$UNFURL" -u values  < "$COMBINED" | sort -u > "$OUT_DIR/unfurl_values.txt"  2>/dev/null || true
"$UNFURL" format '%d:%P' < "$COMBINED" | sort -u > "$OUT_DIR/unfurl_pairs.txt" 2>/dev/null || true

DOM_COUNT=$(wc -l < "$OUT_DIR/unfurl_domains.txt" | tr -d ' ')
PATH_COUNT=$(wc -l < "$OUT_DIR/unfurl_paths.txt"  | tr -d ' ')
KEY_COUNT=$(wc -l  < "$OUT_DIR/unfurl_keys.txt"   | tr -d ' ')
VAL_COUNT=$(wc -l  < "$OUT_DIR/unfurl_values.txt" | tr -d ' ')

log "  domains=$DOM_COUNT  paths=$PATH_COUNT  params=$KEY_COUNT  values=$VAL_COUNT"

# ── anew delta (track new findings vs previous runs) ─────────────────────────
PREV="$OUT_DIR/url_analysis_prev.txt"
NEW_PAIRS=""
if [ -n "$ANEW" ]; then
    NEW_PAIRS=$(cat "$OUT_DIR/unfurl_pairs.txt" | "$ANEW" "$PREV" 2>/dev/null || true)
    NEW_COUNT=$(echo "$NEW_PAIRS" | grep -c '.' 2>/dev/null || echo 0)
    log "  anew: $NEW_COUNT new domain:path pairs since last run"
else
    NEW_PAIRS=$(cat "$OUT_DIR/unfurl_pairs.txt")
fi

# ── flag: interesting parameter names ────────────────────────────────────────
HIGH_PARAMS_RE='api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|app[_-]?secret'
HIGH_PARAMS_RE+='|token|auth[_-]?token|bearer|jwt|session[_-]?id|session[_-]?key'
HIGH_PARAMS_RE+='|password|passwd|pass|credential|private[_-]?key'
HIGH_PARAMS_RE+='|admin|debug|test|internal|dev[_-]?mode'

MED_PARAMS_RE='redirect|redirect_uri|redirect_url|return|return_url|next|callback|forward|destination|target|url|goto'
MED_PARAMS_RE+='|auth|oauth|sso|saml|login|signin|token'
MED_PARAMS_RE+='|file|path|dir|folder|include|require|load|template|page|view'

echo "" >> "$SUMMARY"
echo "## Flagged Parameters" >> "$SUMMARY"

HIGH_PARAM_HITS=$(grep -iE "^($HIGH_PARAMS_RE)$" "$OUT_DIR/unfurl_keys.txt" 2>/dev/null || true)
MED_PARAM_HITS=$(grep -iE "^($MED_PARAMS_RE)$"  "$OUT_DIR/unfurl_keys.txt" 2>/dev/null || true)

if [ -n "$HIGH_PARAM_HITS" ]; then
    while IFS= read -r param; do
        [ -z "$param" ] && continue
        # find example URLs with this param
        EXAMPLE=$(grep -m1 "[?&]${param}=" "$COMBINED" 2>/dev/null || echo "(no example)")
        hit "[PARAM-HIGH] ?${param}= found → ${EXAMPLE}"
    done <<< "$HIGH_PARAM_HITS"
else
    log "  No high-risk param names found"
fi

if [ -n "$MED_PARAM_HITS" ]; then
    while IFS= read -r param; do
        [ -z "$param" ] && continue
        EXAMPLE=$(grep -m1 "[?&]${param}=" "$COMBINED" 2>/dev/null || echo "(no example)")
        info_hit "[PARAM-MED] ?${param}= → ${EXAMPLE}"
    done <<< "$MED_PARAM_HITS"
fi

# ── flag: interesting file extensions in paths ────────────────────────────────
HIGH_EXT_RE='\.(sql|bak|zip|tar\.gz|tar\.bz2|tgz|env|config|cfg|pem|key|pfx|p12)$'
MED_EXT_RE='\.(xml|json|yml|yaml|log|txt|php|asp|aspx|jsp|cfm|cgi|pl|conf|ini|inc)$'

echo "" >> "$SUMMARY"
echo "## Flagged File Extensions" >> "$SUMMARY"

HIGH_EXT_HITS=$(grep -iE "$HIGH_EXT_RE" "$OUT_DIR/unfurl_paths.txt" 2>/dev/null | head -20 || true)
MED_EXT_HITS=$(grep -iE "$MED_EXT_RE"  "$OUT_DIR/unfurl_paths.txt" 2>/dev/null | head -20 || true)

if [ -n "$HIGH_EXT_HITS" ]; then
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        EXAMPLE=$(grep -m1 "$path" "$COMBINED" 2>/dev/null || echo "$TARGET$path")
        hit "[EXT-HIGH] $path → ${EXAMPLE}"
    done <<< "$HIGH_EXT_HITS"
else
    log "  No high-risk file extensions found"
fi

if [ -n "$MED_EXT_HITS" ]; then
    while IFS= read -r path; do
        [ -z "$path" ] && continue
        info_hit "[EXT-MED] $path"
    done <<< "$MED_EXT_HITS"
fi

# ── flag: interesting values (tokens, UUIDs, emails, base64) ─────────────────
echo "" >> "$SUMMARY"
echo "## Interesting Values" >> "$SUMMARY"

INTERESTING_VALS=$(grep -iE \
    '[0-9a-f]{32,}|[A-Za-z0-9+/]{40,}={0,2}|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    "$OUT_DIR/unfurl_values.txt" 2>/dev/null | head -20 || true)

if [ -n "$INTERESTING_VALS" ]; then
    while IFS= read -r val; do
        [ -z "$val" ] && continue
        info_hit "[VALUE] suspicious value: $val"
    done <<< "$INTERESTING_VALS"
else
    log "  No suspicious values found"
fi

# ── new domain:path pairs summary ─────────────────────────────────────────────
if [ -n "$NEW_PAIRS" ]; then
    NEW_EXT_HITS=$(echo "$NEW_PAIRS" | grep -iE '\.(sql|bak|zip|env|config|pem|key)' || true)
    NEW_ADMIN_HITS=$(echo "$NEW_PAIRS" | grep -iE '/(admin|api|internal|debug|graphql|swagger)' || true)

    [ -n "$NEW_EXT_HITS" ] && while IFS= read -r pair; do
        hit "[NEW] $pair"
    done <<< "$NEW_EXT_HITS"

    [ -n "$NEW_ADMIN_HITS" ] && while IFS= read -r pair; do
        info_hit "[NEW-PATH] $pair"
    done <<< "$NEW_ADMIN_HITS"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo "" >> "$SUMMARY"
log "=== done ==="
log "  Files:"
log "    $OUT_DIR/unfurl_domains.txt  ($DOM_COUNT domains)"
log "    $OUT_DIR/unfurl_paths.txt    ($PATH_COUNT paths)"
log "    $OUT_DIR/unfurl_keys.txt     ($KEY_COUNT param names)"
log "    $OUT_DIR/unfurl_values.txt   ($VAL_COUNT values)"
log "    $OUT_DIR/unfurl_pairs.txt    (domain:path endpoint map)"
log "    $SUMMARY                     (this report)"
