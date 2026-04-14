#!/usr/bin/env bash
# hunt-nxdomain-corpus.sh — 建立歷史 hostname 超集，過濾出 NXDOMAIN 候選
# 來源：Starbucks NXDOMAIN → 內網 SSRF（External Writeups 2026）
#
# 用途：當找到允許控制 Host header 的 proxy / edge gateway 時，
#       把這份 corpus 灌進 Burp Intruder 的 Host header 位置，
#       看 response body 能拿到哪些內部服務。
#
# 來源匯集：
#   1. BBOT passive (若 recon/<target>/bbot/subdomains.txt 存在)
#   2. crt.sh
#   3. waymore（若已安裝）
#   4. 額外輸入檔（-f FILE）
#
# 過濾規則：
#   - dig @1.1.1.1 A + AAAA 都回空 → 候選
#   - 可選：dig @8.8.8.8 第二次驗證（-d 開關）
#
# 用法：
#   ./hunt-nxdomain-corpus.sh target.com
#   ./hunt-nxdomain-corpus.sh target.com -d          # double check with 8.8.8.8
#   ./hunt-nxdomain-corpus.sh target.com -f extra.txt
set -uo pipefail

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <target.com> [-d] [-f extra-file]"; exit 1; }
shift || true

DOUBLE_CHECK=0
EXTRA_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) DOUBLE_CHECK=1; shift;;
    -f) EXTRA_FILE="$2"; shift 2;;
    *) shift;;
  esac
done

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$BASE_DIR/recon/$TARGET/nxdomain}"
mkdir -p "$OUT_DIR"
ALL="$OUT_DIR/historical_all.txt"
CORPUS="$OUT_DIR/nxdomain_corpus.txt"
: > "$ALL"; : > "$CORPUS"

log(){ echo "[$(date +%H:%M:%S)] $*"; }

log "=== NXDOMAIN corpus: $TARGET ==="

# ── Source 1: BBOT existing output ──────────────────────────────
BBOT_SUBS="$BASE_DIR/recon/$TARGET/subs/bbot/subdomains.txt"
[ -f "$BBOT_SUBS" ] && cat "$BBOT_SUBS" >> "$ALL" && log "merged $(wc -l < $BBOT_SUBS) from bbot"

BBOT_ALT="$BASE_DIR/recon/$TARGET/bbot/subdomains.txt"
[ -f "$BBOT_ALT" ] && cat "$BBOT_ALT" >> "$ALL"

# ── Source 2: crt.sh ───────────────────────────────────────────
log "crt.sh..."
curl -s --max-time 30 "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null | \
  python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    s=set()
    for e in d:
        for n in e.get('name_value','').split('\n'):
            n=n.strip().lstrip('*.')
            if n.endswith('.${TARGET}') or n=='${TARGET}': s.add(n.lower())
    for n in sorted(s): print(n)
except: pass" >> "$ALL"

# ── Source 3: waymore (optional) ───────────────────────────────
if command -v waymore >/dev/null 2>&1; then
  log "waymore..."
  WAYMORE_OUT="$OUT_DIR/waymore.txt"
  waymore -i "$TARGET" -mode U -oU "$WAYMORE_OUT" 2>/dev/null || true
  [ -s "$WAYMORE_OUT" ] && grep -oE "[a-zA-Z0-9.-]+\.${TARGET}" "$WAYMORE_OUT" >> "$ALL"
elif command -v gau >/dev/null 2>&1; then
  log "gau (waymore not found)..."
  gau --subs "$TARGET" 2>/dev/null | grep -oE "[a-zA-Z0-9.-]+\.${TARGET}" >> "$ALL" || true
fi

# ── Source 4: extra file ───────────────────────────────────────
[ -n "$EXTRA_FILE" ] && [ -f "$EXTRA_FILE" ] && cat "$EXTRA_FILE" >> "$ALL"

# Dedup
sort -u "$ALL" -o "$ALL"
TOTAL=$(wc -l < "$ALL" | tr -d ' ')
log "historical superset: $TOTAL hostnames"

# ── Filter: NXDOMAIN only ──────────────────────────────────────
log "filtering NXDOMAIN via @1.1.1.1 (A + AAAA)..."
while read -r H; do
  [ -z "$H" ] && continue
  A=$(dig +short +time=2 +tries=1 "$H" @1.1.1.1 2>/dev/null)
  AAAA=$(dig +short +time=2 +tries=1 AAAA "$H" @1.1.1.1 2>/dev/null)
  if [ -z "$A" ] && [ -z "$AAAA" ]; then
    if [ "$DOUBLE_CHECK" = "1" ]; then
      A2=$(dig +short +time=2 +tries=1 "$H" @8.8.8.8 2>/dev/null)
      AAAA2=$(dig +short +time=2 +tries=1 AAAA "$H" @8.8.8.8 2>/dev/null)
      [ -n "$A2$AAAA2" ] && continue
    fi
    echo "$H" >> "$CORPUS"
  fi
done < "$ALL"

CORPUS_N=$(wc -l < "$CORPUS" | tr -d ' ')
log "=== NXDOMAIN candidates: $CORPUS_N → $CORPUS ==="
log ""
log "next step: when you find a host-header-controllable proxy,"
log "  load $CORPUS into Burp Intruder Host header position"
