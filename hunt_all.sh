#!/usr/bin/env bash
# ============================================================
# ⚠️ DEPRECATED — 請改用 tools/bbflow.sh
# ============================================================
# 這個檔案是 bbflow.sh 出現前的原型。已被以下 subcommand 取代：
#   ./bbflow.sh doctor            （依賴檢查）
#   ./bbflow.sh init <target>     （scope-first 初始化）
#   ./bbflow.sh recon <target>    （BBOT/Osmedeus recon）
#   ./bbflow.sh hunt <target>     （對 live_hosts.txt 跑全 hunters）
#   ./bbflow.sh flow <target>     （一條龍）
#   ./bbflow.sh test              （regression null-case test）
#   ./bbflow.sh dedupe <target>   （比對已送報告）
#
# bbflow 優點：
#   - 16 個 hunter（本檔 callback 只知道 7 個）
#   - scope-first 強制（沒 SCOPE.md 會拒絕 recon）
#   - 統一 subcommand + 狀態管理（list/status）
#   - 每個 hunter 有範例輸出 + 決策規則
#
# 這個檔案仍可執行，但不再更新。新功能只會加到 bbflow.sh。
# ============================================================

# hunt_all.sh — BBOT/Osmedeus recon → 所有 pattern hunter 批次執行（deprecated）
#
# 流程：
#   1. BBOT passive subdomain + 存活探測（使用現有 bbot_preset_bugbounty.yml）
#      （或 --from-osmedeus 從 VPS 抓結果）
#   2. 對 live hosts 跑全部 hunters：
#      - hunt-envdata.sh        （window.envData 提取）
#      - hunt-sourcemap-secrets.sh（source map 密鑰）
#      - hunt-cors-reflect.sh   （反射 CORS）
#      - hunt-graphql-idor.sh   （GraphQL 無認證 + IDOR）
#      - hunt-user-enum.sh      （帳號枚舉）
#      - hunt-hybris-occ.sh     （SAP OCC default creds）
#   3. 建立 NXDOMAIN corpus（hunt-nxdomain-corpus.sh）
#   4. 統整 HUNTERS_REPORT.md
#
# 用法：
#   ./hunt_all.sh target.com
#   ./hunt_all.sh target.com --mode quick           # 跳過 BBOT（用現有 recon 檔案）
#   ./hunt_all.sh target.com --from-osmedeus        # 從 $OSMEDEUS_VPS 拉結果
#   ./hunt_all.sh target.com --only envdata,cors    # 只跑指定 hunters
#
# 零 LLM 依賴：純 curl + python3 stdlib + bash
set -uo pipefail

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <target.com> [--mode quick|full] [--from-osmedeus] [--only h1,h2,...]"; exit 1; }
shift

MODE="full"
FROM_OSMEDEUS=0
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --from-osmedeus) FROM_OSMEDEUS=1; shift;;
    --only) ONLY="$2"; shift 2;;
    *) shift;;
  esac
done

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$TOOLS_DIR/.." && pwd)"
OUT="$BASE_DIR/recon/$TARGET"
mkdir -p "$OUT"/{bbot,hunters}
LIVE="$OUT/bbot/live_hosts.txt"
BBOT="$(command -v bbot 2>/dev/null || echo $HOME/.local/bin/bbot)"
REPORT="$OUT/HUNTERS_REPORT_$(date +%Y%m%d_%H%M).md"

log(){ echo "[$(date +%H:%M:%S)] $*"; }
want(){ [ -z "$ONLY" ] && return 0; echo ",$ONLY," | grep -q ",$1,"; }

# ── Phase 1: Recon ─────────────────────────────────────────────
if [ "$FROM_OSMEDEUS" = "1" ]; then
  VPS="${OSMEDEUS_VPS:-}"
  [ -z "$VPS" ] && { echo "ERROR: OSMEDEUS_VPS not set"; exit 1; }
  log "Osmedeus: rsync workspace from $VPS"
  ssh "$VPS" "osmedeus scan -f subdomain -t $TARGET 2>/dev/null; osmedeus scan -f general -t $TARGET 2>/dev/null" &
  wait
  scp "$VPS:~/.osmedeus/workspaces/$TARGET/module/http-probing/http-probing.txt" \
    "$LIVE" 2>/dev/null || true
  scp "$VPS:~/.osmedeus/workspaces/$TARGET/module/subdomain-enumeration/final-subdomain.txt" \
    "$OUT/bbot/subdomains.txt" 2>/dev/null || true
elif [ "$MODE" = "full" ] && [ -x "$BBOT" ]; then
  log "BBOT passive recon (this takes ~10 min)..."
  PRESET="$TOOLS_DIR/bbot_preset_bugbounty.yml"
  [ ! -f "$PRESET" ] && PRESET=""
  "$BBOT" -t "$TARGET" \
    ${PRESET:+-p "$PRESET"} \
    -f subdomain-enum,cloud-enum \
    -m httpx,badsecrets \
    -om subdomains,txt \
    -o "$OUT/bbot" --silent 2>/dev/null || true

  # bbot output has varying layout; locate files
  BBOT_SUBS=$(find "$OUT/bbot" -name "subdomains.txt" -type f 2>/dev/null | head -1)
  BBOT_TXT=$(find "$OUT/bbot" -name "output.txt" -type f 2>/dev/null | head -1)
  [ -n "$BBOT_SUBS" ] && cp "$BBOT_SUBS" "$OUT/bbot/subdomains.txt"

  # Extract URL events from bbot NDJSON/output.txt → live_hosts.txt
  if [ -n "$BBOT_TXT" ]; then
    grep -oE 'https?://[^ ]+' "$BBOT_TXT" 2>/dev/null | \
      awk -F/ '{print $1"//"$3}' | sort -u > "$LIVE"
  fi
fi

# If still no live list, fall back to subs → httpx probe
if [ ! -s "$LIVE" ] && [ -f "$OUT/bbot/subdomains.txt" ]; then
  log "probing subs with curl fallback..."
  while read -r SUB; do
    for SCHEME in https http; do
      CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$SCHEME://$SUB/" 2>/dev/null)
      [[ "$CODE" =~ ^[234] ]] && echo "$SCHEME://$SUB" >> "$LIVE"
    done
  done < "$OUT/bbot/subdomains.txt"
  sort -u "$LIVE" -o "$LIVE"
fi

LIVE_N=$(wc -l < "$LIVE" 2>/dev/null | tr -d ' ' || echo 0)
log "live hosts: $LIVE_N → $LIVE"
[ "$LIVE_N" = "0" ] && { echo "no live hosts, abort"; exit 1; }

# ── Phase 2: hunters ────────────────────────────────────────────
cat > "$REPORT" <<EOF
# Hunters Report — $TARGET
Date: $(date '+%Y-%m-%d %H:%M')
Live hosts: $LIVE_N
Mode: $MODE

EOF

run_hunter() {
  local name="$1" script="$2" arg_mode="$3"
  want "$name" || return 0
  log "→ hunter: $name"
  local OUT_H="$OUT/hunters/$name"
  mkdir -p "$OUT_H"
  export OUT_DIR="$OUT_H"
  echo "" >> "$REPORT"
  echo "## $name" >> "$REPORT"
  while read -r H; do
    [ -z "$H" ] && continue
    if [ "$arg_mode" = "host" ]; then
      "$script" "$H" 2>/dev/null || true
    elif [ "$arg_mode" = "url" ]; then
      "$script" "$H/" 2>/dev/null || true
    fi
  done < "$LIVE"
  # Aggregate hits
  local HITS
  HITS=$(grep -h "^🔴" "$OUT_H"/*.txt 2>/dev/null | sort -u || true)
  if [ -n "$HITS" ]; then
    echo "$HITS" | while read L; do echo "- $L" >> "$REPORT"; done
  else
    echo "- (no hits)" >> "$REPORT"
  fi
}

run_hunter envdata     "$TOOLS_DIR/hunters/hunt-envdata.sh"            host
run_hunter sourcemap   "$TOOLS_DIR/hunters/hunt-sourcemap-secrets.sh"  host
run_hunter cors        "$TOOLS_DIR/hunters/hunt-cors-reflect.sh"       url
run_hunter graphql     "$TOOLS_DIR/hunters/hunt-graphql-idor.sh"       host
run_hunter userenum    "$TOOLS_DIR/hunters/hunt-user-enum.sh"          host
run_hunter hybris-occ  "$TOOLS_DIR/hunters/hunt-hybris-occ.sh"         host

# ── Phase 3: NXDOMAIN corpus ────────────────────────────────────
if want nxdomain; then
  log "→ hunter: nxdomain (historical corpus)"
  "$TOOLS_DIR/hunters/hunt-nxdomain-corpus.sh" "$TARGET" 2>/dev/null || true
  NX="$OUT/nxdomain/nxdomain_corpus.txt"
  if [ -s "$NX" ]; then
    echo "" >> "$REPORT"
    echo "## nxdomain corpus" >> "$REPORT"
    echo "- $(wc -l < $NX | tr -d ' ') NXDOMAIN candidates → $NX" >> "$REPORT"
  fi
fi

log "=== report: $REPORT ==="
echo ""
grep "^🔴\|^- 🔴" "$REPORT" 2>/dev/null || grep "^- " "$REPORT" | head -20
