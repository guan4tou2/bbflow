#!/usr/bin/env bash
# ============================================================
# batch_hunt.sh — 批量 Bug Bounty 偵察
# 輸入：Excel / txt / csv（含 IP + Domain）
# 流程：Excel → targets.txt → bbot 批量 → auto_hunt 深挖
#
# 用法:
#   ./tools/batch_hunt.sh targets.xlsx
#   ./tools/batch_hunt.sh targets.xlsx --mode bbot-only
#   ./tools/batch_hunt.sh targets.xlsx --mode hunt-only
#   ./tools/batch_hunt.sh recon/targets.txt --mode hunt-only
#   ./tools/batch_hunt.sh targets.xlsx --parallel 5
#
# 流程說明:
#   Phase A: Excel → targets.txt（用 excel_to_targets.py）
#   Phase B: bbot 批量掃描（所有 target 一次跑，subdomain+bucket+takeover）
#   Phase C: auto_hunt.sh 逐一深挖（SPA 過濾/Actuator/Swagger/GraphQL/OCC 等）
# ============================================================
set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$TOOLS_DIR/.." && pwd)"

# ── 參數 ──────────────────────────────────────────────────────
INPUT="${1:-}"
MODE="full"          # full | bbot-only | hunt-only
PARALLEL=3           # 同時跑幾個 auto_hunt
BBOT_PRESET="$TOOLS_DIR/bbot_preset_bugbounty.yml"   # 用完整路徑，bbot v2 不自動搜尋 ~/.config
BBOT="$(command -v bbot 2>/dev/null || echo "$HOME/.local/bin/bbot")"
PYTHON="$(command -v python3)"

if [ -z "$INPUT" ]; then
  echo "用法: $0 <targets.xlsx|targets.txt> [--mode full|bbot-only|hunt-only] [--parallel N]"
  echo ""
  echo "  --mode bbot-only   只跑 bbot 批量掃描"
  echo "  --mode hunt-only   跳過 bbot，直接 auto_hunt.sh"
  echo "  --mode full        bbot + auto_hunt（預設）"
  echo "  --parallel N       auto_hunt 並行數（預設 3）"
  exit 1
fi

shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --parallel) PARALLEL="$2"; shift 2;;
    *) shift;;
  esac
done

TIMESTAMP=$(date +%Y%m%d_%H%M)
OUT_DIR="$BASE_DIR/recon/batch_$TIMESTAMP"
mkdir -p "$OUT_DIR"
TARGETS_FILE="$OUT_DIR/targets.txt"
LOG="$OUT_DIR/batch.log"
REPORT="$OUT_DIR/BATCH_REPORT_$TIMESTAMP.md"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

cat > "$REPORT" <<EOF
# Batch Hunt Report
**Date:** $(date '+%Y-%m-%d %H:%M')
**Input:** $INPUT
**Mode:** $MODE
**Parallel:** $PARALLEL
**Output:** $OUT_DIR

EOF

log "Batch hunt started: $INPUT (mode=$MODE)"

# ============================================================
# PHASE A: 解析 Excel / TXT → targets.txt
# ============================================================
echo "## Phase A: Target Parsing" >> "$REPORT"

EXT="${INPUT##*.}"
if [[ "${EXT,,}" =~ ^(xlsx|xls)$ ]]; then
  log "Parsing Excel: $INPUT"
  $PYTHON "$TOOLS_DIR/excel_to_targets.py" "$INPUT" \
    --out "$TARGETS_FILE" 2>&1 | tee -a "$LOG"
elif [[ "${EXT,,}" =~ ^(txt|csv)$ ]]; then
  log "Parsing text file: $INPUT"
  if [[ "${EXT,,}" == "txt" ]]; then
    # 直接用（過濾空行和注釋）
    grep -vE "^#|^$" "$INPUT" > "$TARGETS_FILE" || true
    log "Copied $(wc -l < "$TARGETS_FILE" | tr -d ' ') targets"
  else
    # CSV → 提取 domain/IP
    $PYTHON "$TOOLS_DIR/excel_to_targets.py" "$INPUT" \
      --out "$TARGETS_FILE" 2>&1 | tee -a "$LOG"
  fi
else
  log "Unknown format: $EXT. Treating as plain text."
  cp "$INPUT" "$TARGETS_FILE"
fi

if [ ! -s "$TARGETS_FILE" ]; then
  log "ERROR: No targets extracted from $INPUT"
  exit 1
fi

TARGET_COUNT=$(wc -l < "$TARGETS_FILE" | tr -d ' ')
log "Total targets: $TARGET_COUNT"
echo "- **Targets parsed:** $TARGET_COUNT → $TARGETS_FILE" >> "$REPORT"

# ============================================================
# PHASE B: bbot 批量掃描（全部 target 一次跑）
# ============================================================
if [[ "$MODE" == "full" || "$MODE" == "bbot-only" ]]; then
  echo "" >> "$REPORT"
  echo "## Phase B: bbot Batch Scan" >> "$REPORT"

  BBOT_OUT="$OUT_DIR/bbot"
  mkdir -p "$BBOT_OUT"

  if [ -x "$BBOT" ]; then
    log "Starting bbot on $TARGET_COUNT targets..."
    log "Preset: $BBOT_PRESET"

    # bbot 接受 -t <file> 直接讀取 targets.txt
    $BBOT \
      -t "$TARGETS_FILE" \
      -p "$BBOT_PRESET" \
      -o "$BBOT_OUT" \
      --no-deps \
      --silent 2>&1 | tee -a "$LOG" || {
      log "WARNING: bbot exited with error (may still have partial results)"
    }

    # 統計輸出
    BBOT_SUBS=0
    BBOT_FINDINGS=0
    if [ -f "$BBOT_OUT/subdomains.txt" ]; then
      BBOT_SUBS=$(wc -l < "$BBOT_OUT/subdomains.txt" | tr -d ' ')
    fi
    if [ -f "$BBOT_OUT/output.txt" ]; then
      BBOT_FINDINGS=$(grep -cE "\[VULNERABILITY\]|\[FINDING\]" "$BBOT_OUT/output.txt" 2>/dev/null || echo 0)
    fi

    log "bbot complete: $BBOT_SUBS subdomains, $BBOT_FINDINGS findings"
    echo "- **bbot subdomains:** $BBOT_SUBS" >> "$REPORT"
    echo "- **bbot findings:** $BBOT_FINDINGS (VULNERABILITY/FINDING events)" >> "$REPORT"

    # 顯示 critical findings 摘要
    if [ -f "$BBOT_OUT/output.txt" ] && [ "$BBOT_FINDINGS" -gt 0 ]; then
      echo "" >> "$REPORT"
      echo "### bbot Findings" >> "$REPORT"
      grep -E "\[VULNERABILITY\]|\[FINDING\]" "$BBOT_OUT/output.txt" 2>/dev/null | \
        head -50 | while read -r line; do
        echo "- $line" >> "$REPORT"
      done
    fi
  else
    log "WARNING: bbot not found at $BBOT — skipping Phase B"
    echo "- ⚠️ bbot not found, skipped" >> "$REPORT"
  fi
fi

# ============================================================
# PHASE C: auto_hunt.sh 深挖（per-target，最多 $PARALLEL 並行）
# ============================================================
if [[ "$MODE" == "full" || "$MODE" == "hunt-only" ]]; then
  echo "" >> "$REPORT"
  echo "## Phase C: auto_hunt Deep Scan" >> "$REPORT"
  log "Starting auto_hunt on $TARGET_COUNT targets (parallel=$PARALLEL)..."

  HUNT_PIDS=()
  HUNT_SUCCESS=0
  HUNT_FAIL=0

  while IFS= read -r target; do
    # 跳過空行和注釋
    [[ -z "$target" || "$target" == \#* ]] && continue

    log "Hunting: $target"
    (
      "$TOOLS_DIR/auto_hunt.sh" "$target" --mode quick 2>>"$LOG" || true
    ) &
    HUNT_PIDS+=($!)

    # 並行控制
    if [ ${#HUNT_PIDS[@]} -ge "$PARALLEL" ]; then
      wait "${HUNT_PIDS[0]}" 2>/dev/null && ((HUNT_SUCCESS++)) || ((HUNT_FAIL++))
      HUNT_PIDS=("${HUNT_PIDS[@]:1}")
    fi
  done < "$TARGETS_FILE"

  # 等待剩餘
  for pid in "${HUNT_PIDS[@]}"; do
    wait "$pid" 2>/dev/null && ((HUNT_SUCCESS++)) || ((HUNT_FAIL++))
  done

  log "auto_hunt complete: $HUNT_SUCCESS succeeded, $HUNT_FAIL failed"
  echo "- **auto_hunt targets:** $TARGET_COUNT" >> "$REPORT"
  echo "- **Succeeded:** $HUNT_SUCCESS" >> "$REPORT"
  echo "- **Failed:** $HUNT_FAIL" >> "$REPORT"

  # 整合所有 per-target 報告的 critical findings
  echo "" >> "$REPORT"
  echo "### Critical Findings Summary (🔴)" >> "$REPORT"
  find "$BASE_DIR/recon" -name "AUTO_HUNT_*.md" -newer "$BASE_DIR/recon/batch_$TIMESTAMP" 2>/dev/null | \
    while read -r hunt_report; do
      target_name=$(basename "$(dirname "$hunt_report")")
      grep "^- 🔴" "$hunt_report" 2>/dev/null | while read -r line; do
        echo "- **[$target_name]** $line" >> "$REPORT"
      done
    done || true
fi

# ============================================================
# SUMMARY
# ============================================================
echo "" >> "$REPORT"
echo "## Summary" >> "$REPORT"
echo "- **Input:** $INPUT" >> "$REPORT"
echo "- **Total Targets:** $TARGET_COUNT" >> "$REPORT"
echo "- **Output Dir:** $OUT_DIR" >> "$REPORT"
echo "- **Report:** $REPORT" >> "$REPORT"
echo "" >> "$REPORT"
echo "### Output Files" >> "$REPORT"
echo "| File | Description |" >> "$REPORT"
echo "|------|-------------|" >> "$REPORT"
echo "| \`targets.txt\` | 解析後的 target 清單 |" >> "$REPORT"
echo "| \`bbot/subdomains.txt\` | bbot 找到的所有子域名 |" >> "$REPORT"
echo "| \`bbot/output.txt\` | bbot 完整輸出 |" >> "$REPORT"
echo "| \`bbot/output.csv\` | bbot CSV（可匯入 Excel）|" >> "$REPORT"
echo "| \`../recon/<target>/AUTO_HUNT_*.md\` | 各 target 詳細報告 |" >> "$REPORT"

echo ""
echo "========================================"
echo "  BATCH HUNT COMPLETE"
echo "  Targets: $TARGET_COUNT"
echo "  Report:  $REPORT"
echo "========================================"

log "Batch hunt complete. Report: $REPORT"
