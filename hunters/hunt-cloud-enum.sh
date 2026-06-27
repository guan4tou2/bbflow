#!/usr/bin/env bash
# hunt-cloud-enum.sh — Multi-cloud resource enumeration via cloud_enum
#
# 從公司/組織關鍵字推測 AWS/Azure/GCP bucket、App Service、
# Cloud Function 等雲端資源是否存在。
#
# 與 hunt-cloud-bucket.sh 互補：
#   - hunt-cloud-bucket.sh = 直接 curl 探測 S3/GCS/Azure Blob（快、輕量）
#   - hunt-cloud-enum.sh   = cloud_enum 工具做更廣的 multi-cloud enum（慢、全面）
#
# Severity（機械 hunter 只報訊號，ownership/sensitivity 交 LLM 判斷）：
#   🔴 HIGH   — open/listable bucket 或可存取的 cloud resource
#   🟡 EXISTS — resource 存在但受限（403/private）
#   🟢 SUMMARY — 最終統計
#
# 用法：
#   ./hunt-cloud-enum.sh acmecorp
#   ./hunt-cloud-enum.sh acmecorp --disable-azure
#
# 環境變數：
#   OUT_DIR           輸出目錄（預設 ./cloud_enum_out）
#   BBFLOW_PROFILE    safe/deep/stealth（影響 thread 數）
#   CLOUD_ENUM_PATH   cloud_enum.py 路徑（預設 ~/Tools/cloud_enum/cloud_enum.py）

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

KEYWORD="${1:-}"
[ -z "$KEYWORD" ] && { echo "Usage: $0 <company-keyword> [cloud_enum extra flags...]"; exit 1; }
shift

# Extra flags passed through to cloud_enum (e.g. --disable-azure)
EXTRA_FLAGS=("$@")

OUT_DIR="${OUT_DIR:-./cloud_enum_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$KEYWORD" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')
OUT="$OUT_DIR/${SLUG}.txt"
RAW="$OUT_DIR/${SLUG}_raw.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }

# ── Locate cloud_enum ───────────────────────────────────────────────
CLOUD_ENUM="${CLOUD_ENUM_PATH:-}"
if [ -z "$CLOUD_ENUM" ]; then
  for _ce in \
    "$HOME/Tools/cloud_enum/cloud_enum.py" \
    "/opt/cloud_enum/cloud_enum.py"; do
    [ -f "$_ce" ] && CLOUD_ENUM="$_ce" && break
  done
fi

if [ -z "$CLOUD_ENUM" ] || [ ! -f "$CLOUD_ENUM" ]; then
  echo "✗ cloud_enum not found (expected at ~/Tools/cloud_enum/cloud_enum.py)"
  echo "  Install: cd ~/Tools && git clone https://github.com/initstring/cloud_enum.git && cd cloud_enum && pip3 install -r requirements.txt"
  exit 0
fi

# ── Profile-aware thread count ──────────────────────────────────────
case "${BBFLOW_PROFILE:-safe}" in
  deep)
    CE_THREADS="${CE_THREADS:-15}"
    ;;
  stealth)
    CE_THREADS="${CE_THREADS:-2}"
    ;;
  *)
    CE_THREADS="${CE_THREADS:-8}"
    ;;
esac

log "=== cloud_enum hunt: keyword='$KEYWORD' profile=$BBFLOW_PROFILE threads=$CE_THREADS ==="

# ── Run cloud_enum ──────────────────────────────────────────────────
python3 "$CLOUD_ENUM" \
  -k "$KEYWORD" \
  -t "$CE_THREADS" \
  "${EXTRA_FLAGS[@]}" \
  2>&1 | tee "$RAW" || true

# ── Parse results ───────────────────────────────────────────────────
# cloud_enum output format:
#   [+] OPEN S3 bucket: https://acme-backup.s3.amazonaws.com/
#   [+] Protected S3 bucket: https://acme-prod.s3.amazonaws.com/
#   [+] Open Azure container: https://acme.blob.core.windows.net/public
#   [+] Protected GCP bucket: https://storage.googleapis.com/acme-data

OPEN_COUNT=0
PROTECTED_COUNT=0

while IFS= read -r line; do
  # Skip empty and banner lines
  case "$line" in
    ""|\[*\]\ Searching*|\[*\]\ Starting*|\[*\]\ Mutations*|\[*\]\ Testing*) continue ;;
  esac

  # Open / listable resources
  if echo "$line" | grep -qiE '^\[.\]\s*(OPEN|open|Public)'; then
    url=$(echo "$line" | sed -E 's/^\[.\]\s*[^:]+:\s*//')
    provider="unknown"
    echo "$line" | grep -qi 's3\|aws\|amazonaws' && provider="AWS"
    echo "$line" | grep -qi 'azure\|blob\.core\|azurewebsites' && provider="Azure"
    echo "$line" | grep -qi 'gcp\|googleapis\|appspot\|cloudfunctions\|firebaseio' && provider="GCP"
    hit "[HIGH] OPEN $provider resource: $url"
    OPEN_COUNT=$((OPEN_COUNT + 1))
    continue
  fi

  # Protected / exists resources
  if echo "$line" | grep -qiE '^\[.\]\s*(Protected|Exists|Found)'; then
    url=$(echo "$line" | sed -E 's/^\[.\]\s*[^:]+:\s*//')
    provider="unknown"
    echo "$line" | grep -qi 's3\|aws\|amazonaws' && provider="AWS"
    echo "$line" | grep -qi 'azure\|blob\.core\|azurewebsites' && provider="Azure"
    echo "$line" | grep -qi 'gcp\|googleapis\|appspot\|cloudfunctions\|firebaseio' && provider="GCP"
    info_hit "[EXISTS] Protected $provider resource: $url"
    PROTECTED_COUNT=$((PROTECTED_COUNT + 1))
    continue
  fi
done < "$RAW"

# ── Summary ─────────────────────────────────────────────────────────
echo "🟢 SUMMARY: $OPEN_COUNT open + $PROTECTED_COUNT protected resources found for '$KEYWORD'" | tee -a "$OUT"

if [ "$OPEN_COUNT" -gt 0 ]; then
  log "⚠ OPEN resources detected — verify ownership (content references target?) before any severity assignment"
  log "  Ref: feedback_bucket_namespace_ownership.md — LISTABLE ≠ owned; need content verification"
fi

log "=== done: cloud_enum sweep complete → $OUT ==="
