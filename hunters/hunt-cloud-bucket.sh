#!/usr/bin/env bash
# hunt-cloud-bucket.sh — Cloud bucket enumeration（OSINT Arsenal §16.5）
#
# 從 org/domain 名稱推測 S3 / GCS / Azure Blob bucket 名稱，
# 判斷 bucket 是否存在、是否可列目錄（listable）。
#
# Severity：
#   CRITICAL — bucket listable（任何人可列出/下載內容）
#   HIGH     — bucket 存在，private（可能 IDOR/misconfig 路徑）
#   INFO     — bucket 不存在
#
# 用法（domain 模式，bbflow 從 ROOT_DOMAIN 呼叫）：
#   ./hunt-cloud-bucket.sh example.com

set -uo pipefail

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <domain>"; exit 1; }
DOMAIN=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')
BASE=$(echo "$DOMAIN" | rev | cut -d. -f2- | rev | cut -d. -f1)  # e.g. juiker.tw → juiker

OUT_DIR="${OUT_DIR:-./cloud_bucket_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟠 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }

# ── 候選名稱生成（org base + 常見 suffix / prefix）──────────────────────────
SUFFIXES=(
  "" "-dev" "-stg" "-staging" "-prod" "-production"
  "-backup" "-backups" "-data" "-db" "-database"
  "-assets" "-static" "-media" "-files" "-uploads" "-download" "-downloads"
  "-public" "-private" "-internal" "-logs" "-log"
  "-config" "-configs" "-secrets" "-keys"
  "-test" "-uat" "-qa" "-sandbox" "-demo" "-preview"
  "-web" "-app" "-api" "-cdn" "-img" "-images"
  ".dev" ".prod" ".backup" ".data" ".assets" ".static"
)

CANDIDATES=()
for suf in "${SUFFIXES[@]}"; do
  CANDIDATES+=("${BASE}${suf}")
  CANDIDATES+=("${DOMAIN//\./-}${suf}")
done
# dedup
mapfile -t CANDIDATES < <(printf '%s\n' "${CANDIDATES[@]}" | sort -u)

log "=== Cloud bucket hunt: $DOMAIN / $BASE (${#CANDIDATES[@]} candidates) ==="

check_s3() {
  local name="$1"
  local url="https://${name}.s3.amazonaws.com/"
  local resp code body
  resp=$(curl -sk -m 10 -w "\n%{http_code}" "$url" 2>/dev/null)
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -c 1000)

  case "$code" in
    200)
      echo "$body" | grep -q "ListBucketResult" && \
        hit "[CRITICAL] S3 LISTABLE: $url" || \
        warn "[HIGH] S3 exists (200, not listable?): $url"
      ;;
    403)
      # Exists but private — still interesting
      warn "[HIGH] S3 exists (403 private): $url"
      ;;
    404)
      echo "$body" | grep -q "NoSuchBucket" && return 0  # doesn't exist
      info_hit "[INFO] S3 $name: 404 (might exist with different region)"
      ;;
  esac
}

check_gcs() {
  local name="$1"
  local url="https://storage.googleapis.com/${name}/"
  local resp code body
  resp=$(curl -sk -m 10 -w "\n%{http_code}" "$url" 2>/dev/null)
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -c 1000)

  case "$code" in
    200)
      echo "$body" | grep -q "ListBucketResult\|<Contents>" && \
        hit "[CRITICAL] GCS LISTABLE: $url" || \
        warn "[HIGH] GCS exists (200): $url"
      ;;
    403)
      warn "[HIGH] GCS exists (403 private): $url"
      ;;
  esac
}

check_azure() {
  local name="$1"
  # Azure Blob container
  local url="https://${name}.blob.core.windows.net/"
  local resp code body
  resp=$(curl -sk -m 10 -w "\n%{http_code}" "$url" 2>/dev/null)
  code=$(echo "$resp" | tail -1)
  body=$(echo "$resp" | head -c 500)

  case "$code" in
    200|400)
      echo "$body" | grep -qi "EnumerationResults\|BlobServiceProperties\|InvalidQueryParameterValue" && \
        warn "[HIGH] Azure Blob exists: $url"
      ;;
    403)
      echo "$body" | grep -qi "PublicAccessNotPermitted\|AuthorizationFailure" && \
        warn "[HIGH] Azure Blob exists (403 private): $url"
      ;;
  esac
}

for name in "${CANDIDATES[@]}"; do
  check_s3   "$name"
  check_gcs  "$name"
  check_azure "$name"
  sleep 0.3
done

log "=== done: bucket sweep complete ==="
