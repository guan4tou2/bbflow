#!/usr/bin/env bash
# hunt-swagger.sh — Swagger / OpenAPI spec discovery（OSINT Arsenal §16.1）
#
# 對每個 live host 探測 28 條路徑，找出暴露的 API spec。
# Severity：
#   HIGH   — spec 無需認證可讀取（LEAKY_API_SPEC）
#   MEDIUM — spec 在認證後可讀（任意帳號）
#   INFO   — 回應 401/403（存在但受保護）
#
# 用法（host 模式，bbflow run_hunter 呼叫）：
#   ./hunt-swagger.sh https://api.example.com

set -uo pipefail

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <host-url>"; exit 1; }
HOST=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
BASE_URL=$(echo "$INPUT" | sed -E 's|/$||')

OUT_DIR="${OUT_DIR:-./swagger_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | tr '.' '_' | tr ':' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟠 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }

# §16.1 — 28 paths
PATHS=(
  swagger.json
  swagger.yaml
  swagger/v1/swagger.json
  swagger/v2/swagger.json
  swagger-ui.html
  swagger-ui/
  swagger-resources
  api-docs
  api-docs.json
  api/swagger
  api/swagger.json
  api/swagger-ui.html
  api/v1/swagger.json
  api/v2/swagger.json
  api/v3/api-docs
  v2/api-docs
  v3/api-docs
  openapi.json
  openapi.yaml
  openapi/v1
  openapi/v3
  docs
  redoc
  rapidoc
  api/docs
  api/documentation
  .well-known/openapi
  api-spec
)

log "=== Swagger/OpenAPI hunt: $HOST (${#PATHS[@]} paths) ==="

FOUND=0

for path in "${PATHS[@]}"; do
  URL="${BASE_URL}/${path}"

  RESP=$(curl -sk -m 10 -w "\n%{http_code}" "$URL" 2>/dev/null)
  CODE=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -c 2000)

  case "$CODE" in
    200)
      # Check if response looks like a real API spec
      IS_SPEC=0
      echo "$BODY" | grep -qiE '"swagger"\s*:|"openapi"\s*:|"paths"\s*:|swaggerVersion|"info"\s*:' && IS_SPEC=1
      echo "$BODY" | grep -qiE 'swagger-ui|redoc|rapidoc|<!DOCTYPE html' && IS_SPEC=2

      if [ "$IS_SPEC" -eq 1 ]; then
        FOUND=$((FOUND + 1))
        # Check if it requires auth by looking for endpoint count
        EP_COUNT=$(echo "$BODY" | grep -o '"get"\|"post"\|"put"\|"delete"\|"patch"' | wc -l | tr -d ' ')
        hit "[HIGH] LEAKY_API_SPEC: $URL (no auth, ~${EP_COUNT} endpoints visible)"
      elif [ "$IS_SPEC" -eq 2 ]; then
        FOUND=$((FOUND + 1))
        info_hit "[INFO] Swagger UI found: $URL (HTML interface)"
      else
        # 200 but not a spec — skip silently
        :
      fi
      ;;
    401|403)
      info_hit "[INFO] $path → $CODE (protected, spec exists)"
      ;;
    301|302|307|308)
      LOCATION=$(curl -sk -m 8 -D - -o /dev/null "$URL" 2>/dev/null | grep -i '^location:' | cut -d' ' -f2- | tr -d '\r\n')
      info_hit "[INFO] $path → $CODE → $LOCATION"
      ;;
  esac

  sleep 0.15
done

log "=== done: $FOUND spec endpoints found ==="
