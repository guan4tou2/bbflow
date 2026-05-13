#!/usr/bin/env bash
# hunt-zpush-version.sh — Z-Push 版本指紋 + CVE-2025-8264 prerequisite check (mass-host)
# 來源：openfind OF-015（7 主機 Z-Push 2.5.0 確認）
#       Pattern - Vendor Product Multi-Host Enumeration（KB）
#
# Z-Push 是 open-source EAS (Exchange ActiveSync) Mobile Sync 後端，
# 廠商常用於 mail product 的 Outlook / iOS / Android push 支援。
# CVE-2025-8264 (CVSS 9.0) — < 2.7.6 IMAP_FROM_SQL_QUERY SQLi（需 IMAP auth）。
#
# 流程：
#   1. 對 host 試 /Microsoft-Server-ActiveSync 標準路徑
#   2. 抽 X-Zpush-Version header（直接 fingerprint）
#   3. fallback：WWW-Authenticate "Basic realm=\"ZPush\"" / Basic realm 字串
#   4. 版本字串解析（master-2.X.Y / release-2.X.Y）→ 與 2.7.6 比對
#   5. 輸出 CVE-2025-8264 prerequisite 判斷
#
# 用法：
#   ./hunt-zpush-version.sh https://eas-vip.example.com
#   for H in $(cat hosts.txt); do ./hunt-zpush-version.sh "$H"; done
#   # 然後彙整：grep -h '^🔴 VULN' ./zpush_out/*.txt | sort -u
set -uo pipefail

URL="${1:-}"
[ -z "$URL" ] && { echo "Usage: $0 <https://host> | for H in \$(cat hosts.txt); do $0 \"\$H\"; done"; exit 1; }
URL="${URL%/}"
OUT_DIR="${OUT_DIR:-./zpush_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$URL" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit() { echo "🔴 VULN $*" | tee -a "$OUT"; }
warn() { echo "🟠 $*" | tee -a "$OUT"; }
info() { echo "   $*" >> "$OUT"; }

VULN_CUTOFF="2.7.6"

# Probe /Microsoft-Server-ActiveSync
EAS_URL="${URL}/Microsoft-Server-ActiveSync"
log "=== Z-Push probe: $EAS_URL ==="
RESP=$(curl -skI --max-time 8 "$EAS_URL" 2>&1)
STATUS=$(echo "$RESP" | head -1 | grep -oE '[0-9]{3}' | head -1)
[ -z "$STATUS" ] && STATUS="?"
info "HTTP status: $STATUS"

# Extract headers
ZPUSH_VER=$(echo "$RESP" | grep -i "^x-zpush-version:" | sed 's/^[Xx]-[Zz]push-[Vv]ersion:[[:space:]]*//' | tr -d '\r\n' | head -1)
WWW_AUTH=$(echo "$RESP" | grep -i "^www-authenticate:" | tr -d '\r\n' | head -1)
SERVER=$(echo "$RESP" | grep -i "^server:" | tr -d '\r\n' | head -1)
POWERED=$(echo "$RESP" | grep -i "^x-powered-by:" | tr -d '\r\n' | head -1)

info "X-Zpush-Version: ${ZPUSH_VER:-(none)}"
info "WWW-Authenticate: ${WWW_AUTH:-(none)}"
info "Server: ${SERVER:-(none)}"
info "X-Powered-By: ${POWERED:-(none)}"

# Decision tree
if [ -n "$ZPUSH_VER" ]; then
  # Parse version (e.g. master-2.5.0-2c7d40e0322 → 2.5.0)
  VER_NUM=$(echo "$ZPUSH_VER" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

  if [ -n "$VER_NUM" ]; then
    # Numeric compare 2.5.0 vs 2.7.6
    MAJOR=$(echo "$VER_NUM" | cut -d. -f1)
    MINOR=$(echo "$VER_NUM" | cut -d. -f2)
    PATCH=$(echo "$VER_NUM" | cut -d. -f3)
    CUT_MAJOR=$(echo "$VULN_CUTOFF" | cut -d. -f1)
    CUT_MINOR=$(echo "$VULN_CUTOFF" | cut -d. -f2)
    CUT_PATCH=$(echo "$VULN_CUTOFF" | cut -d. -f3)

    VULN=0
    if [ "$MAJOR" -lt "$CUT_MAJOR" ]; then VULN=1
    elif [ "$MAJOR" -eq "$CUT_MAJOR" ] && [ "$MINOR" -lt "$CUT_MINOR" ]; then VULN=1
    elif [ "$MAJOR" -eq "$CUT_MAJOR" ] && [ "$MINOR" -eq "$CUT_MINOR" ] && [ "$PATCH" -lt "$CUT_PATCH" ]; then VULN=1
    fi

    if [ "$VULN" = "1" ]; then
      hit "$URL Z-Push $VER_NUM < $VULN_CUTOFF — CVE-2025-8264 prerequisite met (IMAP SQLi candidate, 需 IMAP auth)"
      info "  → 報送點："
      info "    1. fingerprint 自身（即使無 auth 不可 exploit，老版本仍 advisory-worthy）"
      info "    2. 若有有效 IMAP 帳號 → 試 CVE-2025-8264 payload（IMAP_FROM_SQL_QUERY 條件）"
      info "    3. Multi-host enum：同 vendor 的 autodiscover.* / eas-* / eas.* 都試"
    else
      echo "🟢 SAFE: $URL Z-Push $VER_NUM >= $VULN_CUTOFF" | tee -a "$OUT"
    fi
  else
    warn "Z-Push detected but version 字串無數字格式: $ZPUSH_VER"
  fi
elif echo "$WWW_AUTH" | grep -qi 'realm="ZPush"\|zpush'; then
  warn "Z-Push 確認（WWW-Authenticate realm 命中）但無版本 header — Z-Push 較新版可能關閉 X-Zpush-Version 揭露"
  info "  → 試 GET /Microsoft-Server-ActiveSync?Cmd=Ping 看回應差異"
elif [ "$STATUS" = "401" ] || [ "$STATUS" = "200" ]; then
  info "Endpoint exists（HTTP $STATUS）but no Z-Push fingerprint — may be other EAS impl (Exchange / Kerio / etc)"
else
  info "Endpoint not Z-Push（HTTP $STATUS）"
fi

log "=== done → $OUT ==="
