#!/usr/bin/env bash
# hunt-arjun-params.sh — 隱藏 HTTP parameter discovery via arjun
#
# 用途：發現沒有出現在正常 URL 的隱藏 GET/POST/JSON parameters
# 這些 hidden params 常常繞過存取控制或觸發未授權功能
#
# Usage: OUT_DIR=/path hunt-arjun-params.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-arjun-$$}"
mkdir -p "$OUT_DIR"

ARJUN="$(command -v arjun 2>/dev/null || echo '')"
[ -z "$ARJUN" ] && { echo "✗ arjun not found (pip3 install arjun)"; exit 0; }

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
ARJUN_OUT="$OUT_DIR/arjun_params.json"

# Arjun: scan GET + POST + JSON parameters
# --stable: avoid false positives by repeating requests
# -t 5: 5 concurrent threads
"$ARJUN" \
  -u "$TARGET" \
  -m GET POST JSON \
  -t 5 \
  --stable \
  --passive \
  -o "$ARJUN_OUT" \
  -q 2>/dev/null || true

# Also try common API endpoints if target looks like an API
if echo "$TARGET" | grep -qiE '/api/|/v[0-9]/|/rest/'; then
  "$ARJUN" \
    -u "$TARGET" \
    -m GET POST JSON \
    -t 5 \
    -q 2>/dev/null >> "$OUT_DIR/arjun_api.txt" || true
fi

# Parse results
if [ -s "$ARJUN_OUT" ]; then
  python3 -c "
import json, sys
try:
    data = json.load(open('$ARJUN_OUT'))
    for endpoint, info in data.items() if isinstance(data, dict) else []:
        params = info.get('params', []) if isinstance(info, dict) else info
        if params:
            print(f'🔴 ARJUN hidden-params {endpoint} → {len(params)} params: {params[:5]}')
except:
    pass
" 2>/dev/null || true
fi
