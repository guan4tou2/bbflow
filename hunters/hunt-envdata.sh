#!/usr/bin/env bash
# hunt-envdata.sh — 從 HTML 提取 window.envData / window.__INITIAL_STATE__ / inline config
# 來源：SPA inline window config (disclosed writeup)（AWS Location API key + AWS account IDs + okta clientId）
#      webapp.example.com（ssInlineConfig → appHubHost）
#
# 輸出：提取的 config JSON + 可疑密鑰清單（AWS/Google/Sentry/Firebase）
#
# 用法：
#   ./hunt-envdata.sh https://insight.example.com
#   cat bbot/live_hosts.txt | while read h; do ./hunt-envdata.sh "$h"; done
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./envdata_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
RAW="$OUT_DIR/${SLUG}_raw.html"
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
hit() { echo "🔴 $*" | tee -a "$OUT"; }
log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }

log "=== envData hunt: $HOST ==="
curl -sk --max-time 12 "$HOST/" -o "$RAW"
[ ! -s "$RAW" ] && { log "empty body"; exit 0; }

python3 - "$RAW" "$OUT" "$HOST" <<'PY'
import re, json, sys, os
raw_path, out_path, host = sys.argv[1], sys.argv[2], sys.argv[3]
with open(raw_path) as f: html = f.read()
out = open(out_path, 'a')

def say(msg): print(msg); out.write(msg+"\n")

patterns = [
    # Object.defineProperty(window, "envData", { ... value: Object.freeze({...}) })
    (r'defineProperty\s*\(\s*window\s*,\s*["\']envData["\'][^)]*?Object\.freeze\s*\((\{.+)', 'window.envData'),
    (r'window\.envData\s*=\s*Object\.freeze\s*\((\{.+)', 'window.envData'),
    (r'window\.envData\s*=\s*(\{.+)', 'window.envData'),
    (r'window\.__INITIAL_STATE__\s*=\s*(\{.+)', '__INITIAL_STATE__'),
    (r'window\.__NUXT__\s*=\s*(\{.+)', '__NUXT__'),
    (r'<script[^>]*id=["\']ssInlineConfig["\'][^>]*>(\{.+?)<', 'ssInlineConfig'),
    (r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(\{.+?)</script>', '__NEXT_DATA__'),
]

extracted = {}
for pat, name in patterns:
    m = re.search(pat, html, re.DOTALL)
    if not m: continue
    raw = m.group(1)
    depth = 0; end = -1
    for i, c in enumerate(raw):
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0: end = i+1; break
    if end == -1: continue
    candidate = raw[:end]
    try:
        data = json.loads(candidate)
        extracted[name] = data
        say(f"✓ extracted {name} ({len(candidate)} bytes)")
        fn = out_path.replace('.txt', f'_{name}.json')
        with open(fn, 'w') as fp: json.dump(data, fp, indent=2)
    except Exception:
        pass

if not extracted:
    say("no inline config found")
    out.close(); sys.exit(0)

# Secret grep on extracted configs
flat_text = json.dumps(extracted)
secrets = {
    'AWS Location key (v1.public)': r'v1\.public\.[a-zA-Z0-9_-]{40,}\.[a-zA-Z0-9]+',
    'AWS account ID': r'\baws:iam::(\d{12}):',
    'AWS principal ID': r'"[a-zA-Z]*[Pp]rincipal"\s*:\s*"(\d{12})"',
    'Google API key': r'AIza[0-9A-Za-z_-]{35}',
    'Sentry DSN': r'https://[a-f0-9]+@[a-z0-9.-]+\.sentry\.io/\d+',
    'Okta clientId': r'"clientId"\s*:\s*"(0oa[a-zA-Z0-9]{16,})"',
    'Mapbox token': r'pk\.eyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+',
    'Firebase apiKey': r'"apiKey"\s*:\s*"(AIza[0-9A-Za-z_-]{35})"',
    'Stripe pk_live': r'pk_live_[0-9a-zA-Z]{24,}',
}
for label, pat in secrets.items():
    for m in re.findall(pat, flat_text):
        v = m if isinstance(m, str) else m[0]
        say(f"🔴 {label}: {v[:80]}")
out.close()
PY

log "=== done → $OUT ==="
