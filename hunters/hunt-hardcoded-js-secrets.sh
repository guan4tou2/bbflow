#!/usr/bin/env bash
# hunt-hardcoded-js-secrets.sh — 對 live .js bundle grep 硬編碼密鑰
# 來源：SPA hardcoded client secret pattern（ 含 hardcoded clientSecret，server 差異回應確認）
#
# 和 hunt-sourcemap-secrets.sh 互補：
#   - sourcemap hunter 解 .map，要有 source map 才能還原
#   - 本 hunter 直接對 live .js 做 grep，即使 source map 關了也能打
#   - 混淆後的 js 常常密鑰字串還是 plain（只有變數名被改）
#
# 流程：
#   1. 抓 HTML 找所有 .js 引用（inline + Next.js chunks + webpack）
#   2. 下載每個 .js（跳過 vendor / runtime / framework）
#   3. grep 已知密鑰 pattern（aws/google/stripe/slack/github/oauth/jwt/bearer）
#   4. 特別針對 clientSecret / client_secret / apiKey 上下文（SPA hardcoded client secret pattern）
#
# 用法：
#   ./hunt-hardcoded-js-secrets.sh https://target
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./jsecret_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }

log "=== hardcoded JS secrets hunt: $HOST ==="

# ── Step 1: collect .js URLs ──────────────────────────────────
HTML_FILE="$OUT_DIR/${SLUG}_root.html"
curl -sk --max-time 10 "$HOST/" -o "$HTML_FILE"
[ ! -s "$HTML_FILE" ] && { log "empty body"; exit 0; }

EXTRACT_PY="$OUT_DIR/.extract_urls.py"
cat > "$EXTRACT_PY" <<'PYEOF'
import sys, re
host = sys.argv[1].rstrip('/')
with open(sys.argv[2]) as f: html = f.read()
urls = set()
for m in re.finditer(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']', html):
    u = m.group(1)
    if u.startswith('//'): u = 'https:' + u
    elif u.startswith('/'): u = host + u
    elif u.startswith('http'): pass
    else: u = host + '/' + u
    urls.add(u)
for m in re.finditer(r'"(/_next/static/chunks/[^"]+\.js)"', html):
    urls.add(host + m.group(1))
for m in re.finditer(r'"(/static/js/[^"]+\.js)"', html):
    urls.add(host + m.group(1))
for u in sorted(urls):
    if re.search(r'(^|/)(vendor|runtime|polyfill|framework|react|chunk-vendors)', u):
        continue
    print(u)
PYEOF
JS_URLS=$(python3 "$EXTRACT_PY" "$HOST" "$HTML_FILE")
rm -f "$EXTRACT_PY"
[ -z "$JS_URLS" ] && { log "no .js refs"; exit 0; }

COUNT=0
for URL in $JS_URLS; do
  COUNT=$((COUNT+1))
  [ "$COUNT" -gt 20 ] && break
  JS_FILE="$OUT_DIR/${SLUG}_js_${COUNT}.js"
  curl -sk --max-time 12 "$URL" -o "$JS_FILE"
  [ ! -s "$JS_FILE" ] && continue
  SIZE=$(wc -c < "$JS_FILE" | tr -d ' ')
  [ "$SIZE" -lt 500 ] && continue

  echo "▶ $URL ($SIZE bytes)" >> "$OUT"

  # ── Pattern matching ─────────────────────────────────────────
  python3 - "$JS_FILE" "$URL" "$OUT" <<'PY'
import sys, re
js_path, url, out = sys.argv[1], sys.argv[2], sys.argv[3]
with open(js_path, errors='replace') as f: js = f.read()

patterns = {
    'AWS access key (AKIA/ASIA)': r'\b(AKIA|ASIA)[0-9A-Z]{16}\b',
    'AWS secret (near access key)': r'aws_secret_access_key["\'\s:=]+[A-Za-z0-9/+]{40}',
    'Google AIza key': r'AIza[0-9A-Za-z_-]{35}',
    'GitHub token (ghp/gho/ghs)': r'\bgh[pos]_[A-Za-z0-9]{36}\b',
    'GitHub fine-grained': r'\bgithub_pat_[A-Za-z0-9_]{70,}\b',
    'GitLab PAT (glpat)': r'\bglpat-[A-Za-z0-9_-]{20}\b',
    'Slack bot token': r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b',
    'Stripe sk_live': r'\bsk_live_[A-Za-z0-9]{24,}\b',
    'Stripe pk_live': r'\bpk_live_[A-Za-z0-9]{24,}\b',
    'Stripe sk_test': r'\bsk_test_[A-Za-z0-9]{24,}\b',
    'JWT': r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
    'Mapbox token': r'\bpk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b',
    'Sentry DSN': r'https://[a-f0-9]{20,}@[a-z0-9.-]+\.sentry\.io/\d+',
    'SendGrid': r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b',
    'Mailgun': r'\bkey-[a-f0-9]{32}\b',
    'Twilio SID': r'\bAC[a-f0-9]{32}\b',
    'Firebase RTDB URL': r'https://[a-z0-9-]+\.firebaseio\.com',
    'v1.public (AWS Location)': r'\bv1\.public\.[A-Za-z0-9_-]{40,}',
    # Contextual (SPA hardcoded client secret pattern) — require quoted literal value, min 20 chars, no obvious templating
    'clientSecret (SPA hardcoded client secret pattern)': r'["\']client[_-]?[Ss]ecret["\']\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']',
    'apiKey (quoted literal)': r'["\']api[_-]?[Kk]ey["\']\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']',
    'access_token (quoted literal)': r'["\']access[_-]?token["\']\s*[:=]\s*["\']([A-Za-z0-9_.-]{30,})["\']',
    'password (quoted literal)': r'["\']password["\']\s*[:=]\s*["\']([A-Za-z0-9!@#$%^&*_.-]{8,})["\']',
    'Authorization Bearer hardcoded': r'["\']Authorization["\']\s*[:=]\s*["\']?[Bb]earer [A-Za-z0-9._-]{20,}',
}

# Common junk values to ignore even if they match
JUNK_VALS = re.compile(r'^(?:password|example|test|sample|xxxx+|\*{4,}|placeholder|yourpassword|your[_-]?(?:api[_-]?)?key|undefined|null|changeme|secret|\${[^}]*}|{{[^}]*}}|process\.env|[Pp]laceholder)$')

hits_by_label = {}
for label, pat in patterns.items():
    for m in re.finditer(pat, js):
        val = m.group(1) if m.lastindex and m.groups() else m.group(0)
        # Filter known noise
        if JUNK_VALS.match(val): continue
        # Skip values that look like template placeholders
        if '{' in val or '}' in val or '$' in val: continue
        # Skip JWT-looking literal example
        if label == 'JWT' and ('example.com' in val or 'test' in val.lower()[:30]): continue
        # For quoted-literal password, require non-trivial entropy
        if label == 'password (quoted literal)':
            if len(set(val)) < 4: continue  # e.g. '••••••'
            if val.lower() in ('password','123456','admin','root','user','pass'): continue
        hits_by_label.setdefault(label, set()).add(val[:100])

with open(out, 'a') as fp:
    for label, vals in hits_by_label.items():
        for v in sorted(vals):
            fp.write(f"🔴 {label}: {v}  (in {url})\n")
PY
done

TOTAL=$(grep -c "^🔴" "$OUT" 2>/dev/null | head -1 | tr -d ' \n')
[ -z "$TOTAL" ] && TOTAL=0
log "=== done → $OUT ($TOTAL hits across $COUNT js files) ==="
