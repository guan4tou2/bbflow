#!/usr/bin/env bash
# hunt-ffuf-dirs.sh — Directory/file fuzzing via ffuf
#
# 改進:
#   - 自動偵測 404 response size → -fs 過濾（減少 FP）
#   - 三層掃描: BB-high-ROI list → SecLists raft-medium → API endpoints
#   - -recursion 對有趣路徑深入
#   - -fw 過濾 word count
#   - 支援 FFUF_COOKIE / FFUF_HEADERS 做 authenticated 掃描
#
# Usage:
#   OUT_DIR=/path FFUF_COOKIE="session=xxx" hunt-ffuf-dirs.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-ffuf-$$}"
mkdir -p "$OUT_DIR"

FFUF="$(command -v ffuf 2>/dev/null || echo '')"
FEROX="$(command -v feroxbuster 2>/dev/null || echo '')"

if [ -z "$FFUF" ] && [ -z "$FEROX" ]; then
  echo "✗ ffuf/feroxbuster not found (go install github.com/ffuf/ffuf/v2@latest)"
  exit 0
fi

COOKIE="${FFUF_COOKIE:-}"
EXTRA_HEADER="${FFUF_HEADER:-}"

# Wordlist 優先序 — 繼承 bbflow export 或自動偵測
if [ -z "${SECLISTS:-}" ]; then
  for _sl in \
    "$HOME/Tools/SecLists" \
    "$(brew --prefix seclists 2>/dev/null)/share/seclists" \
    "/opt/homebrew/share/seclists" \
    "/usr/local/share/seclists" \
    "/usr/share/seclists"; do
    [ -d "$_sl/Discovery/Web-Content" ] && SECLISTS="$_sl" && break
  done
  SECLISTS="${SECLISTS:-}"
fi
WL_RAFT_MEDIUM="${SECLISTS:+$SECLISTS/Discovery/Web-Content/raft-medium-files.txt}"
WL_RAFT_DIRS="${SECLISTS:+$SECLISTS/Discovery/Web-Content/raft-medium-directories.txt}"
WL_API="${SECLISTS:+$SECLISTS/Discovery/Web-Content/api/api-endpoints-res.txt}"
WL_PARAMS="${SECLISTS:+$SECLISTS/Discovery/Web-Content/burp-parameter-names.txt}"

# ── BB 高 ROI 自訂 wordlist ──────────────────────────────
BB_WL="$OUT_DIR/bb_paths.txt"
cat > "$BB_WL" <<'WORDLIST'
.env
.env.local
.env.production
.env.staging
.env.backup
.env.example
.git/config
.git/HEAD
.gitignore
.htpasswd
.htaccess
config.json
config.yaml
config.yml
settings.json
settings.yaml
appsettings.json
appsettings.Development.json
web.config
secrets.json
credentials.json
docker-compose.yml
docker-compose.yaml
.dockerenv
terraform.tfstate
terraform.tfstate.backup
package.json
package-lock.json
yarn.lock
Gemfile
requirements.txt
composer.json
dump.sql
backup.sql
database.sql
db.sql
backup.zip
backup.tar.gz
phpinfo.php
info.php
test.php
debug.php
admin
administrator
admin/login
admin/dashboard
wp-admin
wp-login.php
wp-config.php.bak
xmlrpc.php
phpmyadmin
adminer.php
swagger
swagger-ui
api-docs
graphql
graphiql
actuator/env
actuator/health
actuator/mappings
actuator/heapdump
server-status
server-info
.well-known/security.txt
robots.txt
sitemap.xml
crossdomain.xml
_profiler
__debug__
telescope
horizon
console
shell
Fusion/variables.xml
CFIDE/administrator
v1/api-docs
v2/api-docs
v3/api-docs
api/swagger.json
api/openapi.json
api/v1
api/v2
graphql/playground
WORDLIST

# ── detect 404 response size for filtering ──────────────
RAND_PATH=$(cat /dev/urandom | tr -dc 'a-z' | head -c 16 2>/dev/null || echo "zzznotfound")
BASELINE_SIZE=$(curl -s -o /dev/null -w "%{size_download}" \
  "${TARGET}/${RAND_PATH}" --max-time 5 2>/dev/null || echo "0")

# Build common ffuf flags
BASE_FLAGS=(
  "-mc" "200,201,204,301,302,307,401,403,405"
  "-fc" "404,429,503"
  "-t" "20"
  "-timeout" "10"
  "-rate" "15"
  "-s"
)

# Filter by 404 size if non-zero
[ "${BASELINE_SIZE:-0}" -gt 100 ] && BASE_FLAGS+=("-fs" "$BASELINE_SIZE")

# Auth flags
[ -n "$COOKIE" ] && BASE_FLAGS+=("-H" "Cookie: $COOKIE")
[ -n "$EXTRA_HEADER" ] && BASE_FLAGS+=("-H" "$EXTRA_HEADER")

if [ -n "$FFUF" ]; then
  # ── ffuf: Layer 1 BB high-ROI ───────────────────────
  "$FFUF" \
    -u "${TARGET}/FUZZ" \
    -w "$BB_WL" \
    "${BASE_FLAGS[@]}" \
    -of json -o "$OUT_DIR/ffuf_bb.json" 2>/dev/null || true

  # ── ffuf: Layer 2 SecLists raft-medium ──────────────
  if [ -f "$WL_RAFT_MEDIUM" ]; then
    "$FFUF" \
      -u "${TARGET}/FUZZ" \
      -w "$WL_RAFT_MEDIUM" \
      "${BASE_FLAGS[@]}" \
      -of json -o "$OUT_DIR/ffuf_raft.json" 2>/dev/null || true
  fi

  # ── ffuf: Layer 3 API endpoints ─────────────────────
  if [ -f "$WL_API" ]; then
    "$FFUF" \
      -u "${TARGET}/FUZZ" \
      -w "$WL_API" \
      "${BASE_FLAGS[@]}" \
      -mc "200,201,204" \
      -of json -o "$OUT_DIR/ffuf_api.json" 2>/dev/null || true
  fi

elif [ -n "$FEROX" ]; then
  # ── feroxbuster fallback (recursive, Rust) ───────────
  FEROX_FLAGS=( "--silent" "--auto-tune" "--threads" "20" "--timeout" "10"
                "--status-codes" "200,201,204,301,302,307,401,403,405"
                "--rate-limit" "15" )
  [ -n "$COOKIE" ] && FEROX_FLAGS+=("--cookies" "$COOKIE")
  [ -n "$EXTRA_HEADER" ] && FEROX_FLAGS+=("--headers" "$EXTRA_HEADER")
  [ -f "$WL_RAFT_MEDIUM" ] && FEROX_FLAGS+=("--wordlist" "$WL_RAFT_MEDIUM")

  "$FEROX" \
    --url "$TARGET" \
    "${FEROX_FLAGS[@]}" \
    --output "$OUT_DIR/ferox_out.txt" 2>/dev/null || true

  # Convert feroxbuster output to ffuf-like JSON for unified parser
  python3 - "$OUT_DIR/ferox_out.txt" "$OUT_DIR/ffuf_bb.json" <<'CONV' 2>/dev/null || true
import json, sys, re
results = []
try:
    for line in open(sys.argv[1]):
        m = re.match(r'(\d{3})\s+\S+\s+\S+\s+\S+\s+(https?://\S+)', line)
        if m:
            results.append({"status": int(m.group(1)), "url": m.group(2),
                            "length": 0, "words": 0})
except Exception:
    pass
json.dump({"results": results}, open(sys.argv[2], "w"))
CONV
fi

# ── Parse all results ──────────────────────────────────
python3 - <<'PYEOF' 2>/dev/null || true
import json, os, glob

out_dir = os.environ.get('OUT_DIR', '/tmp')
seen = set()
HIGH_VALUE = {'.env', '.git', 'config', 'backup', 'dump', 'sql', 'phpinfo',
              'admin', 'terraform', 'secrets', 'credentials', 'docker'}

for jf in sorted(glob.glob(f'{out_dir}/ffuf_*.json')):
    try:
        data = json.load(open(jf))
        for r in data.get('results', []):
            url = r.get('url', '')
            status = r.get('status', 0)
            length = r.get('length', 0)
            words = r.get('words', 0)
            if url in seen or length < 20:
                continue
            seen.add(url)
            is_high = any(h in url.lower() for h in HIGH_VALUE)
            if status == 200 and is_high:
                print(f'🔴 FFUF [200-high] {url} ({length}b)')
            elif status == 200:
                print(f'🔴 FFUF [200] {url} ({length}b)')
            elif status in (301, 302, 307):
                print(f'🟡 FFUF [{status}] {url} ({length}b)')
            elif status in (401, 403):
                print(f'🟡 FFUF [{status}-auth-required] {url} ({length}b)')
    except Exception:
        pass
PYEOF
