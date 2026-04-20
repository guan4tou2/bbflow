#!/usr/bin/env bash
# hunt-ffuf-dirs.sh — Directory + file fuzzing via ffuf
#
# 目標：找常見高價值路徑（admin panels, backups, config files, debug endpoints）
# 不跑通用 wordlist（太慢），只跑 bug-bounty 高 ROI 路徑清單
#
# Usage: OUT_DIR=/path hunt-ffuf-dirs.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-ffuf-$$}"
mkdir -p "$OUT_DIR"

FFUF="$(command -v ffuf 2>/dev/null || echo '')"
[ -z "$FFUF" ] && { echo "✗ ffuf not found (brew install ffuf)"; exit 0; }

WORDLIST="$OUT_DIR/bb_paths.txt"

# Bug bounty high-ROI path list（精選，不是通用 dirbuster）
cat > "$WORDLIST" <<'WORDLIST_EOF'
.env
.env.local
.env.production
.env.staging
.env.backup
.git/config
.git/HEAD
.gitignore
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
Dockerfile
.dockerenv
terraform.tfstate
terraform.tfstate.backup
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
admin/
administrator/
admin/login
wp-admin/
wp-login.php
wp-config.php.bak
xmlrpc.php
phpmyadmin/
adminer.php
swagger/
swagger-ui/
api-docs
api-docs/
graphql
graphiql
actuator/env
actuator/health
actuator/mappings
actuator/heapdump
.well-known/security.txt
robots.txt
sitemap.xml
crossdomain.xml
clientaccesspolicy.xml
server-status
server-info
_profiler/
__debug__/
telescope/
horizon/
_ignition/health-check
console/
shell/
cgi-bin/
Fusion/variables.xml
CFIDE/administrator/
WORDLIST_EOF

FFUF_OUT="$OUT_DIR/ffuf_results.json"

"$FFUF" \
  -u "${TARGET}/FUZZ" \
  -w "$WORDLIST" \
  -mc 200,201,204,301,302,307,401,403 \
  -fc 404,429,503 \
  -t 20 \
  -timeout 10 \
  -rate 20 \
  -o "$FFUF_OUT" \
  -of json \
  -s 2>/dev/null || true

# Parse hits
if [ -s "$FFUF_OUT" ]; then
  python3 -c "
import json, sys
try:
    data = json.load(open('$FFUF_OUT'))
    for r in data.get('results', []):
        status = r.get('status', 0)
        url = r.get('url', '')
        length = r.get('length', 0)
        # Skip common false positives
        if length < 20:
            continue
        # Prioritize interesting status codes
        if status in (200, 301, 302, 307, 401, 403):
            flag = '🔴' if status == 200 else '🟡'
            print(f'{flag} FFUF [{status}] {url} ({length}b)')
except Exception as e:
    pass
" 2>/dev/null || true
fi
