#!/usr/bin/env bash
# hunt-backup-files.sh — 備份檔案 / 歷史版本洩漏探測
# 來源：xray dirscan backup 規則 + 實戰常見 backup 命名慣例
#
# 設計：
#   1. 靜態候選：常見 backup.zip/www.tar.gz/db.sql 等 40 個命名
#   2. 動態候選：從 target hostname 衍生（target.com.zip / target.tar.gz / target.sql）
#   3. 以 Index-of / 目錄列表 fallback：/backup/ /backups/ /bak/ /db/ /upload/
#   4. Content-type + size 雙驗證（避免 SPA 回傳 200 HTML 當成 hit）
#
# 用法：
#   ./hunt-backup-files.sh https://target
#   ./hunt-backup-files.sh https://target extra_name1 extra_name2   # 附加候選
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host> [extra_name...]"; exit 1; }
HOST="${HOST%/}"
shift
EXTRA_NAMES=("$@")

OUT_DIR="${OUT_DIR:-./backup_files_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

# 萃取 hostname → 動態候選字根
HOSTNAME=$(echo "$HOST" | sed -E 's|^https?://||; s|:.*$||; s|/.*$||')
ROOT=$(echo "$HOSTNAME" | awk -F. '{ if (NF>=2) print $(NF-1); else print $1 }')  # e.g. example
FULL=$(echo "$HOSTNAME" | sed 's/^www\.//')                                       # e.g. example.com

# ── 可執行判斷：HTTP 2xx + Content-Length > 512 + Content-Type 非 html/json ──
check() {
  local path="$1"
  local URL="${HOST}${path}"
  # HEAD 先看
  local HDR
  HDR=$(curl -skI --max-time 6 "$URL" 2>/dev/null)
  local CODE CT CL
  CODE=$(echo "$HDR" | head -1 | awk '{print $2}')
  CT=$(echo "$HDR" | grep -i '^content-type:' | head -1 | tr -d '\r' | awk '{print tolower($2)}')
  CL=$(echo "$HDR" | grep -i '^content-length:' | head -1 | tr -d '\r' | awk '{print $2}')

  [[ ! "$CODE" =~ ^2 ]] && return 1
  # 過濾 HTML/JSON/plain（避免 SPA 無腦 200）
  if echo "$CT" | grep -qiE 'text/html|application/json|text/plain'; then
    # 例外：.sql/.env/.config 這類 plain text 仍要看
    case "$path" in
      *.sql|*.env|*.config|*.conf|*.ini|*.xml|*.yaml|*.yml)
        :  # pass through
        ;;
      *)
        return 1
        ;;
    esac
  fi
  # Content-Length 要 > 512 才算（排除 0-byte fake）
  if [ -n "$CL" ] && [ "$CL" -lt 512 ] 2>/dev/null; then
    return 1
  fi
  # 真實抓前 256 bytes 確認 magic bytes
  local MAGIC
  MAGIC=$(curl -sk --max-time 8 -r 0-256 "$URL" 2>/dev/null | head -c 32 | od -An -tx1 | tr -d ' \n' | head -c 64)
  case "$path" in
    *.zip)   echo "$MAGIC" | grep -qiE '^504b0304' || return 1;;
    *.rar)   echo "$MAGIC" | grep -qiE '^526172' || return 1;;
    *.7z)    echo "$MAGIC" | grep -qiE '^377abcaf' || return 1;;
    *.gz|*.tgz|*.tar.gz)
             echo "$MAGIC" | grep -qiE '^1f8b' || return 1;;
    *.tar)   echo "$MAGIC" | grep -qiE '7573746172' || return 1;;  # "ustar"
    *.sql|*.env|*.conf|*.ini|*.yaml|*.yml|*.xml|*.config)
             # 純文字，至少要含有可讀性內容
             local SNIP
             SNIP=$(curl -sk --max-time 8 -r 0-512 "$URL" 2>/dev/null | head -c 256 | tr -d '\r')
             case "$path" in
               *.sql)  echo "$SNIP" | grep -qE 'CREATE TABLE|INSERT INTO|DROP TABLE|mysqldump|/\*!' || return 1;;
               *.env)  echo "$SNIP" | grep -qE '^[A-Z_][A-Z0-9_]*=' || return 1;;
               *.xml)  echo "$SNIP" | grep -qE '<\?xml|<[a-zA-Z]' || return 1;;
               *.conf|*.config|*.ini)
                       echo "$SNIP" | grep -qE '^\[|^[a-zA-Z_][a-zA-Z0-9_]*\s*=' || return 1;;
               *.yaml|*.yml)
                       echo "$SNIP" | grep -qE '^[a-zA-Z_][a-zA-Z0-9_]*:' || return 1;;
             esac
             ;;
  esac
  hit "[P1-CRIT] BACKUP $URL [$CODE] (type=${CT:-?}, size=${CL:-?})"
  return 0
}

log "=== Backup file hunt: $HOST (root=$ROOT, full=$FULL) ==="

# ═══════════════════════════════════════════════════════════════
# 靜態候選（41 個）— 最常見的檔名
# ═══════════════════════════════════════════════════════════════
STATIC=(
  "/backup.zip" "/backup.tar.gz" "/backup.tar" "/backup.rar" "/backup.7z" "/backup.sql"
  "/bak.zip" "/bak.tar.gz"
  "/www.zip" "/www.tar.gz" "/www.rar" "/www.7z" "/www.tar"
  "/web.zip" "/web.tar.gz" "/web.rar"
  "/wwwroot.zip" "/wwwroot.tar.gz" "/wwwroot.rar"
  "/website.zip" "/website.tar.gz"
  "/site.zip" "/site.tar.gz" "/site.rar"
  "/html.zip" "/html.tar.gz"
  "/public_html.zip" "/public_html.tar.gz"
  "/db.sql" "/db.zip" "/dump.sql" "/dump.zip"
  "/database.sql" "/database.zip"
  "/data.sql" "/data.zip"
  "/admin.zip" "/admin.tar.gz"
  "/src.zip" "/src.tar.gz"
  "/app.zip" "/app.tar.gz"
  "/release.zip" "/release.tar.gz"
  "/production.zip" "/production.tar.gz"
  "/prod.zip" "/prod.tar.gz"
  "/dev.zip" "/dev.tar.gz"
  "/staging.zip" "/staging.tar.gz"
  "/test.zip" "/test.tar.gz"
  "/old.zip" "/old.tar.gz"
  "/upload.zip" "/uploads.zip"
  "/files.zip" "/file.zip"
)

for p in "${STATIC[@]}"; do
  check "$p" || true
done

# ═══════════════════════════════════════════════════════════════
# 動態候選（hostname 衍生）
# ═══════════════════════════════════════════════════════════════
log "• Dynamic candidates: root=$ROOT full=$FULL"
DYNAMIC=(
  "/${ROOT}.zip"          "/${ROOT}.tar.gz"       "/${ROOT}.rar"       "/${ROOT}.7z"      "/${ROOT}.sql"
  "/${FULL}.zip"          "/${FULL}.tar.gz"       "/${FULL}.rar"       "/${FULL}.7z"      "/${FULL}.sql"
  "/${ROOT}_backup.zip"   "/${FULL}_backup.zip"
  "/${ROOT}-backup.zip"   "/${FULL}-backup.zip"
  "/${ROOT}_bak.zip"      "/${FULL}_bak.zip"
  "/${ROOT}_db.sql"       "/${FULL}_db.sql"
  "/${ROOT}_prod.zip"     "/${FULL}_prod.zip"
)
for p in "${DYNAMIC[@]}"; do
  check "$p" || true
done

# ═══════════════════════════════════════════════════════════════
# 使用者附加候選
# ═══════════════════════════════════════════════════════════════
for NAME in "${EXTRA_NAMES[@]}"; do
  [ -z "$NAME" ] && continue
  log "• Extra candidate: $NAME"
  # 自動加上副檔名變化
  for EXT in ".zip" ".tar.gz" ".bak" ".old" "~"; do
    check "/${NAME}${EXT}" || true
  done
done

# ═══════════════════════════════════════════════════════════════
# 目錄列表（Apache / Nginx autoindex 開啟）
# ═══════════════════════════════════════════════════════════════
log "• Checking Index-of / autoindex directories"
INDEX_DIRS=(
  "/backup/" "/backups/" "/bak/" "/db/" "/database/" "/dumps/"
  "/upload/" "/uploads/" "/files/" "/file/" "/old/" "/archive/" "/archives/"
  "/.git/" "/.svn/" "/temp/" "/tmp/" "/test/"
)
for d in "${INDEX_DIRS[@]}"; do
  URL="${HOST}${d}"
  CODE=$(curl -sk --max-time 6 -o /tmp/.bk_$$ -w "%{http_code}" "$URL" 2>/dev/null)
  BODY=$(head -c 2000 /tmp/.bk_$$ 2>/dev/null)
  rm -f /tmp/.bk_$$
  if [[ "$CODE" =~ ^2 ]] && echo "$BODY" | grep -qE '<title>Index of|Directory listing|autoindex'; then
    hit "[P2-HIGH] Directory listing → $URL"
    # 從頁面抽出檔名
    echo "$BODY" | grep -oE 'href="[^"?/][^"]*"' | head -20 | sed 's|href="|       →  |;s|"$||' >> "$OUT"
  fi
done

log "=== done — see $OUT ==="
