#!/usr/bin/env bash
# hunt-electron-open-external.sh
# Electron IM App — shell.openExternal 靜態分析快篩
#
# 用法:
#   bash hunt-electron-open-external.sh <asar_or_dir> [app_name]
#
# 範例:
#   bash hunt-electron-open-external.sh app.asar "Juiker"
#   bash hunt-electron-open-external.sh /tmp/asar_extracted/ "Mattermost"
#
# 輸出:
#   GRADE_UNKNOWN: 無法判斷（需人工看）
#   GRADE_NONE:    找不到 shell.openExternal
#   GRADE_B:       靜態確認，無驗證
#   GRADE_MITIG:   有驗證邏輯，可能已修

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

TARGET="${1:-}"
APP_NAME="${2:-unknown}"
TMPDIR_ASAR="/tmp/electron_hunt_$$"

usage() {
  echo "Usage: $0 <app.asar | extracted_dir> [app_name]" >&2
  exit 1
}

[[ -z "$TARGET" ]] && usage

# ── 1. 解包 ASAR（若輸入是 .asar 檔案）────────────────────────────────────────
if [[ "$TARGET" == *.asar ]]; then
  echo "[*] Extracting ASAR: $TARGET"
  mkdir -p "$TMPDIR_ASAR"
  if ! npx --yes @electron/asar extract "$TARGET" "$TMPDIR_ASAR" 2>/dev/null; then
    echo "[!] asar extract failed. Install: npm install -g @electron/asar" >&2
    exit 1
  fi
  SEARCH_DIR="$TMPDIR_ASAR"
else
  SEARCH_DIR="$TARGET"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  Electron shell.openExternal Hunter — $APP_NAME"
echo "  Search dir: $SEARCH_DIR"
echo "════════════════════════════════════════════════════════"

# ── 2. 確認是否是 Electron App ────────────────────────────────────────────────
echo ""
echo "[1/5] Electron fingerprint..."
if ls "$SEARCH_DIR/package.json" &>/dev/null; then
  MAIN_ENTRY=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('main','?'), d.get('version','?'), d.get('name','?'))" \
    "$SEARCH_DIR/package.json" 2>/dev/null || echo "?")
  echo "      package.json: $MAIN_ENTRY"
else
  echo "      package.json: not found (may be compiled)"
fi

# ── 3. 快篩 sink ──────────────────────────────────────────────────────────────
echo ""
echo "[2/5] Scanning for shell.openExternal sinks..."

SINK_FILES=$(grep -rl "openExternal\|shell-openExternal\|shell\.open" \
  "$SEARCH_DIR" --include="*.js" 2>/dev/null \
  | grep -v "node_modules" | grep -v "\.min\.js" || true)

if [[ -z "$SINK_FILES" ]]; then
  echo "      ❌ shell.openExternal NOT FOUND → GRADE_NONE"
  echo ""
  echo "RESULT: GRADE_NONE — $APP_NAME 無 shell.openExternal，跳過"
  [[ -d "$TMPDIR_ASAR" ]] && rm -rf "$TMPDIR_ASAR"
  exit 0
fi

echo "      ✅ Found in:"
echo "$SINK_FILES" | sed 's/^/         /'

# ── 4. 深度分析每個 sink 檔案 ─────────────────────────────────────────────────
echo ""
echo "[3/5] Analyzing call sites..."

HAS_VALIDATION=0
HAS_UNVALIDATED=0
UNVALIDATED_SNIPPETS=""

while IFS= read -r f; do
  echo ""
  echo "  ── File: ${f#$SEARCH_DIR/}"

  # 取出 openExternal 附近 10 行
  SNIPPETS=$(grep -n "openExternal\|shell-openExternal\|shell\.open" "$f" | head -10)
  echo "$SNIPPETS" | sed 's/^/     /'

  # 判斷是否有驗證邏輯（scheme allowlist / startsWith / URL parse）
  CONTEXT=$(grep -A5 -B5 "openExternal" "$f" 2>/dev/null | head -40)
  if echo "$CONTEXT" | grep -qiE "startsWith|https:|allowlist|whitelist|protocol|url\.parse|new URL|scheme|validateUrl|safeUrl|allowedProtocol"; then
    echo "     ⚠️  可能有驗證邏輯（需人工確認）"
    HAS_VALIDATION=1
  else
    echo "     🔴 無明顯驗證 — 候選 sink"
    HAS_UNVALIDATED=1
    UNVALIDATED_SNIPPETS="${UNVALIDATED_SNIPPETS}\n[${f#$SEARCH_DIR/}]\n${SNIPPETS}\n"
  fi
done <<< "$SINK_FILES"

# ── 5. 確認 IPC 來源 ──────────────────────────────────────────────────────────
echo ""
echo "[4/5] Checking IPC registration..."

IPC_HITS=$(grep -rn "ipcMain.on\|ipcMain.handle\|hub\.on\|hubConnection" \
  "$SEARCH_DIR" --include="*.js" 2>/dev/null \
  | grep -v node_modules \
  | grep -i "shell\|open\|external\|navigate" || true)

if [[ -n "$IPC_HITS" ]]; then
  echo "      IPC handlers related to shell/open:"
  echo "$IPC_HITS" | sed 's/^/      /'
else
  echo "      (no direct IPC hits for shell/open — may use SignalR/hub)"
fi

# ── 6. webPreferences 安全設定 ────────────────────────────────────────────────
echo ""
echo "[5/5] webPreferences security..."

WP_HITS=$(grep -rn "contextIsolation\|nodeIntegration\|sandbox" \
  "$SEARCH_DIR" --include="*.js" 2>/dev/null \
  | grep -v node_modules | grep -v "\.min\.js" | head -20 || true)

if [[ -n "$WP_HITS" ]]; then
  echo "$WP_HITS" | sed 's/^/      /'
else
  echo "      (no explicit webPreferences found — default: contextIsolation=true in Electron 12+)"
fi

# ── 7. 結論 ──────────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════"
if [[ "$HAS_UNVALIDATED" -eq 1 ]]; then
  echo "  RESULT: 🟠 GRADE_B CANDIDATE — $APP_NAME"
  echo ""
  echo "  無驗證的 sink 摘要："
  echo -e "$UNVALIDATED_SNIPPETS" | sed 's/^/  /'
  echo ""
  echo "  下一步："
  echo "    1. 人工追呼叫鏈（確認 url 來自攻擊者可控輸入）"
  echo "    2. Windows VM + impacket-smbserver → search-ms: 動態確認"
  echo "    3. 寫 Grade B 報告（SOP.md 步驟 6-7）"
elif [[ "$HAS_VALIDATION" -eq 1 ]]; then
  echo "  RESULT: ⚠️  GRADE_UNKNOWN — $APP_NAME（有驗證邏輯，需人工確認是否可繞過）"
else
  echo "  RESULT: ❌ GRADE_NONE — $APP_NAME（無 unvalidated sink）"
fi
echo "════════════════════════════════════════════════════════"
echo ""

[[ -d "$TMPDIR_ASAR" ]] && rm -rf "$TMPDIR_ASAR"
