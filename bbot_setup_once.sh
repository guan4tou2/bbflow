#!/usr/bin/env bash
# ============================================================
# bbot_setup_once.sh — 一次性初始化 bbot（新環境必跑）
#
# 解決問題：
#   - bbot 第一次跑會要 sudo 密碼安裝 core deps
#   - 本腳本繞過 sudo 需求，讓 bbot 可非互動式批量執行
#   - 安裝缺少的 Python 依賴（ansible/baddns/pyopenssl/asyncpg）
#   - 建立 deps cache 讓 bbot 跳過 install_core_deps
#   - 複製 preset 到 ~/.config/bbot/presets/
#
# 用法（只需跑一次）：
#   ./tools/bbot_setup_once.sh
# ============================================================

set -euo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BBOT="$(command -v bbot 2>/dev/null || echo "$HOME/.local/bin/bbot")"

echo "======================================"
echo "  bbot 一次性初始化"
echo "======================================"

# ── 1. 確認 bbot 已安裝 ──────────────────────────────────────
if [ ! -x "$BBOT" ]; then
  echo "[!] bbot 未安裝，請先執行: pipx install bbot"
  exit 1
fi
BBOT_VER=$("$BBOT" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
echo "[+] bbot 版本: $BBOT_VER"

# ── 2. 安裝 bbot 依賴（pipx inject）────────────────────────────
echo "[*] 安裝 Python 依賴..."
INJECTED=""
for pkg in ansible baddns pyopenssl asyncpg; do
  if pipx inject bbot "$pkg" 2>&1 | grep -q "done"; then
    INJECTED="$INJECTED $pkg"
  fi
done
echo "[+] 已注入到 bbot venv:$INJECTED"

# ── 3. 繞過 sudo：建立 deps cache 讓 bbot 跳過 install_core_deps ─
echo "[*] 建立 bbot core deps 快取（繞過 sudo）..."
python3 - << 'PYEOF'
import sys
sys.path.insert(0, '')

# Find bbot's site-packages
import glob
bbot_paths = glob.glob(f"{__import__('pathlib').Path.home()}/.local/pipx/venvs/bbot/lib/python*/site-packages")
if bbot_paths:
    sys.path.insert(0, bbot_paths[0])

try:
    import mmh3
    import orjson
    from pathlib import Path
    from bbot.core.helpers.depsinstaller.installer import DepsInstaller

    core_deps_hash = str(mmh3.hash(orjson.dumps(DepsInstaller.CORE_DEPS, option=orjson.OPT_SORT_KEYS)))
    cache_dir = Path.home() / ".bbot" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_dir / core_deps_hash
    cache_file.touch()
    print(f"[+] Cache created: {cache_file}")
except Exception as e:
    print(f"[!] Cache creation failed: {e}")
    print("    (bbot will still work, just may ask for sudo on first run)")
PYEOF

# ── 4. 複製 preset 到 ~/.config/bbot/presets/ ─────────────────
PRESET_SRC="$TOOLS_DIR/bbot_preset_bugbounty.yml"
PRESET_DEST="$HOME/.config/bbot/presets/bugbounty.yml"
if [ -f "$PRESET_SRC" ]; then
  cp "$PRESET_SRC" "$PRESET_DEST"
  echo "[+] Preset installed: $PRESET_DEST"
  echo "    使用方式: bbot -t target.com -p bugbounty --no-deps"
fi

# ── 5. 驗證 bbot 可正常啟動 ──────────────────────────────────
echo ""
echo "[*] 驗證 bbot 啟動（dry-run）..."
OUTPUT=$("$BBOT" -t example.com -p bugbounty --no-deps --dry-run 2>&1 || true)
if echo "$OUTPUT" | grep -q "Loaded.*scan modules"; then
  MOD_COUNT=$(echo "$OUTPUT" | grep "Loaded.*scan modules" | grep -oE '[0-9]+/[0-9]+' | head -1)
  SUCC_COUNT=$(echo "$OUTPUT" | grep "Setup succeeded" | grep -oE '[0-9]+/[0-9]+' | head -1)
  echo "[+] ✅ bbot 正常！Scan modules: $MOD_COUNT | Setup: $SUCC_COUNT"
elif echo "$OUTPUT" | grep -q "ERRR"; then
  echo "[!] bbot 有 error，但可能仍可執行："
  echo "$OUTPUT" | grep "ERRR" | head -5
else
  echo "[?] 無法確認，請手動執行: bbot -t example.com -p bugbounty --no-deps --dry-run"
fi

# ── 6. 安裝 openpyxl / tldextract（Excel 解析）────────────────
echo ""
echo "[*] 安裝 Excel 解析工具..."
pip3 install --break-system-packages openpyxl tldextract -q 2>&1 | tail -2 || \
  pip3 install openpyxl tldextract -q 2>&1 | tail -2 || \
  echo "[!] 請手動: pip3 install openpyxl tldextract"
python3 -c "import openpyxl; print('[+] openpyxl 可用')" 2>/dev/null || echo "[!] openpyxl 安裝失敗"

echo ""
echo "======================================"
echo "  設定完成！"
echo ""
echo "  快速使用："
echo "  1. Excel → targets:"
echo "     python3 tools/excel_to_targets.py targets.xlsx"
echo ""
echo "  2. bbot 批量掃描:"
echo "     bbot -t recon/targets.txt -p bugbounty --no-deps"
echo ""
echo "  3. 完整批量（bbot + auto_hunt）:"
echo "     ./tools/batch_hunt.sh targets.xlsx"
echo ""
echo "  4. 單一 target 深挖:"
echo "     ./tools/auto_hunt.sh target.com --mode full"
echo "======================================"
