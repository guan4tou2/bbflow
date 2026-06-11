#!/usr/bin/env bash
# setup_python_tools.sh — 用 uv tool install 裝 bbflow Python 工具（一律 uv）
#
# 用法:
#   scripts/setup_python_tools.sh            # 裝到 uv tool bin (~/.local/bin)
#   scripts/setup_python_tools.sh --system   # 裝後 sudo symlink → /usr/local/bin（VPS）
#
# 政策（見 ENVIRONMENT.md）: Python 工具一律 uv，不用 pip/pipx/brew。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST="${BBFLOW_PYLIST:-$HERE/../python-tools.txt}"
[ -f "$LIST" ] || { echo "找不到 python-tools.txt ($LIST)"; exit 1; }

UV="$(command -v uv || echo "$HOME/.local/bin/uv")"
[ -x "$UV" ] || { echo "需要 uv: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }

SYSTEM=0
[ "${1:-}" = "--system" ] && SYSTEM=1

while read -r spec; do
  case "$spec" in ''|\#*) continue ;; esac
  name="$(echo "$spec" | sed 's|.*/||; s|\.git$||')"
  echo ">> uv tool install $spec"
  "$UV" tool install "$spec" --force
  if [ "$SYSTEM" = "1" ] && [ -x "$HOME/.local/bin/$name" ]; then
    sudo ln -sf "$HOME/.local/bin/$name" "/usr/local/bin/$name" && echo "   → symlink /usr/local/bin/$name"
  fi
done < "$LIST"
echo "完成。uv tool list 檢視；驗證: bbflow doctor"
