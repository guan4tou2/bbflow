#!/usr/bin/env bash
# setup_pinned_tools.sh — 依 tools.lock go install 鎖定版本（converge 本機到 lock）
# 用途: 新機器初始化、或對齊本地/VPS 版本。需要 go。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="${BBFLOW_LOCK:-$HERE/../tools.lock}"
[ -f "$LOCK" ] || { echo "找不到 tools.lock ($LOCK)"; exit 1; }
command -v go >/dev/null 2>&1 || { echo "需要 go"; exit 1; }

while read -r bin want mod _rest; do
  case "$bin" in ''|\#*) continue ;; esac
  # major-locked (vN.x) → 用 @latest（go 在該 module major path 內解析最新小版本）
  case "$want" in v[0-9]*.x) want=latest ;; esac
  echo ">> go install ${mod}@${want}"
  go install "${mod}@${want}"
done < "$LOCK"
echo "完成。驗證: scripts/check_tool_versions.sh"
