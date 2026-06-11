#!/usr/bin/env bash
# setup_pinned_tools.sh — 依 tools.lock go install 鎖定版本（converge 本機到 lock）
#
# 用法:
#   scripts/setup_pinned_tools.sh            # 裝到 GOBIN (~/go/bin)，需 ~/go/bin 在 PATH
#   scripts/setup_pinned_tools.sh --system   # 裝後 sudo cp 到 /usr/local/bin（VPS canonical）
#
# 路徑慣例（見 ENVIRONMENT.md）:
#   VPS  = /usr/local/bin 為 canonical（PATH 優先，bbflow 用這個）→ 用 --system
#   本地 = 依現有 PATH（brew/go/pdtm），不強制 --system
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="${BBFLOW_LOCK:-$HERE/../tools.lock}"
[ -f "$LOCK" ] || { echo "找不到 tools.lock ($LOCK)"; exit 1; }
command -v go >/dev/null 2>&1 || { echo "需要 go"; exit 1; }

SYSTEM=0
[ "${1:-}" = "--system" ] && SYSTEM=1
GOBIN="$(go env GOBIN)"; [ -z "$GOBIN" ] && GOBIN="$(go env GOPATH)/bin"

while read -r bin want mod _rest; do
  case "$bin" in ''|\#*) continue ;; esac
  # major-locked (vN.x) → 用 @latest（go 在該 module major path 內解析最新小版本）
  case "$want" in v[0-9]*.x) want=latest ;; esac
  echo ">> go install ${mod}@${want}"
  go install "${mod}@${want}"
  if [ "$SYSTEM" = "1" ] && [ -x "$GOBIN/$bin" ]; then
    sudo cp "$GOBIN/$bin" "/usr/local/bin/$bin" && echo "   → promoted /usr/local/bin/$bin"
    rm -f "$GOBIN/$bin"   # 不留 go/bin 孤兒（避免雙 binary 混淆）
  fi
done < "$LOCK"
echo "完成。驗證: scripts/check_tool_versions.sh"
