#!/usr/bin/env bash
# check_tool_versions.sh — 比對已安裝工具版本 vs tools.lock，漂移就 warn（non-blocking）
# 用途: bbflow doctor 呼叫；也可獨立跑。回傳 0=全對齊，1=有漂移/缺失。
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCK="${BBFLOW_LOCK:-$HERE/../tools.lock}"
[ -f "$LOCK" ] || { echo "[check] 找不到 tools.lock ($LOCK)"; exit 0; }

drift=0; missing=0; ok=0
while read -r bin want mod _rest; do
  case "$bin" in ''|\#*) continue ;; esac
  path="$(command -v "$bin" 2>/dev/null || true)"
  [ -z "$path" ] && [ -x "$HOME/go/bin/$bin" ] && path="$HOME/go/bin/$bin"
  if [ -z "$path" ] || [ ! -x "$path" ]; then
    printf "  [MISSING] %-12s want=%s\n" "$bin" "$want"; missing=$((missing+1)); continue
  fi
  case "$want" in
    latest|v[0-9]*.x)
      printf "  [flex]    %-12s %s (彈性，不強制比對)\n" "$bin" "$want"; ok=$((ok+1)); continue ;;
  esac
  case "$_rest" in
    *noverify*)
      printf "  [pin~]    %-12s %s (已釘版，工具無 -version 跳過驗證)\n" "$bin" "$want"; ok=$((ok+1)); continue ;;
  esac
  got="$("$path" -version 2>&1 | grep -ioE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
  if [ -z "$got" ]; then
    printf "  [MISSING] %-12s 無法取得版本 (want=%s, path=%s)\n" "$bin" "$want" "$path"; missing=$((missing+1))
  elif [ "$got" = "$want" ]; then
    printf "  [ok]      %-12s %s\n" "$bin" "$got"; ok=$((ok+1))
  else
    printf "  [DRIFT]   %-12s installed=%s want=%s\n" "$bin" "$got" "$want"; drift=$((drift+1))
  fi
done < "$LOCK"

echo "  ---- ok=$ok drift=$drift missing=$missing ----"
[ "$drift" -eq 0 ] && [ "$missing" -eq 0 ]
