#!/usr/bin/env bash
# hunter-chains.sh — Hunter 自動串接邏輯
#
# 某些 hunter 的輸出是另一個 hunter 的最佳輸入。
# 此腳本定義串接規則，由 bbflow.sh 在 hunt 階段呼叫。
#
# 用法（bbflow.sh 內部呼叫）：
#   source configs/hunter-chains.sh
#   run_chains "$HUNT_DIR"
#
# 串接規則：
#   git-exposure 命中 → git-dumper → trufflehog-secrets
#   wayback-endpoints 產出 → url-analysis（unfurl 分析）
#   subdomain-enum 產出 → dns-deep（dnsx 深層分析）
#   tls-audit SAN 輸出 → subdomain-enum 補充
#   config-leak 命中 .env → 提取 API key → google-api-key 驗證
#   param-fuzz 產出 → dalfox-xss（已有參數的 URL）
#   param-fuzz 產出 → crlf-inject
#   oob-interact 在所有注入型 hunter 之後跑

CHAIN_LOG="${HUNT_DIR:-/tmp}/chain_log.txt"

chain_log() {
  echo "[chain $(date +%H:%M:%S)] $*" | tee -a "$CHAIN_LOG"
}

# 檢查 hunter 輸出是否有命中
has_hits() {
  local dir="$1" pattern="$2"
  find "$dir" -name "$pattern" -size +0c 2>/dev/null | head -1 | grep -q .
}

# 檢查 hunter 輸出檔是否存在且非空
has_output() {
  local file="$1"
  [ -f "$file" ] && [ -s "$file" ]
}

run_chains() {
  local HUNT_DIR="${1:-.}"
  local TOOLS_DIR
  TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

  chain_log "=== Running hunter chains ==="

  # Chain 1: git-exposure → git-dumper → trufflehog
  if has_hits "$HUNT_DIR/hunters/git-exposure" "*.txt"; then
    local git_hits
    git_hits=$(grep -rh '🔴.*\.git' "$HUNT_DIR/hunters/git-exposure/" 2>/dev/null | grep -oE 'https?://[^ ]+' | head -5)
    if [ -n "$git_hits" ]; then
      chain_log "Chain: git-exposure → git-dumper ($(echo "$git_hits" | wc -l | tr -d ' ') targets)"
      echo "$git_hits" | while read -r url; do
        local base_url="${url%%/.git*}"
        OUT_DIR="$HUNT_DIR/hunters/git-dumper" \
          "$TOOLS_DIR/hunters/hunt-git-dumper.sh" "$base_url" 2>/dev/null || true
      done
    fi
  fi

  # Chain 2: wayback/katana 產出 → url-analysis
  local all_urls=""
  for src in wayback katana gau param-fuzz; do
    local src_dir="$HUNT_DIR/hunters/$src"
    [ -d "$src_dir" ] && all_urls="$src_dir"
  done
  if [ -n "$all_urls" ]; then
    chain_log "Chain: URL collectors → url-analysis"
    OUT_DIR="$HUNT_DIR/hunters/url-analysis" \
      "$TOOLS_DIR/hunters/hunt-url-analysis.sh" "${TARGET:-unknown}" 2>/dev/null || true
  fi

  # Chain 3: param-fuzz 有參數 URL → crlf-inject
  if has_output "$HUNT_DIR/hunters/param-fuzz/param_urls.txt"; then
    local param_count
    param_count=$(wc -l < "$HUNT_DIR/hunters/param-fuzz/param_urls.txt" | tr -d ' ')
    if [ "$param_count" -gt 0 ]; then
      chain_log "Chain: param-fuzz ($param_count URLs) → crlf-inject"
      OUT_DIR="$HUNT_DIR/hunters/crlf" \
        "$TOOLS_DIR/hunters/hunt-crlf-inject.sh" "${TARGET:-unknown}" 2>/dev/null || true
    fi
  fi

  # Chain 4: config-leak 命中 → 提取敏感資訊
  if has_hits "$HUNT_DIR/hunters/config-leak" "*.txt"; then
    local env_hits
    env_hits=$(grep -rh '🔴.*\.env\|🔴.*config' "$HUNT_DIR/hunters/config-leak/" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$env_hits" -gt 0 ]; then
      chain_log "Chain: config-leak ($env_hits hits) — manual review recommended for API key extraction"
    fi
  fi

  # Chain 5: TLS SAN → 新發現的子域名補充到 subdomain 列表
  if has_output "$HUNT_DIR/hunters/tls-audit/tls_sans.txt"; then
    local san_count
    san_count=$(wc -l < "$HUNT_DIR/hunters/tls-audit/tls_sans.txt" | tr -d ' ')
    chain_log "Chain: tls-audit → $san_count SAN domains discovered (merged to subdomains)"
    if [ -f "$HUNT_DIR/bbot/subdomains.txt" ]; then
      cat "$HUNT_DIR/hunters/tls-audit/tls_sans.txt" >> "$HUNT_DIR/bbot/subdomains.txt"
      sort -u "$HUNT_DIR/bbot/subdomains.txt" -o "$HUNT_DIR/bbot/subdomains.txt"
    fi
  fi

  chain_log "=== Chains complete ==="
}
