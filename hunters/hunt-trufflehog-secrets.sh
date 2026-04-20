#!/usr/bin/env bash
# hunt-trufflehog-secrets.sh — 深度 git secret 掃描 via trufflehog
#
# 用途：對已 dump 的 .git repo（git-dumper 產出）做 trufflehog 掃描
# 比 hunt-git-exposure.sh 的 grep 更深：
#   - 掃所有 commit history（含已刪除的 secrets）
#   - 100+ 種 detector（AWS/GCP/GitHub/Stripe/SendGrid/etc.）
#   - 只報驗證成功的（--only-verified）
#
# Usage: OUT_DIR=/path hunt-trufflehog-secrets.sh <url>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-trufflehog-$$}"
mkdir -p "$OUT_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_DIR="$(cd "$TOOLS_DIR/.." && pwd)"

TFH="$(command -v trufflehog 2>/dev/null || echo '')"
[ -z "$TFH" ] && { echo "✗ trufflehog not found (brew install trufflehog)"; exit 0; }

DOMAIN=$(echo "$TARGET" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)
TARGET_SLUG=$(echo "$DOMAIN" | tr '.' '_')

TFH_OUT="$OUT_DIR/trufflehog_results.json"
> "$TFH_OUT"

# ── Method 1: scan dumped .git dir if it exists ───────────
DUMPED_GIT_DIRS=(
  "$BASE_DIR/GitHack/$DOMAIN"
  "$BASE_DIR/git-dumper/$DOMAIN"
  "$BASE_DIR/gittools_dump/$DOMAIN"
  "$BASE_DIR/research/$DOMAIN/git-dump"
)
for GITDIR in "${DUMPED_GIT_DIRS[@]}"; do
  [ -d "$GITDIR/.git" ] || [ -f "$GITDIR/.git/config" ] || continue
  echo "→ scanning local git: $GITDIR" >&2
  "$TFH" git \
    --json \
    --no-update \
    --only-verified \
    "file://$GITDIR" 2>/dev/null >> "$TFH_OUT" || true
done

# ── Method 2: scan live git remote URL ───────────────────
# Try to detect if target has .git exposed and extract remote URL
GIT_CONFIG_URL=$(curl -sf "$TARGET/.git/config" 2>/dev/null | grep -oE 'https?://[^ ]+' | head -1)
if [ -n "$GIT_CONFIG_URL" ]; then
  echo "→ scanning remote git: $GIT_CONFIG_URL" >&2
  "$TFH" git \
    --json \
    --no-update \
    --only-verified \
    "$GIT_CONFIG_URL" 2>/dev/null >> "$TFH_OUT" || true
fi

# ── Method 3: scan GitHub org/repo if detected ────────────
# 從 git config 提取 GitHub remote（常見於 .git 洩漏）
GITHUB_REMOTE=$(curl -sf "$TARGET/.git/config" 2>/dev/null \
  | grep -oE 'github\.com[:/][^[:space:]]+\.git' | head -1 \
  | sed 's|github\.com[:/]|https://github.com/|' | sed 's|\.git$||')
if [ -n "$GITHUB_REMOTE" ]; then
  echo "→ scanning GitHub repo: $GITHUB_REMOTE" >&2
  "$TFH" github \
    --json \
    --no-update \
    --only-verified \
    --repo "$GITHUB_REMOTE" 2>/dev/null >> "$TFH_OUT" || true
fi

# ── Parse and output hits ─────────────────────────────────
if [ -s "$TFH_OUT" ]; then
  python3 -c "
import json, sys

with open('$TFH_OUT') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            hit = json.loads(line)
            det_name = hit.get('DetectorName', hit.get('detector_name', 'unknown'))
            verified = hit.get('Verified', hit.get('verified', False))
            raw = hit.get('Raw', hit.get('raw', ''))[:60]
            source = hit.get('SourceMetadata', {})
            loc = str(source)[:80] if source else ''
            v_tag = '[VERIFIED]' if verified else '[unverified]'
            print(f'🔴 TRUFFLEHOG {v_tag} {det_name}: {raw}... {loc}')
        except json.JSONDecodeError:
            pass
" 2>/dev/null || true
fi
