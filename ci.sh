#!/usr/bin/env bash
# ci.sh — 本地 CI：bash syntax + bbflow doctor + bbflow test + markdown lint
#
# 設計：
#   本 repo 無 git remote，沒有 GitHub Actions。CI 用本地 script 驅動，
#   可手動跑也可掛 pre-push hook。
#
# 用法：
#   ./tools/ci.sh                  # 全部 check
#   ./tools/ci.sh --fast           # 只跑 syntax + doctor（跳過 bbflow test 的網路呼叫）
#   ./tools/ci.sh --install-hook   # 安裝為 .git/hooks/pre-push
#
# Exit code:
#   0 = all pass
#   1 = at least one check failed
set -uo pipefail

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$TOOLS_DIR/.." && pwd)"

FAST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --fast) FAST=1; shift;;
    --install-hook)
      HOOK="$BASE_DIR/.git/hooks/pre-push"
      cat > "$HOOK" <<'EOF'
#!/usr/bin/env bash
# pre-push hook — runs bbflow local CI
exec "$(git rev-parse --show-toplevel)/tools/ci.sh" --fast
EOF
      chmod +x "$HOOK"
      echo "✓ installed pre-push hook → $HOOK"
      echo "  (runs tools/ci.sh --fast on each git push)"
      exit 0;;
    -h|--help) echo "Usage: $0 [--fast] [--install-hook]"; exit 0;;
    *) shift;;
  esac
done

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
PASS=0; FAIL=0
pass(){ echo "${G}✓${N} $*"; PASS=$((PASS+1)); }
fail(){ echo "${R}✗${N} $*"; FAIL=$((FAIL+1)); }
section(){ echo ""; echo "${C}== $* ==${N}"; }

# ── 1. Bash syntax on all hunter + bbflow + install + ci scripts ──
section "bash syntax"
for f in "$TOOLS_DIR"/bbflow.sh "$TOOLS_DIR"/install.sh "$TOOLS_DIR"/ci.sh \
         "$TOOLS_DIR"/hunters/hunt-*.sh; do
  [ ! -f "$f" ] && continue
  if bash -n "$f" 2>/dev/null; then
    pass "syntax: $(basename "$f")"
  else
    fail "syntax: $(basename "$f")"
    bash -n "$f"  # Show error
  fi
done

# ── 2. Python syntax on embedded heredocs (best-effort) ───────
section "python (embedded heredocs)"
for f in "$TOOLS_DIR"/hunters/hunt-*.sh; do
  [ ! -f "$f" ] && continue
  # Extract all PY/PYEOF heredoc bodies and check each
  awk '/<<'"'"'PY'"'"'/,/^PY$/' "$f" | sed '1d;$d' > /tmp/ci_py_$$ 2>/dev/null
  if [ -s /tmp/ci_py_$$ ]; then
    if python3 -c "$(cat /tmp/ci_py_$$)" 2>/dev/null || python3 -m py_compile /tmp/ci_py_$$ 2>/dev/null; then
      pass "python heredoc: $(basename "$f")"
    else
      # Python code inside heredoc may not be valid as standalone; check via py_compile
      python3 -m py_compile /tmp/ci_py_$$ 2>/dev/null && pass "python heredoc: $(basename "$f")" || \
        fail "python heredoc: $(basename "$f")"
    fi
  fi
  rm -f /tmp/ci_py_$$
done

# ── 3. bbflow doctor ─────────────────────────────────────────
section "bbflow doctor"
HUNTER_COUNT=$(ls "$TOOLS_DIR"/hunters/hunt-*.sh 2>/dev/null | wc -l | tr -d ' ')
if "$TOOLS_DIR/bbflow.sh" doctor 2>&1 | grep -q "✗ hunt-"; then
  fail "doctor: some hunters not executable"
else
  pass "doctor: all $HUNTER_COUNT hunters present + executable"
fi

# ── 4. bbflow test (regression null-case) ─────────────────────
if [ "$FAST" = "0" ]; then
  section "bbflow test (regression null-case)"
  TEST_OUT=$("$TOOLS_DIR/bbflow.sh" test 2>&1 | tail -3)
  if echo "$TEST_OUT" | grep -qE "all [0-9]+ null-case hunters passed"; then
    NPASS=$(echo "$TEST_OUT" | grep -oE "all [0-9]+ null-case" | grep -oE "[0-9]+")
    pass "regression test: $NPASS/$NPASS null case 0 FP"
  else
    fail "regression test: some hunter produced unexpected hits"
    echo "$TEST_OUT" | sed 's/^/    /'
  fi
else
  section "bbflow test"
  echo "   (skipped — --fast mode)"
fi

# ── 5. Hunter file permissions ────────────────────────────────
section "file permissions"
for f in "$TOOLS_DIR"/hunters/hunt-*.sh "$TOOLS_DIR"/bbflow.sh "$TOOLS_DIR"/install.sh "$TOOLS_DIR"/ci.sh; do
  [ ! -f "$f" ] && continue
  if [ -x "$f" ]; then
    pass "executable: $(basename "$f")"
  else
    fail "not executable: $(basename "$f")"
  fi
done

# ── 6. Secret scan — 阻擋真 credential / target-specific info ──
section "secret scan"
SECRET_PATTERNS=(
  'AIza[A-Za-z0-9_-]{35}'                              # Google API key
  'eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+'  # JWT
  'sk_live_[0-9a-zA-Z]{24,}'                           # Stripe secret
  'ghp_[A-Za-z0-9]{36}'                                # GitHub PAT
  'xox[baprs]-[A-Za-z0-9-]{10,}'                       # Slack
  'v1\.public\.[A-Za-z0-9_-]{40,}'                     # AWS Location
  '-----BEGIN (RSA|OPENSSH|EC|DSA|PRIVATE)'            # Private key
  '\bAKIA[0-9A-Z]{16}\b'                               # AWS access key
  'glpat-[A-Za-z0-9_-]{20}'                            # GitLab PAT
  'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'           # SendGrid
)
SCAN_FAIL=0
for PAT in "${SECRET_PATTERNS[@]}"; do
  MATCHES=$(grep -rnE "$PAT" "$TOOLS_DIR" \
    --include='*.sh' --include='*.md' --include='*.yml' --include='*.yaml' --include='*.py' 2>/dev/null | \
    grep -v 'REDACTED\|FAKE\|FakeKey\|EXAMPLE\|xxxxxx\|0000000\|TESTING\|placeholder\|CONVENTIONS.md\|ci.sh' || true)
  if [ -n "$MATCHES" ]; then
    fail "secret match: $PAT"
    echo "$MATCHES" | head -5 | sed 's/^/    /'
    SCAN_FAIL=$((SCAN_FAIL+1))
  fi
done
[ "$SCAN_FAIL" = "0" ] && pass "secret scan: no real credentials leaked"

# Target-fingerprint scan — loaded from optional .ci-fingerprints file
# (gitignored; each contributor keeps their own list of past target identifiers)
FP_FILE="$TOOLS_DIR/.ci-fingerprints"
if [ -f "$FP_FILE" ]; then
  section "target-fingerprint scan (from .ci-fingerprints)"
  FP_FAIL=0
  while IFS= read -r PAT; do
    [ -z "$PAT" ] && continue
    [[ "$PAT" == \#* ]] && continue
    MATCHES=$(grep -rnE "$PAT" "$TOOLS_DIR" \
      --include='*.sh' --include='*.md' --include='*.yml' 2>/dev/null | \
      grep -v 'CONVENTIONS.md\|ci.sh\|.ci-fingerprints' || true)
    if [ -n "$MATCHES" ]; then
      fail "target fingerprint: $PAT"
      echo "$MATCHES" | head -3 | sed 's/^/    /'
      FP_FAIL=$((FP_FAIL+1))
    fi
  done < "$FP_FILE"
  [ "$FP_FAIL" = "0" ] && pass "target-fingerprint scan: clean"
fi

# ── 7. Docs alignment: hunter count 一致性 ─────────────────────
section "docs alignment"
README_COUNT=$(grep -cE '^\| `hunt-[a-z-]+\.sh`' "$TOOLS_DIR/hunters/README.md" 2>/dev/null || echo 0)
WORKFLOW_COUNT=$(grep -cE '^\| `hunt-[a-z-]+\.sh`' "$TOOLS_DIR/WORKFLOW.md" 2>/dev/null || echo 0)
BBFLOW_REG_COUNT=$(grep -cE '^\s*run_hunter\s+\S+' "$TOOLS_DIR/bbflow.sh" 2>/dev/null || echo 0)
ACTUAL_FILES=$(ls -1 "$TOOLS_DIR/hunters"/hunt-*.sh 2>/dev/null | wc -l | tr -d ' ')

echo "   actual hunt-*.sh files: $ACTUAL_FILES"
echo "   README.md table rows:  $README_COUNT"
echo "   WORKFLOW.md table rows: $WORKFLOW_COUNT"
echo "   bbflow.sh registered:   $BBFLOW_REG_COUNT (excludes takeover special-case)"

# Allow bbflow count to be off by 2 (takeover uses inline block, gkey is standalone)
if [ "$README_COUNT" -eq "$ACTUAL_FILES" ] && [ "$WORKFLOW_COUNT" -eq "$ACTUAL_FILES" ]; then
  pass "docs aligned: README + WORKFLOW both list all $ACTUAL_FILES hunters"
else
  fail "docs mismatch: README=$README_COUNT, WORKFLOW=$WORKFLOW_COUNT, files=$ACTUAL_FILES"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "${C}== Summary ==${N}"
echo "${G}PASS: $PASS${N}   ${R}FAIL: $FAIL${N}"
[ "$FAIL" = "0" ] && exit 0 || exit 1
