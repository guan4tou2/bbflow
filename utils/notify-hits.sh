#!/usr/bin/env bash
# notify-hits.sh — pipe hunter hits to notification channels
# Usage: echo "🔴 XSS found at https://..." | ./notify-hits.sh [--tag hunter-name]
#
# Reads stdin, prepends tag, sends via notify if available.
# Falls back to stdout if notify not installed.

NOTIFY="$(command -v notify 2>/dev/null || echo '')"
TAG="${1:+[$1] }"

if [ -n "$NOTIFY" ] && [ -f "${HOME}/.config/notify/provider-config.yaml" ]; then
  while IFS= read -r line; do
    echo "${TAG}${line}"
    echo "${TAG}${line}" | "$NOTIFY" -silent 2>/dev/null || true
  done
else
  # passthrough — no notify configured
  while IFS= read -r line; do
    echo "${TAG}${line}"
  done
fi
