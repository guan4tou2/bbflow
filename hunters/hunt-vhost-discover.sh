#!/usr/bin/env bash
# hunt-vhost-discover.sh — Virtual host discovery via gobuster + curl fuzzing
#
# Usage:
#   OUT_DIR=/path BBFLOW_PROFILE=safe hunt-vhost-discover.sh <url-or-domain>
#
# Output:
#   🔴 Confirmed vhost — different status AND content-length from baseline
#   🟡 Possible vhost  — size difference only

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "usage: $0 <url-or-domain>"
  echo "  env: OUT_DIR, BBFLOW_PROFILE={safe|deep|stealth}"
  exit 1
fi

OUT_DIR="${OUT_DIR:-/tmp/bb-vhost-$$}"
mkdir -p "$OUT_DIR"

# ── strip scheme, extract domain ──────────────────────────────────────────────
DOMAIN="${TARGET#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"
DOMAIN="${DOMAIN%%:*}"   # strip port

# ── resolve IP ───────────────────────────────────────────────────────────────
echo "[*] Resolving $DOMAIN ..."
TARGET_IP=""
if command -v dig &>/dev/null; then
  TARGET_IP=$(dig +short A "$DOMAIN" | grep -Eo '^[0-9.]+$' | head -1)
fi
if [ -z "$TARGET_IP" ] && command -v host &>/dev/null; then
  TARGET_IP=$(host "$DOMAIN" 2>/dev/null | awk '/has address/{print $4; exit}')
fi
if [ -z "$TARGET_IP" ]; then
  echo "[!] Could not resolve $DOMAIN — using domain directly"
  TARGET_IP="$DOMAIN"
fi
echo "[*] IP: $TARGET_IP"

# ── profile-aware thread counts ───────────────────────────────────────────────
case "${BBFLOW_PROFILE:-safe}" in
  deep)    THREADS=20; DELAY=0 ;;
  stealth) THREADS=2;  DELAY=1 ;;
  *)       THREADS=8;  DELAY=0 ;;
esac

# ── auto-calibrate baseline ───────────────────────────────────────────────────
RAND_HOST="$(LC_ALL=C tr -dc 'a-z' </dev/urandom 2>/dev/null | head -c12 || echo 'randombaseline123').${DOMAIN}"
echo "[*] Calibrating baseline with Host: $RAND_HOST ..."
BASELINE_OUT=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code} %{size_download}" \
  -H "Host: $RAND_HOST" "http://$TARGET_IP" 2>/dev/null || echo "000 0")
BASELINE_STATUS=$(awk '{print $1}' <<<"$BASELINE_OUT")
BASELINE_SIZE=$(awk '{print $2}' <<<"$BASELINE_OUT")
echo "[*] Baseline → status=$BASELINE_STATUS size=$BASELINE_SIZE"

# ── wordlist selection ─────────────────────────────────────────────────────────
SECLISTS_VHOST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
ALT_PATHS=(
  "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
  "$HOME/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
  "/usr/local/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
)
WORDLIST=""
[ -f "$SECLISTS_VHOST" ] && WORDLIST="$SECLISTS_VHOST"
if [ -z "$WORDLIST" ]; then
  for p in "${ALT_PATHS[@]}"; do
    [ -f "$p" ] && WORDLIST="$p" && break
  done
fi

RESULTS="$OUT_DIR/vhost-results.txt"
> "$RESULTS"

# ── curl-based fuzzing helper ─────────────────────────────────────────────────
fuzz_host() {
  local vhost="$1"
  local out
  out=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code} %{size_download}" \
    -H "Host: $vhost" "http://$TARGET_IP" 2>/dev/null || echo "000 0")
  local status size
  status=$(awk '{print $1}' <<<"$out")
  size=$(awk '{print $2}' <<<"$out")

  local size_diff=$(( size - BASELINE_SIZE ))
  size_diff=${size_diff#-}   # abs value (bash 3 compatible)

  local status_diff=0
  [ "$status" != "$BASELINE_STATUS" ] && status_diff=1

  if [ "$status_diff" -eq 1 ] && [ "$size_diff" -gt 50 ]; then
    echo "🔴 $vhost  [status=$status size=$size]" | tee -a "$RESULTS"
  elif [ "$size_diff" -gt 200 ]; then
    echo "🟡 $vhost  [status=$status size=$size (baseline=$BASELINE_SIZE)]" | tee -a "$RESULTS"
  fi

  [ "${DELAY:-0}" -gt 0 ] && sleep "$DELAY"
}

# ── Step 1: manual top-pattern fuzzing ───────────────────────────────────────
TOP_PATTERNS=(admin api dev staging test internal beta portal dashboard mail vpn git ci cd deploy)
echo ""
echo "[*] Fuzzing top patterns against $TARGET_IP (Host: <pattern>.$DOMAIN) ..."
for p in "${TOP_PATTERNS[@]}"; do
  fuzz_host "${p}.${DOMAIN}"
done

# ── Step 2: gobuster vhost or curl-only wordlist ──────────────────────────────
GOBUSTER="$(command -v gobuster 2>/dev/null || echo '')"
echo ""
if [ -n "$GOBUSTER" ] && [ -n "$WORDLIST" ]; then
  echo "[*] Running gobuster vhost (threads=$THREADS wordlist=$WORDLIST) ..."
  GOBUSTER_OUT="$OUT_DIR/gobuster-vhost.txt"
  "$GOBUSTER" vhost \
    -u "http://$TARGET_IP" \
    --domain "$DOMAIN" \
    -w "$WORDLIST" \
    -t "$THREADS" \
    --no-error \
    --append-domain \
    -o "$GOBUSTER_OUT" 2>/dev/null || true

  # parse gobuster hits and re-classify with our size diff logic
  if [ -f "$GOBUSTER_OUT" ]; then
    while IFS= read -r line; do
      vhost=$(awk '{print $2}' <<<"$line" | tr -d '()')
      [ -z "$vhost" ] && continue
      fuzz_host "$vhost"
    done < <(grep -i "Found:" "$GOBUSTER_OUT" 2>/dev/null || true)
  fi
elif [ -n "$WORDLIST" ]; then
  echo "[*] gobuster not found — curl-only wordlist fuzzing (threads=$THREADS) ..."
  # parallel curl using background jobs
  ACTIVE=0
  while IFS= read -r word; do
    [ -z "$word" ] && continue
    fuzz_host "${word}.${DOMAIN}" &
    ACTIVE=$(( ACTIVE + 1 ))
    if [ "$ACTIVE" -ge "$THREADS" ]; then
      wait
      ACTIVE=0
    fi
  done < "$WORDLIST"
  wait
else
  echo "[!] No wordlist found (SecLists not installed) — top-pattern only scan done above."
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
TOTAL=$(wc -l < "$RESULTS" 2>/dev/null || echo 0)
TOTAL=$(echo "$TOTAL" | tr -d ' ')
if [ "$TOTAL" -gt 0 ]; then
  echo "[+] $TOTAL potential vhost(s) found → $RESULTS"
  cat "$RESULTS"
else
  echo "[~] No vhosts detected (all responses match baseline)"
fi
