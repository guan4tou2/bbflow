#!/bin/bash
# bbflow-vps.sh — unified recon wrapper for Oracle Cloud Bug Bounty VPS
# Version: 1.1 (2026-04-22)
# Usage: bbflow.sh <subcommand> <target> [options]

set -uo pipefail

OUT="${HOME}/workspaces-osmedeus"
mkdir -p "$OUT"

sub="${1:-help}"
TARGET="${2:-}"

banner() { echo "[$(date -u +%FT%TZ)] $*"; }

need_target() {
  [ -z "$TARGET" ] && { echo "Usage: $0 $sub <target>"; exit 1; }
}

case "$sub" in

  help|--help|-h|"")
    cat << 'EOF'
bbflow-vps.sh — Unified Bug Bounty Recon CLI

USAGE
  bbflow.sh <command> <target> [options]

RECON WORKFLOWS (uses Osmedeus under the hood)
  lite <domain>        Quick subdomain + probe + fingerprint (~2 min)
  standard <domain>    bbflow-safe flow: 7 modules incl. archive + screenshots,
                       NO nuclei, NO content fuzz, NO DNS brute (~20 min)
  vulnscan <domain>    Osmedeus domain-standard (includes nuclei — requires
                       H1USER env or BB_ALLOW_NUCLEI=1 confirmation; ~60 min)
  extensive <domain>   Exhaustive incl. DNS bruteforce (~60 min)
  single <url>         Single URL analysis flow

SPECIALIZED SUB-TOOLS
  takeover <domain>    subjack + nuclei takeover templates on subs from lite run
  s3 <bucket>          s3scanner on explicit bucket
  crawl <url>          hakrawler + gau + waybackurls piped through uro
  params <url>         x8 hidden param fuzzer (Rust)
  xss <url>            dalfox XSS scan
  jaeles <url>         jaeles signature-based scan
  cmdinject <url>      commix command injection
  waf <url>            gotestwaf WAF bypass evaluation
  nuclei <url|file>    nuclei templates (add headers via -H inside)
  secrets <target>     trufflehog scan — URL (git repo) / path / github org/name
  dork <domain>        pagodo passive Google dork (DORKS_FILE env var override)
  goofuzz <domain>     GooFuzz Google-CSE dork (GOOFUZZ_WL / GOOFUZZ_KEY env)
  reconftw <domain>    Big all-in-one orchestrator (reconftw -r, ~hours)

UTILITY
  status <domain>      Summarise artefacts in workspace
  pull <domain>        Tar-gz the workspace to stdout (for local rsync/scp)
  clean <domain>       Remove workspace (destructive)
  tools                List all installed tools + PATH locations
  health               osmedeus health check

ENV VARS
  H1USER               HackerOne username (used as X-Bug-Bounty header when set)
EOF
    ;;

  lite)
    need_target
    banner "osmedeus domain-lite on $TARGET"
    exec osmedeus run -f domain-lite -t "$TARGET" --timeout 30m
    ;;

  standard)
    need_target
    banner "osmedeus bbflow-safe on $TARGET (passive + archive + screenshots, NO nuclei/content fuzz)"
    exec osmedeus run -f bbflow-safe -t "$TARGET" --timeout 2h
    ;;

  vulnscan)
    need_target
    banner "osmedeus domain-standard on $TARGET (includes nuclei — ensure program allows it)"
    if [ -z "${H1USER:-}" ] && [ -z "${BB_ALLOW_NUCLEI:-}" ]; then
      echo "  ⚠️  H1USER or BB_ALLOW_NUCLEI env not set — nuclei will send without X-Bug-Bounty header"
      echo "  Abort with Ctrl-C or set H1USER=..."; sleep 5
    fi
    exec osmedeus run -f domain-standard -t "$TARGET" --timeout 2h
    ;;

  extensive)
    need_target
    banner "osmedeus domain-extensive on $TARGET (includes DNS brute)"
    exec osmedeus run -f domain-extensive -t "$TARGET" --timeout 3h
    ;;

  single)
    need_target
    banner "osmedeus url flow on $TARGET"
    exec osmedeus run -f url -t "$TARGET" --timeout 1h
    ;;

  takeover)
    need_target
    mkdir -p "$OUT/$TARGET/takeover"
    if [ -f "$TARGET" ]; then
      subs="$TARGET"
    else
      subs="$OUT/$TARGET/subdomain/subdomain-$TARGET.txt"
    fi
    if [ ! -f "$subs" ]; then
      echo "No subs file at $subs — run 'bbflow.sh lite $TARGET' first or pass a .txt file as target"
      exit 1
    fi
    banner "subjack on $(wc -l < "$subs") subdomains"
    subjack -w "$subs" -t 100 -timeout 10 -ssl -v -o "$OUT/$TARGET/takeover/subjack.txt" || true
    banner "nuclei takeover templates"
    nuclei -l "$subs" -t ~/nuclei-templates/http/takeovers/ \
      ${H1USER:+-H "X-Bug-Bounty: HackerOne-$H1USER"} \
      -silent -o "$OUT/$TARGET/takeover/nuclei.txt" || true
    echo ""
    echo "=== Results ==="
    wc -l "$OUT/$TARGET/takeover/"*.txt 2>/dev/null
    ;;

  s3)
    need_target
    exec s3scanner -bucket "$TARGET"
    ;;

  crawl)
    need_target
    tmp=$(mktemp)
    banner "hakrawler + gau + waybackurls → uro dedupe"
    (echo "$TARGET" | hakrawler -d 3 -subs -u 2>/dev/null; \
     echo "$TARGET" | sed 's|https\?://||' | gau --threads 5 2>/dev/null) | sort -u > "$tmp"
    echo "raw: $(wc -l < "$tmp")"
    cat "$tmp" | uro > "${tmp}.clean"
    echo "clean: $(wc -l < "${tmp}.clean")"
    echo ""
    echo "=== First 40 ==="
    head -40 "${tmp}.clean"
    echo ""
    echo "(full list saved to $tmp.clean)"
    ;;

  params)
    need_target
    banner "x8 hidden param scan"
    wl="$HOME/bbtools/top25-parameter/Top-25-XSS-parameters.txt"
    [ ! -f "$wl" ] && wl="/dev/null"
    x8 -u "$TARGET" -W "$wl" -X GET ${H1USER:+--custom-headers "X-Bug-Bounty: HackerOne-$H1USER"}
    ;;

  xss)
    need_target
    exec dalfox url "$TARGET" --skip-bav --no-color \
      ${H1USER:+-H "X-Bug-Bounty: HackerOne-$H1USER"}
    ;;

  jaeles)
    need_target
    exec jaeles scan -c 50 -s 'common' -u "$TARGET" \
      ${H1USER:+-H "X-Bug-Bounty: HackerOne-$H1USER"}
    ;;

  cmdinject)
    need_target
    exec commix -u "$TARGET" --batch \
      ${H1USER:+--headers="X-Bug-Bounty: HackerOne-$H1USER"}
    ;;

  waf)
    need_target
    exec gotestwaf --url "$TARGET" --verbose
    ;;

  secrets)
    # trufflehog — scan git repo / URL / filesystem for leaked secrets
    need_target
    if echo "$TARGET" | grep -qE '^https?://'; then
      exec trufflehog git "$TARGET"
    elif [ -d "$TARGET" ]; then
      exec trufflehog filesystem "$TARGET"
    else
      # Assume github repo org/name
      exec trufflehog github --repo "https://github.com/$TARGET"
    fi
    ;;

  dork)
    # pagodo — passive Google dork against a domain
    need_target
    mkdir -p "$OUT/$TARGET/dork"
    cd ~/bbtools/pagodo
    dorks="${DORKS_FILE:-$HOME/bbtools/pagodo/dorks/default.dorks}"
    [ ! -f "$dorks" ] && dorks="$HOME/bbtools/google-dork-wordlists/1-million-dorks.txt"
    [ ! -f "$dorks" ] && { echo "No dorks file; pass DORKS_FILE=... env var"; exit 1; }
    exec pagodo -g "$dorks" -d "$TARGET" -s "$OUT/$TARGET/dork/urls.txt" -o "$OUT/$TARGET/dork/results.json"
    ;;

  goofuzz)
    # GooFuzz — Google-dork based pathfinding (needs Google CSE key file: -k)
    need_target
    wl="${GOOFUZZ_WL:-$HOME/bbtools/google-dork-wordlists/cctv.txt}"
    keyfile="${GOOFUZZ_KEY:-}"
    args="-t $TARGET -w $wl"
    [ -n "$keyfile" ] && args="$args -k $keyfile"
    [ -n "${GOOFUZZ_EXT:-}" ] && args="$args -e $GOOFUZZ_EXT"
    exec goofuzz $args
    ;;

  reconftw)
    # reconftw — big all-in-one recon orchestrator
    need_target
    [ ! -f ~/bbtools/reconftw/reconftw.sh ] && { echo "reconftw not installed at ~/bbtools/reconftw"; exit 1; }
    cd ~/bbtools/reconftw
    exec bash reconftw.sh -d "$TARGET" -r
    ;;

  nuclei)
    need_target
    if [ -f "$TARGET" ]; then flag="-l"; else flag="-u"; fi
    exec nuclei $flag "$TARGET" -silent \
      ${H1USER:+-H "X-Bug-Bounty: HackerOne-$H1USER"}
    ;;

  status)
    need_target
    d="$OUT/$TARGET"
    [ ! -d "$d" ] && { echo "No workspace for $TARGET"; exit 1; }
    echo "=== $TARGET ==="
    count() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
    echo "Subs:        $(count "$d/subdomain/subdomain-$TARGET.txt")"
    echo "Live HTTP:   $(count "$d/probing/http-$TARGET.txt")"
    echo "Interesting: $(count "$d/fingerprint/http-interesting-$TARGET.txt")"
    echo "Archive:     $(count "$d/archive/archive-urls-$TARGET.txt")"
    echo "Screenshots: $(ls "$d/screenshots/$TARGET-screenshots/" 2>/dev/null | wc -l | tr -d ' ')"
    echo "Vulns:       $(count "$d/vulnscan/nuclei-jsonl-$TARGET.txt")"
    echo "Takeover:    $(count "$d/takeover/subjack.txt")"
    echo ""
    echo "Folders: $(find "$d" -maxdepth 1 -type d | wc -l | tr -d ' ')"
    ;;

  pull)
    need_target
    tar czf - -C "$OUT" "$TARGET" 2>/dev/null
    ;;

  clean)
    need_target
    rm -rf "$OUT/$TARGET"
    echo "Cleaned $TARGET"
    ;;

  tools)
    echo "=== bbflow-vps tool inventory ==="
    all=(osmedeus dalfox hakrawler jaeles s3scanner subjack x8 paramspider uro commix gotestwaf trufflehog goofuzz pagodo nuclei subfinder httpx dnsx katana ffuf amass findomain puredns shuffledns naabu tlsx urlfinder kingfisher metabigor)
    for t in "${all[@]}"; do
      p=$(command -v "$t" 2>/dev/null || true)
      if [ -n "$p" ]; then printf "  \u2713 %-15s %s\n" "$t" "$p"; else printf "  \u2717 %-15s MISSING\n" "$t"; fi
    done
    echo ""
    echo "=== Reference repos (non-PATH) ==="
    for r in commix reconftw wstg WebHackersWeapons can-i-take-over-xyz ezXSS top25-parameter ParamSpider GooFuzz pagodo GDorks google-dork-wordlists; do
      if [ -d "$HOME/bbtools/$r" ]; then printf "  \u2713 %-25s ~/bbtools/%s\n" "$r" "$r"; else printf "  \u2717 %-25s MISSING\n" "$r"; fi
    done
    ;;

  health)
    exec osmedeus health
    ;;

  *)
    echo "Unknown subcommand: $sub"
    "$0" help
    exit 1
    ;;

esac
