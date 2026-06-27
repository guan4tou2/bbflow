# kiterunner (kr) v1.0.2

> API endpoint discovery using wordlists of known API routes
> Source: https://github.com/assetnote/kiterunner
> VPS help captured: 2026-06-27

## Install

```bash
# Binary release from GitHub (not `go install`)
# Download from https://github.com/assetnote/kiterunner/releases
wget https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz
tar xzf kiterunner_1.0.2_linux_amd64.tar.gz
mv kr ~/go/bin/
```

## Command Tree

```
kr
├── scan       Scan targets using .kite wordlists (route + method + parameter)
├── brute      Brute-force targets using plain text wordlists (like gobuster)
├── kb         Knowledge base management
│   ├── compile   Compile .txt routes into .kite format
│   └── replay    Replay a specific request from scan results
├── wordlist   Wordlist management
│   ├── list      List available wordlists
│   └── download  Download Assetnote .kite wordlists
└── version    Print version
```

## Key Flags (scan / brute)

| Flag | Default | Note |
|------|---------|------|
| `-w <wordlist>` | (required) | `.kite` file for `scan`, plain text for `brute` |
| `-x, --concurrency` | 100 | number of concurrent workers |
| `--delay` | 0 | delay between requests per worker (ms) |
| `--fail-status-codes` | none | status codes to ignore (e.g. `400,404,403`) |
| `-o <file>` | stdout | output file |
| `--max-redirects` | 3 | max redirects to follow |
| `--kitebuilder-full-scan` | off | test all methods+content-types per route (slow) |
| `-A, --assetnote-wordlist` | none | use built-in Assetnote wordlist by name |
| `--header` | none | custom header (repeatable: `--header "X-Key: val"`) |
| `--ignore-length` | none | ignore responses of this content-length |
| `-t, --timeout` | 15 | request timeout (seconds) |
| `--max-connection-per-host` | 3 | max connections per host |
| `--progress` | on | show progress bar |
| `-q, --quiet` | off | minimal output |

## Gotchas (bbflow-specific)

1. **Binary is `kr`, not `kiterunner`** — the installed binary name is `kr`
2. **`.kite` format required for `scan`** — `scan` uses Assetnote's `.kite` wordlists (route + method + params); plain text wordlists only work with `brute`
3. **No `go install`** — must download binary release from GitHub (Go module setup is broken for end-user install)
4. **Assetnote wordlists** — download `.kite` files from https://wordlists.assetnote.io/ or use `kr wordlist download`
5. **High default concurrency** — `-x 100` can trigger WAF; use `-x 2 --delay 500` for stealth

## bbflow Usage Pattern

```bash
# API route discovery with .kite wordlist
kr scan "$TARGET" \
  -w ~/Tools/wordlists/routes-large.kite \
  -x 10 \
  --fail-status-codes 400,404,403 \
  -o "$OUT_DIR/kr_scan.txt"

# Brute mode with plain text wordlist (like gobuster)
kr brute "$TARGET" \
  -w /path/to/wordlist.txt \
  -x 10 \
  --fail-status-codes 404 \
  -o "$OUT_DIR/kr_brute.txt"

# Stealth
kr scan "$TARGET" \
  -w routes-small.kite \
  -x 2 \
  --delay 500 \
  --fail-status-codes 400,404,403

# Full scan (all methods + content-types per route)
kr scan "$TARGET" \
  -w routes-large.kite \
  --kitebuilder-full-scan \
  -x 5
```
