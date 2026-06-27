# feroxbuster v2.13.1

> Fast content discovery tool written in Rust with recursive scanning
> Source: https://github.com/epi052/feroxbuster
> VPS help captured: 2026-06-27

## Install

```bash
# Download prebuilt binary (Rust — no `go install`)
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
# Or via package manager
brew install feroxbuster        # macOS
sudo apt install feroxbuster    # Debian/Ubuntu (if available)
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-u <url>` | — | target URL |
| `-w <wordlist>` | built-in | wordlist path |
| `-t <n>` | 50 | number of concurrent threads |
| `-x <exts>` | — | extensions to append (comma-separated): `php,html,js,txt` |
| `-C <codes>` | — | filter (exclude) status codes: `-C 404,403` |
| `-s <codes>` | — | match (include) only these status codes |
| `--filter-size <n>` | — | filter responses by size (repeatable) |
| `--filter-words <n>` | — | filter responses by word count |
| `--filter-lines <n>` | — | filter responses by line count |
| `--filter-regex <regex>` | — | filter responses matching regex |
| `-o <file>` | stdout | output file |
| `--json` | off | JSON output |
| `-k` | off | disable TLS certificate verification |
| `--proxy <url>` | — | proxy URL |
| `--rate-limit <n>` | 0 | max requests/sec (0 = unlimited) |
| `-d <n>` | 4 | max recursion depth |
| `--auto-tune` | off | automatically lower scan rate on errors |
| `--auto-bail` | off | stop scanning on too many errors |
| `-H <header>` | — | custom header (repeatable) |
| `-b <cookie>` | — | cookie string |
| `-a <agent>` | feroxbuster UA | custom user agent |
| `--burp` | off | shortcut for `--proxy http://127.0.0.1:8080 -k` |
| `-q` | off | quiet mode (less output) |
| `-n` | off | no recursion |
| `--time-limit <duration>` | — | max scan time: `10m`, `1h` |
| `--resume-from <file>` | — | resume scan from state file |
| `--dont-scan <regex>` | — | regex for URLs to never scan |
| `-e` | off | extract links from response bodies |

## Gotchas

1. **`--auto-tune` is great for bug bounty** — dynamically reduces request rate when target returns errors/429s; prevents IP bans
2. **Rust binary — needs download, not `go install`** — use the install script or package manager
3. **`-C` filters (excludes), `-s` matches (includes)** — easy to confuse; `-C 404` removes 404s, `-s 200,301` keeps only those
4. **Recursive by default** — feroxbuster recurses into found directories up to `-d 4`; use `-n` to disable
5. **State file for resume** — feroxbuster saves state; Ctrl+C then resume with `--resume-from`
6. **High default threads** — `-t 50` with recursion can generate massive traffic; use `--rate-limit 30 --auto-tune` for stealth

## bbflow Usage Pattern

```bash
# Standard content discovery with stealth
feroxbuster -u "$TARGET" \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,js,txt,json,xml \
  -t 10 --rate-limit 30 --auto-tune \
  -C 404 -k -o ferox_results.txt

# Quick scan with auto-bail
feroxbuster -u "$TARGET" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,html -t 10 --rate-limit 20 \
  --auto-tune --auto-bail \
  -C 404 -o quick_results.txt

# Through proxy (Burp/mitmproxy)
feroxbuster -u "$TARGET" \
  -w wordlist.txt --burp \
  -t 5 --rate-limit 10 \
  -C 404 -o proxied_results.txt

# JSON output for processing
feroxbuster -u "$TARGET" \
  -w wordlist.txt -x php,html \
  -t 10 --rate-limit 30 --auto-tune \
  -C 404 --json -o ferox.json

# Filter by response size (remove soft-404s)
feroxbuster -u "$TARGET" \
  -w wordlist.txt \
  --filter-size 1234 -C 404 \
  -t 10 --rate-limit 30 -o filtered.txt
```
