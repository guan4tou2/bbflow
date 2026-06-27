# xnLinkFinder latest

> Link and parameter extractor from URLs, files, and web archives
> Source: https://github.com/xnl-h4ck3r/xnLinkFinder
> VPS help captured: 2026-06-27

## Install

```bash
uv tool install xnLinkFinder
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-i <input>` | — | input URL, file, or directory |
| `-sf <domain>` | — | **scope filter** — only output links matching this domain |
| `-o <file>` | stdout | output file for links |
| `-op <file>` | — | output file for parameters |
| `-oo <file>` | — | output file for origin URLs (where links were found) |
| `-sp <codes>` | — | filter by status code (e.g. `200,301`) |
| `-spo` | off | filter status codes for origin URLs only |
| `-silent` | off | suppress banner and info messages |
| `-d <n>` | — | depth of crawl |
| `-H <header>` | — | custom header (repeatable) |
| `-c <cookie>` | — | cookie string |
| `-p <proxy>` | — | HTTP proxy |
| `-t <n>` | — | number of threads |
| `-timeout <n>` | — | request timeout in seconds |
| `-insecure` | off | skip TLS verification |
| `-s429` | off | stop on 429 (rate limited) |
| `-replay-proxy <url>` | — | send found URLs through replay proxy |
| `-ascii-only` | off | only output ASCII characters |
| `-origin` | off | prefix each link with its origin URL |
| `-v` | off | verbose output |

## Input Types

| Input | Example |
|-------|---------|
| URL | `-i https://target.com` |
| File with URLs | `-i urls.txt` |
| Directory | `-i ./responses/` (reads HTML/JS files) |
| Wayback URLs | `-i waybackurls_output.txt` |
| Burp XML | `-i burp_export.xml` |
| ZAP JSON | `-i zap_export.json` |

## Gotchas

1. **MUST use `-sf domain.com`** — without scope filter, output includes links to every external domain referenced in the page (CDNs, analytics, etc.); results are unusable for targeted recon
2. **`-op` for parameters** — parameters are output separately with `-op`; don't rely on `-o` alone for param discovery
3. **Works on local files** — can extract links from downloaded HTML/JS files in a directory, not just live URLs
4. **Wayback integration** — feed waybackurls output directly as input for historical link discovery
5. **Complements jsluice** — xnLinkFinder crawls pages + JS; jsluice does deeper JS-only extraction
6. **Installed via uv** — follows bbflow uv-only convention

## bbflow Usage Pattern

```bash
# Extract links and params from single URL
xnLinkFinder -i "$TARGET" \
  -sf "$DOMAIN" \
  -o links.txt -op params.txt -silent

# Bulk extraction from URL list
xnLinkFinder -i live_hosts.txt \
  -sf "$DOMAIN" \
  -o all_links.txt -op all_params.txt -silent

# From downloaded JS/HTML files
xnLinkFinder -i ./js_files/ \
  -sf "$DOMAIN" \
  -o js_links.txt -op js_params.txt -silent

# With origin tracking
xnLinkFinder -i "$TARGET" \
  -sf "$DOMAIN" \
  -o links.txt -op params.txt \
  -oo origins.txt -origin -silent

# Filtered by status code
xnLinkFinder -i "$TARGET" \
  -sf "$DOMAIN" \
  -sp 200 -spo \
  -o links.txt -op params.txt -silent

# Through proxy for inspection
xnLinkFinder -i "$TARGET" \
  -sf "$DOMAIN" \
  -p http://127.0.0.1:8080 \
  -o links.txt -op params.txt -silent

# Pipeline: katana → xnLinkFinder for deep param extraction
katana -u "$TARGET" -d 3 -silent -o crawl.txt && \
xnLinkFinder -i crawl.txt \
  -sf "$DOMAIN" \
  -o deep_links.txt -op deep_params.txt -silent
```
