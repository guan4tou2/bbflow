# katana latest

> Fast web crawler with JavaScript parsing and automatic form filling
> Source: https://github.com/projectdiscovery/katana
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-u <url>` | — | single target URL |
| `-list <file>` | — | file with list of URLs to crawl |
| `-d <n>` | 3 | maximum crawl depth |
| `-jc` | off | enable JavaScript crawling (headless) |
| `-ct <duration>` | — | max crawl duration (e.g. `5m`, `1h`) |
| `-c <n>` | 10 | number of concurrent fetchers |
| `-p <n>` | 10 | parallelism (number of URLs processed in parallel) |
| `-rl <n>` | 150 | rate limit requests/sec |
| `-rd <range>` | — | random delay between requests (e.g. `1-3` for 1-3s) |
| `-ef <exts>` | — | exclude extensions (comma-separated): `png,jpg,gif,css,woff` |
| `-f <fields>` | url | output fields: `url,path,fqdn,rdn,rurl,qurl,qpath,file,ufile,kv,dir,udir` |
| `-sf <domain>` | — | scope filter — only crawl matching domain(s) |
| `-o <file>` | stdout | output file |
| `-jsonl` | off | JSONL output |
| `-silent` | off | only show output |
| `-H <header>` | — | custom header (repeatable) |
| `-proxy <url>` | — | HTTP/SOCKS5 proxy |
| `-timeout <n>` | 15 | request timeout in seconds |
| `-retry <n>` | 1 | number of retries |
| `-aff` | off | automatic form fill during crawl |
| `-kf <type>` | — | known files to crawl: `robotstxt,sitemapxml,all` |
| `-xhr` | off | extract XHR request URL and method |

## Gotchas

1. **`-rd 1-3` adds stealth** — random 1-3 second delay between requests; essential for rate-limited targets
2. **`-jc` requires Chrome/Chromium** — JavaScript crawling launches headless browser; much slower but finds JS-rendered endpoints
3. **`-ef` is important** — without excluding static extensions, output is flooded with images/fonts/css
4. **`-ct` prevents runaway crawls** — set a time limit to avoid crawling for hours on large sites
5. **Scope leaks** — without `-sf`, katana follows links to external domains; always set scope filter

## bbflow Usage Pattern

```bash
# Standard crawl with stealth
katana -u "$TARGET" \
  -d 3 -c 5 -rl 30 -rd 1-3 \
  -ef png,jpg,gif,css,woff,woff2,svg,ico \
  -kf all -silent -o crawl_results.txt

# JavaScript-enabled crawl (slower, more thorough)
katana -u "$TARGET" \
  -d 2 -jc -c 3 -rl 20 -rd 1-3 \
  -ef png,jpg,gif,css,woff,woff2,svg,ico \
  -silent -o js_crawl.txt

# Extract endpoints with params for XSS/SQLi testing
katana -u "$TARGET" \
  -d 3 -f qurl -silent \
  -ef png,jpg,gif,css,woff,woff2,svg,ico \
  -o params_urls.txt

# Bulk crawl from list
katana -list live_hosts.txt \
  -d 2 -c 5 -p 5 -rl 50 -rd 1-3 \
  -ef png,jpg,gif,css -silent -o bulk_crawl.txt
```
