# dalfox v2.13.0

> Parameter analysis and XSS scanner with WAF bypass
> Source: https://github.com/hahwul/dalfox
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/hahwul/dalfox/v2@latest
```

## Command Tree

```
dalfox
├── url <URL>          scan single URL with parameters
├── file <file>        scan URLs from file (bulk mode)
├── pipe               read URLs from stdin
├── sxss <URL>         stored XSS testing mode
├── server             launch REST API server
├── payload            list built-in payloads
└── version
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-b <url>` | — | blind XSS callback URL (e.g. your BXSS server) |
| `--waf-bypass` | off | enable WAF bypass payloads |
| `--delay <ms>` | 0 | delay between requests in **milliseconds** |
| `-w <n>` | 100 | number of concurrent workers |
| `-o <file>` | stdout | output file |
| `--output-format <fmt>` | plain | output format: `plain`, `json` |
| `--timeout <n>` | 10 | timeout in seconds |
| `--proxy <url>` | — | HTTP/SOCKS5 proxy |
| `--custom-payload <file>` | — | file with custom XSS payloads |
| `--custom-alert-value <str>` | — | custom alert value (e.g. `document.domain`) |
| `--custom-alert-type <type>` | — | alert type: `str`, `none` |
| `-p <param>` | all | test specific parameter only |
| `--skip-bav` | off | skip built-in BAV (basic auth verification) |
| `--skip-mining-all` | off | skip parameter mining |
| `--skip-mining-dom` | off | skip DOM-based XSS mining |
| `-H <header>` | — | custom header (repeatable) |
| `--cookie <cookie>` | — | cookie string |
| `--data <data>` | — | POST body data |
| `--method <method>` | GET | HTTP method |
| `--blind` | off | only test blind XSS vectors |
| `--follow-redirects` | off | follow redirects |
| `--no-color` | off | disable color output |
| `--silence` | off | silence mode (only show PoC) |

## Gotchas

1. **`-b` is required for blind XSS** — without `-b <callback_url>`, dalfox skips OOB XSS payloads entirely
2. **`--delay` is in milliseconds** — `--delay 1000` = 1 second; not seconds like most tools
3. **Needs parameterized URLs** — `url` mode requires URLs with query params (e.g. `https://example.com/page?q=test`); bare URLs find nothing
4. **`file` mode for bulk** — use `dalfox file urls.txt` not `cat urls.txt | dalfox url`; pipe mode is `dalfox pipe`
5. **High default workers** — `-w 100` is very aggressive; reduce to `-w 5-10` for bug bounty
6. **WAF detection** — dalfox auto-detects WAF but `--waf-bypass` must be explicitly enabled to use bypass payloads

## bbflow Usage Pattern

```bash
# Single URL scan with stealth settings
dalfox url "$TARGET_URL" \
  -b "https://your-bxss-server.com" \
  --waf-bypass --delay 500 -w 5 \
  -o xss_results.txt

# Bulk scan from katana/paramspider output
dalfox file param_urls.txt \
  -b "https://your-bxss-server.com" \
  --waf-bypass --delay 500 -w 5 \
  -o bulk_xss.txt

# Pipe mode with custom headers
cat param_urls.txt | dalfox pipe \
  -b "https://your-bxss-server.com" \
  -H "Authorization: Bearer $TOKEN" \
  --delay 1000 -w 3 \
  -o xss_auth.txt

# Targeted parameter test
dalfox url "https://target.com/search?q=test" \
  -p q --waf-bypass --delay 500 \
  --output-format json -o result.json
```
