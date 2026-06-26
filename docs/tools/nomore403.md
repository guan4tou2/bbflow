# nomore403

> 403/401 bypass automation — tests multiple bypass techniques per URL
> Source: https://github.com/devploit/nomore403
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/devploit/nomore403@latest
```

## Key Flags

| Flag | Note |
|------|------|
| `-u <URL>` | target URL or file with URLs |
| `-i <IP>` | IP for X-Forwarded-For injection |
| `-k <techniques>` | specific techniques (default: all 9) |
| `-d <ms>` | delay between requests |
| `-m <n>` | max goroutines (default: 50) |
| `-t <method>` | HTTP method (default: GET) |
| `-H <header>` | custom headers (repeatable) |
| `-x <proxy>` | proxy URL |
| `--status <codes>` | filter by status codes (e.g. `200,301`) |
| `--unique` | unique output by status+length |
| `-o <file>` | save results to file |
| `--json` | JSON output |
| `-l` | stop on 429 rate limit |
| `--timeout <ms>` | timeout in ms (default: 6000) |
| `-v` | verbose |

## Default Techniques

`verbs, verbs-case, headers, endpaths, midpaths, double-encoding, unicode, http-versions, path-case`

## Gotchas

1. **Output has ANSI colors** — strip with `sed 's/\x1b\[[0-9;]*m//g'`
2. **Auto-calibrate** — nomore403 does baseline calibration to filter false positives
3. **Binary name** — installed as `nomore403` via devploit fork; older `bypass-403` (iamj0ker) may need renaming
4. **Rate limiting** — use `-d <ms>` for delay and `-m` to reduce goroutines on strict targets

## bbflow Usage Pattern

```bash
# Single URL
nomore403 -u "https://target.com/admin"

# From file
nomore403 -u urls.txt --status 200,301,302 --unique

# Stealth mode
nomore403 -u "$URL" -d 500 -m 5 --timeout 10000
```
