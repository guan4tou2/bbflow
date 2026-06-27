# httpx latest

> Fast HTTP probing and technology detection
> Source: https://github.com/projectdiscovery/httpx
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-l <file>` | stdin | input file with hosts/URLs |
| `-u <url>` | — | single target URL |
| `-sc` | off | display status code |
| `-title` | off | display page title |
| `-td` | off | technology detection (Wappalyzer) |
| `-ip` | off | display resolved IP |
| `-cdn` | off | display CDN/WAF in use |
| `-cl` | off | display content length |
| `-ct` | off | display content type |
| `-location` | off | display redirect location |
| `-web-server` | off | display web server header |
| `-o <file>` | stdout | output file |
| `-json` | off | JSON output |
| `-threads <n>` | 50 | number of concurrent threads |
| `-rl <n>` | 150 | rate limit requests/sec |
| `-timeout <n>` | 15 | timeout in seconds |
| `-silent` | off | only show output (no banner/stats) |
| `-follow-redirects` | off | follow HTTP redirects |
| `-fr` | off | alias for `-follow-redirects` |
| `-match-code <codes>` | — | match specific status codes (comma-separated) |
| `-filter-code <codes>` | — | filter out status codes |
| `-match-length <n>` | — | match specific content length |
| `-filter-length <n>` | — | filter by content length |
| `-match-string <str>` | — | match response containing string |
| `-filter-string <str>` | — | filter response containing string |
| `-probe` | off | display probe status (SUCCESS/FAILED) |
| `-favicon` | off | display favicon hash |
| `-hash <algo>` | — | display body hash (md5/sha256) |
| `-irh` | off | include response headers in output |
| `-irr` | off | include response body in JSON output |

## Gotchas

1. **Default 50 threads can be aggressive** — lower to `-threads 10 -rl 30` for bug bounty targets to avoid triggering WAF/rate limits
2. **stdin is default input** — `cat hosts.txt | httpx` works; no `-l` needed with pipes
3. **`-json` not `-jsonl`** — httpx uses `-json` (outputs one JSON per line despite the flag name)
4. **`-td` requires network** — technology detection fingerprints pull from embedded DB, but initial load can be slow
5. **Probe both HTTP and HTTPS** — httpx auto-probes both `http://` and `https://` when given bare hostnames

## bbflow Usage Pattern

```bash
# Probe live hosts from subdomain list
cat subdomains.txt | httpx -sc -title -td -ip -cdn \
  -threads 10 -rl 30 -silent -o live_hosts.txt

# JSON output for downstream processing
cat subdomains.txt | httpx -sc -title -td -ip -cdn \
  -json -silent -threads 10 -o probe_results.json

# Filter for interesting status codes
cat subdomains.txt | httpx -sc -silent \
  -match-code 200,301,302,403 \
  -threads 10 -o filtered.txt

# Follow redirects and capture final destination
cat subdomains.txt | httpx -sc -title -location \
  -follow-redirects -silent -o redirects.txt
```
