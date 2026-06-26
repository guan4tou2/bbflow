# cdncheck

> Identify CDN / Cloud / WAF technology behind IP or domain
> Source: https://github.com/projectdiscovery/cdncheck
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
```

## Key Flags

| Flag | Note |
|------|------|
| `-i <input>` | list of ip/dns (file or inline) |
| `-cdn` | only show CDN results |
| `-cloud` | only show Cloud results |
| `-waf` | only show WAF results |
| `-resp` | **display technology name** (required for useful output) |
| `-j, -jsonl` | JSON Lines output |
| `-silent` | only results, no banner |
| `-o <file>` | write to file |
| `-r <resolvers>` | custom resolvers |
| `-e, -exclude` | exclude detected IP from output |

## Gotchas

1. **`-jsonl` not `-json`** — the flag is `-j` or `-jsonl`, there is no `-json`
2. **`-resp` is essential** — without it, output only shows IP/domain with no technology info
3. **WAF detection is limited** — only detects arvancloud, cloudflare, incapsula; use wafw00f for comprehensive WAF fingerprinting

## bbflow Usage Pattern

```bash
# Single host
echo "example.com" | cdncheck -silent -resp -jsonl

# Bulk
cdncheck -i hosts.txt -silent -resp -jsonl -o cdn_results.jsonl

# WAF only
cdncheck -i hosts.txt -waf -resp -silent
```

## JSON Output Fields

```json
{"ip":"1.2.3.4","cdn":"cloudflare","cdn_name":"Cloudflare","waf":"cloudflare","waf_name":"Cloudflare WAF"}
```
