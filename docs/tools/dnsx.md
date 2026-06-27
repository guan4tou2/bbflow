# dnsx latest

> Fast multi-purpose DNS toolkit with retries and multiple record types
> Source: https://github.com/projectdiscovery/dnsx
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-l <file>` | stdin | input file with domains/subdomains |
| `-a` | off | query A records |
| `-aaaa` | off | query AAAA records |
| `-cname` | off | query CNAME records |
| `-mx` | off | query MX records |
| `-ns` | off | query NS records |
| `-txt` | off | query TXT records |
| `-ptr` | off | query PTR records |
| `-soa` | off | query SOA records |
| `-any` | off | query ANY records |
| `-axfr` | off | attempt zone transfer |
| `-resp` | off | display DNS response |
| `-resp-only` | off | display only response (no query) |
| `-json` | off | JSON output |
| `-o <file>` | stdout | output file |
| `-silent` | off | only show output |
| `-rl <n>` | — | rate limit queries/sec |
| `-t <n>` | 100 | number of concurrent threads |
| `-retry <n>` | 2 | number of retries |
| `-r <file>` | system | custom resolver file |
| `-rc <code>` | — | filter by response code (e.g. `NOERROR`, `NXDOMAIN`) |
| `-re <str>` | — | regex to match response |
| `-cdn` | off | display CDN name |
| `-asn` | off | display ASN info |
| `-wc` | off | display wildcard status |

## Gotchas

1. **Great for filtering resolved vs unresolved** — pipe subdomains through dnsx to strip dead hosts before probing
2. **No record type = just resolution check** — without `-a`/`-cname`/etc., dnsx only checks if the domain resolves
3. **stdin is default** — `cat subs.txt | dnsx` works without `-l`
4. **`-resp` vs `-resp-only`** — `-resp` shows `domain [response]`; `-resp-only` shows just the response value
5. **High default threads** — `-t 100` is fast but may overwhelm resolvers; use `-t 20 -rl 50` for stealth

## bbflow Usage Pattern

```bash
# Filter resolved subdomains
cat subdomains.txt | dnsx -silent -o resolved.txt

# Get A records with responses
cat subdomains.txt | dnsx -a -resp -silent -o a_records.txt

# Get CNAME records (subdomain takeover candidates)
cat subdomains.txt | dnsx -cname -resp -silent -o cname_records.txt

# Full record enumeration
cat subdomains.txt | dnsx \
  -a -aaaa -cname -mx -ns -txt \
  -resp -json -silent -o full_dns.json

# Rate-limited scan
cat subdomains.txt | dnsx -a -resp -silent \
  -t 20 -rl 50 -retry 3 -o resolved.txt

# Check for zone transfer
echo "$DOMAIN" | dnsx -axfr -resp -silent
```
