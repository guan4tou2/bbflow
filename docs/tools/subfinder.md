# subfinder v2.14.0

> Passive subdomain enumeration using multiple sources
> Source: https://github.com/projectdiscovery/subfinder
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-d <domain>` | — | target domain (repeatable for multiple) |
| `-dL <file>` | — | file with list of domains |
| `-o <file>` | stdout | output file |
| `-oJ` | off | JSON output |
| `-silent` | off | only show subdomains |
| `-all` | off | use all sources (including slow ones) |
| `-sources <list>` | — | comma-separated sources to use |
| `-exclude-sources <list>` | — | comma-separated sources to exclude |
| `-rl <n>` | — | rate limit per second |
| `-t <n>` | 10 | number of concurrent goroutines |
| `-timeout <n>` | 30 | timeout in seconds |
| `-config <file>` | `~/.config/subfinder/provider-config.yaml` | provider config file path |
| `-nW` | off | remove wildcard and dead subdomains |
| `-rL <file>` | — | custom resolver list |
| `-recursive` | off | recursive subdomain enumeration |
| `-cs` | off | display source for each subdomain |
| `-active` | off | active mode — verify subdomains via DNS |
| `-ip` | off | include resolved IPs |
| `-max-time <n>` | — | max enumeration time in minutes |
| `-v` | off | verbose output |

## Gotchas

1. **Needs API keys for full coverage** — without keys in `~/.config/subfinder/provider-config.yaml`, only free sources are used (misses 60%+ of results)
2. **`-all` is slow but thorough** — includes slower sources like Wayback, CommonCrawl; use for initial recon, skip for quick checks
3. **Provider config location** — default `~/.config/subfinder/provider-config.yaml`; VPS and local may have different keys configured
4. **Passive only** — subfinder does NOT brute-force; pair with puredns/amass for active enumeration
5. **Duplicate output** — multiple sources return the same subdomain; pipe through `sort -u` or use `-nW` to dedupe

## bbflow Usage Pattern

```bash
# Quick passive enumeration
subfinder -d "$DOMAIN" -silent -o subdomains.txt

# Thorough enumeration with all sources
subfinder -d "$DOMAIN" -all -silent -cs -o subdomains_full.txt

# Multiple domains
subfinder -dL domains.txt -all -silent -o all_subs.txt

# With source tracking (for audit trail)
subfinder -d "$DOMAIN" -all -cs -silent -o subs_with_source.txt

# Pipeline: subfinder → puredns → httpx
subfinder -d "$DOMAIN" -all -silent | \
  puredns resolve -w resolved.txt | \
  httpx -sc -title -td -silent -o live.txt
```
