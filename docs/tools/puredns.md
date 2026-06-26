# puredns v2.1.1

> Subdomain bruteforce + DNS resolution with wildcard filtering
> Source: https://github.com/d3mondev/puredns
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/d3mondev/puredns/v2@latest
# Also requires massdns:
git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && cp bin/massdns ~/go/bin/
```

## Commands

| Command | Purpose |
|---------|---------|
| `resolve <file>` | resolve a list of domains |
| `bruteforce <wordlist> <domain>` | subdomain brute with wordlist |

## Key Flags (resolve)

| Flag | Note |
|------|------|
| `-r <file>` | public resolvers (default: `~/.config/puredns/resolvers.txt`) |
| `--resolvers-trusted <file>` | trusted resolvers for validation |
| `-t <n>` | threads for wildcard filtering (default: 100) |
| `-l <n>` | rate limit queries/sec (default: unlimited) |
| `--rate-limit-trusted <n>` | rate limit for trusted resolvers (default: 500) |
| `-w <file>` | write found domains to file |
| `--write-massdns <file>` | write massdns DB |
| `--write-wildcards <file>` | write wildcard roots |
| `-n <n>` | wildcard detection tests (default: 3) |
| `--skip-wildcard-filter` | skip wildcard detection |
| `--skip-validation` | skip trusted resolver validation |
| `--trusted-only` | use only trusted resolvers |

## Gotchas

1. **Requires massdns** — puredns wraps massdns; must be in PATH
2. **Resolver file required** — must have `~/.config/puredns/resolvers.txt` or specify `-r`
3. **stdin support** — `cat domains.txt | puredns resolve`

## bbflow Usage Pattern

```bash
# Resolve subdomains with wildcard filtering
puredns resolve subdomains.txt -w resolved.txt

# Bruteforce
puredns bruteforce wordlist.txt target.com -w found.txt

# Rate-limited (stealth)
puredns resolve subs.txt -l 50 -t 10 -w resolved.txt
```
