# massdns latest

> High-performance DNS stub resolver for bulk lookups
> Source: https://github.com/blechschmidt/massdns
> VPS help captured: 2026-06-27

## Install

```bash
git clone https://github.com/blechschmidt/massdns.git
cd massdns && make
cp bin/massdns ~/go/bin/   # or /usr/local/bin/
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-r <file>` | — | **required** — file with DNS resolvers (one per line) |
| `-t <type>` | A | DNS record type: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `ANY` |
| `-o <format>` | — | output format: `S` (simple), `F` (full), `J` (JSON), `Snl` (simple no newline) |
| `-w <file>` | stdout | write output to file |
| `-s <n>` | 10000 | hashmap size (concurrent queries in flight) |
| `-c <n>` | — | number of concurrent sockets (default: auto) |
| `--retry <type>` | — | retry mode: `SERVFAIL`, `REFUSED`, `FORMERR` |
| `-l` | off | log to stderr |
| `--root` | off | use raw sockets (requires root) |
| `--flush` | off | flush output after each line |
| `--processes <n>` | 1 | number of parallel resolver processes |
| `--sticky` | off | use same resolver for retries |

## Output Formats

| Format | Example |
|--------|---------|
| `S` | `sub.example.com. A 1.2.3.4` |
| `Snl` | same as S but no trailing newline |
| `F` | full DNS response with headers |
| `J` | JSON output |

## Gotchas

1. **Used by puredns internally** — puredns wraps massdns; most hunters use puredns instead of massdns directly
2. **Needs good resolver list** — quality of results depends entirely on resolvers; use curated lists (e.g. `trickest/resolvers`)
3. **`-r` is required** — massdns will not run without a resolver file
4. **Extremely fast** — can do 10k+ queries/sec; may get you banned from resolvers or trigger abuse reports
5. **No wildcard filtering** — massdns does not detect DNS wildcards; puredns adds this layer
6. **Input from stdin** — domains are read from stdin: `cat domains.txt | massdns -r resolvers.txt ...`

## bbflow Usage Pattern

```bash
# Basic A record resolution
cat subdomains.txt | massdns \
  -r resolvers.txt \
  -t A -o S -w resolved.txt

# JSON output for parsing
cat subdomains.txt | massdns \
  -r resolvers.txt \
  -t A -o J -w resolved.json

# Multiple record types
cat subdomains.txt | massdns \
  -r resolvers.txt \
  -t CNAME -o S -w cname_records.txt

# Rate-controlled (reduce hashmap size)
cat subdomains.txt | massdns \
  -r resolvers.txt \
  -t A -o S -s 500 -w resolved.txt

# Typical pipeline (prefer puredns for most use cases)
# massdns is used directly only when puredns is too slow
# or you need raw DNS response data
cat subdomains.txt | massdns \
  -r resolvers.txt \
  -t A -o J -w raw_dns.json
```
