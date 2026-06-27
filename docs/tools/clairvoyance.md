# clairvoyance latest

> GraphQL schema recovery through field and type brute-forcing
> Source: https://github.com/nikitastupin/clairvoyance
> VPS help captured: 2026-06-27

## Install

```bash
uv tool install clairvoyance
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-u <url>` | — | target GraphQL endpoint URL |
| `-w <file>` | — | wordlist for field/type brute-forcing |
| `-o <file>` | stdout | output file (recovered schema JSON) |
| `--progress` | off | show progress bar |
| `-H <header>` | — | custom header (repeatable) |
| `--proxy <url>` | — | HTTP proxy |
| `-d <n>` | — | max depth for schema recovery |
| `--no-ssl` | off | disable SSL verification |
| `-c <n>` | — | concurrency level |

## Gotchas

1. **Installed via uv, not go** — `uv tool install clairvoyance` (follows bbflow uv-only convention)
2. **Only useful when introspection is OFF** — if introspection works, just query `__schema` directly; clairvoyance is for when it is disabled
3. **Outputs recovered schema as JSON** — pipe to GraphQL tools or save for manual analysis
4. **Wordlist quality matters** — use GraphQL-specific wordlists (field names, type names); generic wordlists waste time
5. **Slow on large schemas** — brute-forces field names one by one; use targeted wordlists and `-c` for concurrency
6. **Pair with graphw00f** — fingerprint the engine first with graphw00f, then recover schema with clairvoyance

## bbflow Usage Pattern

```bash
# Basic schema recovery
clairvoyance -u "$GRAPHQL_URL" \
  -w /usr/share/seclists/Discovery/Web-Content/graphql.txt \
  -o recovered_schema.json --progress

# With authentication
clairvoyance -u "$GRAPHQL_URL" \
  -w graphql_wordlist.txt \
  -H "Authorization: Bearer $TOKEN" \
  -o schema.json --progress

# Through proxy
clairvoyance -u "$GRAPHQL_URL" \
  -w graphql_wordlist.txt \
  --proxy http://127.0.0.1:8080 \
  -o schema.json

# Pipeline: graphw00f → clairvoyance
python3 ~/Tools/graphw00f/main.py -d -t "$GRAPHQL_URL" && \
python3 ~/Tools/graphw00f/main.py -f -t "$GRAPHQL_URL" && \
clairvoyance -u "$GRAPHQL_URL" \
  -w graphql_wordlist.txt \
  -o recovered_schema.json --progress
```
