# graphw00f latest

> GraphQL server fingerprinting and engine detection
> Source: https://github.com/dolevf/graphw00f
> VPS: `~/Tools/graphw00f` (git clone, not pip)
> VPS help captured: 2026-06-27

## Install

```bash
# NOT a pip package — clone the repo
cd ~/Tools && git clone https://github.com/dolevf/graphw00f.git
cd ~/Tools/graphw00f && pip install -r requirements.txt
# Run as: python3 ~/Tools/graphw00f/main.py
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-t <url>` | — | target GraphQL endpoint URL |
| `-d` | off | detect mode — quick check if endpoint is GraphQL |
| `-f` | off | fingerprint mode — thorough engine identification |
| `-p <url>` | — | HTTP/SOCKS proxy |
| `-T <n>` | 10 | request timeout in seconds |
| `-H <header>` | — | custom header (repeatable): `-H "Auth: Bearer xxx"` |
| `-o <file>` | stdout | output file (CSV) |
| `-r` | off | do not follow redirects |
| `-l` | off | list all detectable engines |
| `-u <UA>` | — | custom user-agent string |
| `--version` | — | show version |

## Detected Engines

graphw00f can identify 20+ GraphQL implementations including:

- Apollo, Hasura, Graphene, Ariadne, graphql-go
- AWS AppSync, Dgraph, Directus, WPGraphQL
- graphql-php, graphql-ruby, graphql-java, Juniper
- Sangria, Strawberry, Tartiflette, and more

## Gotchas

1. **Run as `python3 ~/Tools/graphw00f/main.py`** — NOT a pip package; must reference the cloned path
2. **Needs a GraphQL endpoint URL** — provide the full path (e.g. `https://target.com/graphql`), not just the domain
3. **`-d` first, then `-f`** — detect mode confirms GraphQL exists (fast, one check); fingerprint mode identifies the engine (thorough, many probes)
4. **Some endpoints require auth** — use `-H "Authorization: Bearer $TOKEN"` for authenticated endpoints
5. **False positives on non-GraphQL** — always verify with `-d` before trusting fingerprint results

## bbflow Usage Pattern

```bash
# Quick detect if endpoint is GraphQL
python3 ~/Tools/graphw00f/main.py -d -t "$GRAPHQL_URL"

# Full fingerprint the GraphQL engine
python3 ~/Tools/graphw00f/main.py -f -t "$GRAPHQL_URL"

# With auth header
python3 ~/Tools/graphw00f/main.py \
  -f -t "$GRAPHQL_URL" \
  -H "Authorization: Bearer $TOKEN"

# Through proxy
python3 ~/Tools/graphw00f/main.py \
  -f -t "$GRAPHQL_URL" \
  -p http://127.0.0.1:8080

# Output to CSV
python3 ~/Tools/graphw00f/main.py \
  -f -t "$GRAPHQL_URL" -o results.csv

# Pipeline: detect → fingerprint → introspect with clairvoyance
python3 ~/Tools/graphw00f/main.py -d -t "$GRAPHQL_URL" && \
python3 ~/Tools/graphw00f/main.py -f -t "$GRAPHQL_URL"
```
