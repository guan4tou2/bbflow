# alterx v0.1.0

> Subdomain wordlist generator using patterns and permutations
> Source: https://github.com/projectdiscovery/alterx
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-l <file>` | stdin | input file with known subdomains |
| `-p <patterns>` | built-in | custom patterns (comma-separated or file) |
| `-en` | off | enrich — use all built-in patterns |
| `-o <file>` | stdout | output file |
| `-silent` | off | only show output |
| `-limit <n>` | — | max number of permutations to generate |
| `-estimate` | off | estimate output count without generating |
| `-ms <n>` | — | max subdomain label size |
| `-pp <file>` | — | payloads to use in pattern placeholders |

## Pattern Syntax

Patterns use `{{word}}`, `{{number}}`, `{{sub}}` placeholders:

| Placeholder | Meaning |
|-------------|---------|
| `{{sub}}` | existing subdomain label |
| `{{word}}` | word from wordlist/payload |
| `{{number}}` | numeric range |
| `{{suffix}}` | existing suffix |

Example patterns: `{{word}}-{{sub}}`, `{{sub}}{{number}}`, `dev-{{sub}}`

## Gotchas

1. **Generates permutations, does NOT resolve** — output is a wordlist; pipe to puredns or dnsx for resolution
2. **Can produce massive output** — use `-limit` or `-estimate` first to check size before generating
3. **`-en` enables all patterns** — greatly increases output; good for thorough recon, bad for quick checks
4. **stdin is default** — `cat known_subs.txt | alterx` works without `-l`
5. **Pair with puredns** — the standard pipeline is `alterx → puredns resolve` for discovering new subdomains

## bbflow Usage Pattern

```bash
# Generate permutations from known subdomains
cat known_subs.txt | alterx -silent -o permutations.txt

# Enriched generation (all built-in patterns)
cat known_subs.txt | alterx -en -silent -o permutations_full.txt

# Estimate before generating
cat known_subs.txt | alterx -en -estimate

# Custom patterns
cat known_subs.txt | alterx \
  -p "{{word}}-{{sub}},dev-{{sub}},staging-{{sub}},{{sub}}-api" \
  -silent -o custom_perms.txt

# Full pipeline: alterx → puredns → httpx
cat known_subs.txt | alterx -en -silent | \
  puredns resolve -w new_resolved.txt | \
  httpx -sc -title -silent -o new_live.txt

# With limit to avoid massive output
cat known_subs.txt | alterx -en -limit 100000 -silent -o perms.txt
```
