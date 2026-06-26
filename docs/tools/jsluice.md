# jsluice

> Extract URLs, paths, and secrets from JavaScript files
> Source: https://github.com/BishopFox/jsluice
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
```

## Modes

| Mode | Purpose |
|------|---------|
| `urls` | extract URLs and paths |
| `secrets` | find hardcoded secrets (API keys, tokens) |
| `tree` | print syntax trees |
| `query` | run tree-sitter queries |
| `format` | beautify JS |

## Key Flags (global)

| Flag | Note |
|------|------|
| `-c <n>` | concurrency (default: 1) |
| `-C <cookies>` | cookies for HTTP fetches |
| `-H <header>` | custom headers (repeatable) |
| `-j` | read raw JS from stdin |
| `-w` | treat input as WARC file |

## URLs Mode Flags

| Flag | Note |
|------|------|
| `-I` | ignore string literals |
| `-S` | include source code context |
| `-R <url>` | resolve relative paths with this base URL |
| `-u` | unique URLs per file |

## Secrets Mode Flags

| Flag | Note |
|------|------|
| `-p <file>` | custom patterns JSON file |

## Output Format

URLs mode outputs JSON lines:
```json
{"url":"/api/v1/users","queryParams":[],"bodyParams":[],"method":"","headers":{}}
```

Secrets mode outputs JSON lines:
```json
{"kind":"AWSAccessKey","data":{"key":"AKIA...","match":"AKIA..."},"filename":"app.js","severity":"high"}
```

## Gotchas

1. **Parse URL from JSON** — use `grep -o '"url":"[^"]*"' | sed 's/"url":"//;s/"$//'` (not `grep -oP`)
2. **Expects files, not URLs** — download JS first, then pass local path: `jsluice urls app.js`
3. **stdin mode** — for piping: `curl -s URL | jsluice urls -j`

## bbflow Usage Pattern

```bash
# Extract endpoints from local JS file
jsluice urls app.js

# Extract secrets
jsluice secrets app.js

# Pipeline: download then extract
curl -sk "$JS_URL" -o /tmp/app.js && jsluice urls /tmp/app.js

# With base URL resolution
jsluice urls -R "https://target.com" app.js
```
