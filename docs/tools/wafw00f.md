# wafw00f

> WAF detection and fingerprinting
> Source: https://github.com/EnableSecurity/wafw00f
> VPS help captured: 2026-06-27

## Install

```bash
uv tool install wafw00f
```

## Key Flags

| Flag | Note |
|------|------|
| `-a, --findall` | **test all WAFs** (don't stop at first match) |
| `-r, --noredirect` | don't follow 3xx |
| `-t <WAF>` | test for one specific WAF |
| `-o <file>` | output to csv/json/text (auto by extension) |
| `-f <format>` | force output format |
| `-i <file>` | read targets from file (csv/json/text) |
| `-l, --list` | list all detectable WAFs |
| `-p <proxy>` | HTTP/SOCKS5 proxy |
| `-T <seconds>` | request timeout |
| `-H <file>` | custom headers from text file |
| `--no-colors` | disable ANSI colors |

## Gotchas

1. **Always use `-a`** — without it, wafw00f stops at the first WAF match; many sites have multiple layers
2. **Output parsing** — output contains ANSI colors by default; strip with `sed 's/\x1b\[[0-9;]*m//g'` or use `--no-colors`
3. **"is behind" extraction** — result lines say "is behind <WAF>"; parse with `sed 's/.*is behind //'` (not `grep -P`)

## bbflow Usage Pattern

```bash
# Single target (all WAFs)
wafw00f -a "https://target.com"

# Bulk from file
wafw00f -a -i targets.txt -o waf_results.json

# List supported WAFs
wafw00f -l
```
