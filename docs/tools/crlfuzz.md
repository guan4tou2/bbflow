# crlfuzz v1.4.0

> CRLF injection scanner
> Source: https://github.com/dwisiswant0/crlfuzz
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
```

## Key Flags

| Flag | Note |
|------|------|
| `-u <URL>` | single URL |
| `-l <file>` | URLs from file |
| `-X <method>` | HTTP method (default: GET) |
| `-d <data>` | request body |
| `-H <header>` | custom header |
| `-x <proxy>` | proxy URL |
| `-c <n>` | concurrency (default: 20) |
| `-o <file>` | output file |
| `-s` | silent mode |
| `-v` | verbose |

## bbflow Usage Pattern

```bash
# Single
crlfuzz -u "https://target.com" -s

# Bulk
crlfuzz -l urls.txt -c 10 -o crlf_results.txt -s

# Stealth
crlfuzz -u "$URL" -c 2 -s
```
