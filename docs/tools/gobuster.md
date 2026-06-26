# gobuster v3.8.2

> Directory/file/vhost/DNS/fuzz enumeration
> Source: https://github.com/OJ/gobuster
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/OJ/gobuster/v3@latest
```

## Modes

| Mode | Purpose |
|------|---------|
| `dir` | directory/file bruteforce |
| `vhost` | virtual host enumeration |
| `dns` | DNS subdomain enum |
| `fuzz` | generic fuzzing (FUZZ keyword) |
| `s3` | AWS S3 bucket enum |
| `gcs` | GCS bucket enum |
| `tftp` | TFTP enum |

## Key Flags (shared)

| Flag | Note |
|------|------|
| `-u <URL>` | target URL |
| `-w <wordlist>` | wordlist path (or `-` for stdin) |
| `-t <n>` | threads (default: 10) |
| `-d <duration>` | delay between requests per thread |
| `-o <file>` | output file |
| `-q` | quiet (no banner) |
| `-k` | skip TLS verification |
| `--proxy <url>` | HTTP/SOCKS5 proxy |
| `-a <UA>` | user-agent |
| `--random-agent` | random UA |

## vhost Mode Flags

| Flag | Note |
|------|------|
| `--append-domain` | append main domain to wordlist words |
| `--domain <domain>` | domain to append (if URL is IP) |
| `--exclude-length <ranges>` | exclude by content length |
| `--exclude-status <ranges>` | exclude by status (e.g. `200,300-400,404`) |

## Gotchas

1. **vhost mode wants IP as URL** — use IP with `--domain target.com` for accurate vhost detection
2. **`--append-domain`** — without it, wordlist entries must be FQDNs
3. **No built-in auto-calibration** — use `--exclude-length` to filter baseline response size

## bbflow Usage Pattern

```bash
# Dir enumeration
gobuster dir -u "https://target.com" -w /path/to/wordlist.txt -t 10 -q

# Vhost discovery
gobuster vhost -u "http://10.0.0.1" -w vhosts.txt --domain target.com --append-domain -t 5

# Stealth
gobuster dir -u "$URL" -w wordlist.txt -t 2 -d 1s -q
```
