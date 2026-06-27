# amass v5.1.1

> Attack surface mapping and subdomain enumeration
> Source: https://github.com/owasp-amass/amass
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/owasp-amass/amass/v4/...@latest
```

## Command Tree (v5)

```
amass
├── enum             enumerate subdomains
│   ├── -d <domain>  target domain
│   ├── -passive     passive-only mode
│   └── -active      include active techniques
├── intel            discover root domains via ASN/CIDR/org
├── db               interact with the graph database
│   ├── -show        show stored results
│   ├── -names       list found subdomains
│   └── -enum        show enumeration history
└── version
```

> **Note:** v5 significantly changed the CLI from v3/v4. Many flags were renamed or removed.

## Key Flags (enum)

| Flag | Default | Note |
|------|---------|------|
| `-d <domain>` | — | target domain (repeatable) |
| `-o <file>` | stdout | output file |
| `-passive` | off | passive-only enumeration (no DNS brute) |
| `-active` | off | include active techniques (cert grabbing, zone transfer) |
| `-config <file>` | `~/.config/amass/config.yaml` | config file with API keys |
| `-dir <path>` | `~/.config/amass/` | output/graph database directory |
| `-timeout <n>` | — | timeout in minutes |
| `-src` | off | show data source for each result |
| `-ip` | off | show IP addresses |
| `-ipv4` | off | show only IPv4 addresses |
| `-ipv6` | off | show only IPv6 addresses |
| `-brute` | off | brute-force subdomain enumeration |
| `-w <file>` | — | wordlist for brute-force |
| `-rf <file>` | — | resolver file |
| `-max-dns-queries <n>` | — | max DNS queries per second |
| `-asn <asn>` | — | filter by ASN |
| `-cidr <cidr>` | — | filter by CIDR |

## Gotchas

1. **v5 changed CLI significantly** — old v3/v4 flags (`amass enum -brute -min-for-recursive 3`) may not work; check `amass enum -h`
2. **Very resource hungry** — amass active mode consumes significant CPU/RAM; use `-passive` for lightweight enumeration
3. **API keys are critical** — without config at `~/.config/amass/config.yaml`, coverage is limited to free sources
4. **Graph DB grows large** — amass stores results in a graph database in `-dir`; can consume GB of disk over time
5. **Slow compared to subfinder** — for quick passive enum, subfinder is faster; amass shines in deep/active recon
6. **`-timeout` is in minutes** — not seconds; set appropriately for large scopes

## bbflow Usage Pattern

```bash
# Quick passive enumeration
amass enum -d "$DOMAIN" -passive -o amass_passive.txt

# Active enumeration with source tracking
amass enum -d "$DOMAIN" -active -src -ip -o amass_active.txt

# With config and timeout
amass enum -d "$DOMAIN" \
  -config ~/.config/amass/config.yaml \
  -passive -timeout 30 -o amass_results.txt

# Intel: discover root domains by ASN
amass intel -asn 12345 -o root_domains.txt

# Combine with subfinder for coverage
(subfinder -d "$DOMAIN" -all -silent; \
 amass enum -d "$DOMAIN" -passive) | sort -u > all_subs.txt
```
