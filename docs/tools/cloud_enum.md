# cloud_enum v0.8

> Multi-cloud OSINT — AWS/Azure/GCP bucket and resource enumeration
> Source: https://github.com/initstring/cloud_enum
> VPS help captured: 2026-06-27

## Install

```bash
# VPS: installed at ~/Tools/cloud_enum
cd ~/Tools
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt

# Run as:
python3 ~/Tools/cloud_enum/cloud_enum.py
```

## Key Flags

| Flag | Note |
|------|------|
| `-k <keyword>` | keyword to enumerate (e.g. company name) |
| `-kf <file>` | file of keywords (one per line) |
| `-m <file>` | mutations wordlist (overrides built-in) |
| `-t <n>` | threads (default: 5) |
| `-l <file>` | log file path |
| `-f <format>` | output format: `text` (default), `json`, `csv` |
| `--disable-aws` | skip AWS S3/App/EC2 checks |
| `--disable-azure` | skip Azure Blob/App/DB/VM checks |
| `--disable-gcp` | skip GCP Bucket/App/Function/Project checks |
| `-qs` | quiet mode — suppress banner |
| `--no-color` | disable colored output |

## Enumeration Targets

| Provider | Resource Types |
|----------|---------------|
| AWS | S3 buckets, Elastic Beanstalk apps, EC2 instances |
| Azure | Blob containers, App Services, Databases, VMs |
| GCP | Storage buckets, App Engine apps, Cloud Functions, Firebase, Projects |

## Gotchas (bbflow-specific)

1. **Keyword-based, not domain-based** — input is company/org name (e.g. `acme`), not a domain; it generates permutations internally
2. **Built-in mutation wordlist** — appends common suffixes (`-dev`, `-backup`, `-prod`, etc.) to keywords; override with `-m`
3. **Thread count matters** — default 5 threads is slow for large keyword lists; `-t 10` is safe, `-t 20` may trigger rate limits
4. **Complements hunt-cloud-bucket.sh** — hunt-cloud-bucket.sh does direct curl probing; cloud_enum uses DNS + HTTP for broader coverage
5. **Python 3 required** — no pip package; run directly from cloned directory

## bbflow Usage Pattern

```bash
# Single keyword
python3 ~/Tools/cloud_enum/cloud_enum.py \
  -k "acmecorp" \
  -t 10 \
  -l "$OUT_DIR/cloud_enum.log"

# Multiple keywords from file
python3 ~/Tools/cloud_enum/cloud_enum.py \
  -kf "$OUT_DIR/keywords.txt" \
  -t 10 \
  -f json \
  -l "$OUT_DIR/cloud_enum.json"

# AWS-only scan
python3 ~/Tools/cloud_enum/cloud_enum.py \
  -k "targetcorp" \
  --disable-azure --disable-gcp \
  -t 10

# Stealth (fewer threads)
python3 ~/Tools/cloud_enum/cloud_enum.py \
  -k "targetcorp" \
  -t 2 \
  -l "$OUT_DIR/cloud_enum.log"
```
