# gowitness v3

> Visual recon — headless Chrome screenshots + metadata collection
> Source: https://github.com/sensepost/gowitness
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/sensepost/gowitness/v3@latest
```

## Command Tree

```
gowitness
├── scan
│   ├── single   -u <URL>
│   ├── file     -f <file>  (or stdin: cat urls | gowitness scan file -f -)
│   ├── cidr     -c <CIDR>
│   ├── nmap     -f <nmap.xml>
│   └── nessus   -f <nessus.xml>
├── report
│   ├── server   --db-uri sqlite://...   (Web UI)
│   ├── generate --db-uri sqlite://...   (static HTML)
│   ├── list     --db-uri sqlite://...
│   ├── merge    (multiple SQLite → one)
│   ├── convert  (SQLite ↔ JSONL)
│   └── migrate  (v2 → v3)
└── version
```

## Key Flags (scan level)

| Flag | Default | Note |
|------|---------|------|
| `-s, --screenshot-path` | `./screenshots` | where images are stored |
| `--screenshot-format` | `jpeg` | `jpeg` or `png` |
| `--screenshot-fullpage` | off | full-page instead of viewport |
| `--screenshot-jpeg-quality` | 60 | 1-100 |
| `-t, --threads` | 6 | concurrent goroutines |
| `-T, --timeout` | 60 | seconds before page timeout |
| `--delay` | 3 | seconds between navigation and screenshot |
| `--write-db` | off | **must enable to use report commands** |
| `--write-db-uri` | `sqlite://gowitness.sqlite3` | SQLite/MySQL/Postgres |
| `--write-jsonl` | off | write JSONL output |
| `--write-csv` | off | write CSV output |
| `--save-content` | off | save network request content (WARNING: huge) |
| `--chrome-proxy` | none | `proto://address:port` |
| `--chrome-user-agent` | Chrome 128 UA | custom UA string |
| `--chrome-header` | none | repeatable: `--chrome-header "X-Custom: val"` |
| `--chrome-wss-url` | none | connect to remote Chrome DevTools |
| `--http-code-filter` | all | only screenshot specific codes |
| `-q, --quiet` | off | silence logging |

## Gotchas (bbflow-specific)

1. **No `--db-uri` on scan** — v2 had `--db-uri`; v3 requires `--write-db --write-db-uri "sqlite://path"`
2. **No `--timeout` for delay** — `--timeout` is page timeout (60s default), `--delay` is wait-before-screenshot (3s)
3. **No `--chrome-flags`** — use specific flags: `--chrome-proxy`, `--chrome-user-agent`, `--chrome-header`
4. **`--write-db` is opt-in** — without it, only screenshots are saved (no DB for report commands)
5. **scan file stdin** — use `-f -` for stdin piping: `cat urls.txt | gowitness scan file -f -`

## bbflow Usage Pattern

```bash
# Single target
gowitness scan single \
  --url "$TARGET" \
  --screenshot-path "$SCREENSHOT_DIR" \
  --write-db \
  --write-db-uri "sqlite://$DB_FILE" \
  --delay 3

# Bulk from file
gowitness scan file \
  -f "$HOSTS_FILE" \
  --screenshot-path "$SCREENSHOT_DIR" \
  --write-db \
  --write-db-uri "sqlite://$DB_FILE" \
  --delay 3 \
  --threads 6

# View results
gowitness report server --db-uri "sqlite://$DB_FILE"
```
