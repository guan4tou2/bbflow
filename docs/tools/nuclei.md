# nuclei v3.8.0

> Template-based vulnerability scanner for automated security testing
> Source: https://github.com/projectdiscovery/nuclei
> VPS help captured: 2026-06-27

## Install

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates   # pull community templates on first run
```

## Command Tree

```
nuclei
├── scan (default)     -u/-l targets, -t templates
├── -update            update nuclei binary
├── -update-templates  update community templates
└── -validate          validate templates
```

## Key Flags

| Flag | Default | Note |
|------|---------|------|
| `-u <url>` | — | single target URL |
| `-l <file>` | — | file with list of target URLs |
| `-t <template>` | all | template/directory to run (repeatable) |
| `-tags <tags>` | — | run templates matching tags (comma-separated) |
| `-severity <sev>` | all | filter by severity: `info,low,medium,high,critical` |
| `-rl <n>` | 150 | **total** requests/second across all templates |
| `-bs <n>` | 25 | bulk size — number of hosts per template batch |
| `-c <n>` | 25 | maximum templates executed in parallel |
| `-o <file>` | stdout | output file |
| `-jsonl` | off | JSONL output (one JSON object per line) |
| `-silent` | off | only show findings |
| `-proxy <url>` | — | HTTP/SOCKS5 proxy |
| `-H <header>` | — | custom header (repeatable): `-H "X-Bug-Bounty: hunter"` |
| `-as` | off | automatic scan — select templates based on tech detect |
| `-nc` | off | no color output |
| `-stats` | off | show execution statistics |
| `-timeout <n>` | 10 | timeout in seconds per request |
| `-retries <n>` | 1 | number of retries |
| `-etags <tags>` | — | exclude templates matching tags |
| `-es <sev>` | — | exclude severities |

## Gotchas

1. **`-rl` is total req/s, not per-template** — setting `-rl 100` with 10 templates means ~10 req/s each, not 100 each
2. **Use `-jsonl` not `-json`** — `-json` does not exist; the flag is `-jsonl` for structured output
3. **Template auto-update** — on first run nuclei auto-downloads templates; use `-update-templates` to refresh; use `-duc` (disable update check) in CI
4. **Interactsh callback** — OOB templates need interactsh; defaults to public server; self-host with `-iserver` for stealth
5. **Headless templates** — require Chrome/Chromium installed; enable with `-headless`
6. **Large template sets are slow** — scope with `-tags`, `-severity`, or `-t path/` to avoid hour-long scans

## bbflow Usage Pattern

```bash
# Quick scan single target (medium+ severity)
nuclei -u "$TARGET" \
  -severity medium,high,critical \
  -rl 50 -bs 25 -c 10 \
  -o nuclei_results.txt -jsonl -silent

# Bulk scan from httpx output
nuclei -l live_hosts.txt \
  -tags cve,exposure,misconfig \
  -severity medium,high,critical \
  -rl 100 -bs 25 -c 25 \
  -o nuclei_results.jsonl -jsonl -silent \
  -H "X-Bug-Bounty: hunter"

# Targeted template run
nuclei -u "$TARGET" \
  -t nuclei-templates/http/exposures/ \
  -rl 30 -o exposures.txt -jsonl

# Auto-scan (tech-detect → template selection)
nuclei -u "$TARGET" -as -rl 50 -o auto_results.jsonl -jsonl
```
