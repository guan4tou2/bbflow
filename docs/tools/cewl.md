# CeWL

> Custom wordlist generator — spider a website and extract unique words for targeted brute-forcing
> Source: https://github.com/digininja/CeWL
> VPS help captured: 2026-06-27

## Install

```bash
# VPS: installed at ~/Tools/CeWL (Ruby + Bundler)
cd ~/Tools
git clone https://github.com/digininja/CeWL.git
cd CeWL
bundle install

# Run as:
ruby ~/Tools/CeWL/cewl.rb
# or if executable:
~/Tools/CeWL/cewl.rb
```

## Key Flags

| Flag | Note |
|------|------|
| `-d <n>` | spider depth (default: 2) |
| `-m <n>` | minimum word length (default: 3) |
| `-w <file>` | write wordlist to file |
| `-e` | extract email addresses (written to separate file) |
| `--email_file <file>` | output file for emails (with `-e`) |
| `--meta` | extract metadata from documents (PDF/DOCX/etc.) |
| `-a` | include metadata in wordlist |
| `-c` | show word count next to each word |
| `--lowercase` | convert all words to lowercase |
| `-n` | don't output the wordlist to stdout |
| `--with-numbers` | include words containing numbers |
| `-u <UA>` | custom User-Agent string |
| `--proxy_host <host>` | proxy hostname |
| `--proxy_port <port>` | proxy port |
| `--auth_type <type>` | auth type: `basic` or `digest` |
| `--auth_user <user>` | auth username |
| `--auth_pass <pass>` | auth password |
| `-H <header>` | custom header (repeatable) |
| `--debug` | debug output |
| `-v` | verbose |

## Gotchas (bbflow-specific)

1. **Ruby + Bundler required** — needs Ruby 2.7+ and `bundle install` before first run; fails silently without gems
2. **Slow on large sites** — spidering depth 3+ on content-heavy sites can take 10+ minutes; use `-d 1` or `-d 2` for initial runs
3. **Complements SecLists** — generate target-specific words to append to generic wordlists for password spraying or directory fuzzing
4. **Email extraction is separate** — `-e` extracts emails but writes them to a different file (`--email_file`), not the main wordlist
5. **Metadata extraction** — `--meta` downloads and parses PDF/DOCX/XLSX for author names, software versions, usernames; slow but high value for OSINT

## bbflow Usage Pattern

```bash
# Basic wordlist generation
ruby ~/Tools/CeWL/cewl.rb "https://target.com" \
  -d 2 \
  -m 5 \
  --lowercase \
  --with-numbers \
  -w "$OUT_DIR/cewl_wordlist.txt"

# With email extraction + metadata
ruby ~/Tools/CeWL/cewl.rb "https://target.com" \
  -d 2 \
  -m 5 \
  -e --email_file "$OUT_DIR/cewl_emails.txt" \
  --meta -a \
  -w "$OUT_DIR/cewl_wordlist.txt"

# Shallow + fast (just homepage)
ruby ~/Tools/CeWL/cewl.rb "https://target.com" \
  -d 0 \
  -m 6 \
  --lowercase \
  -w "$OUT_DIR/cewl_shallow.txt"

# Combine with SecLists for fuzzing
cat "$OUT_DIR/cewl_wordlist.txt" "$SECLISTS/Discovery/Web-Content/raft-small-words.txt" \
  | sort -u > "$OUT_DIR/combined_wordlist.txt"
```
