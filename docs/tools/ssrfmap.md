# SSRFmap

> SSRF exploitation framework — automatic testing of SSRF parameters with modular payloads
> Source: https://github.com/swisskyrepo/SSRFmap
> VPS help captured: 2026-06-27

## Install

```bash
# VPS: installed at ~/Tools/SSRFmap
cd ~/Tools
git clone https://github.com/swisskyrepo/SSRFmap.git
cd SSRFmap
pip3 install -r requirements.txt

# Run as:
python3 ~/Tools/SSRFmap/ssrfmap.py
```

## Key Flags

| Flag | Note |
|------|------|
| `-r <file>` | request file (Burp-style saved HTTP request) |
| `-p <param>` | vulnerable parameter name to inject into |
| `-m <modules>` | modules to run (comma-separated) |
| `--lhost <ip>` | attacker listening host (for OOB/reverse shell modules) |
| `--lport <port>` | attacker listening port |
| `--ssl` | use HTTPS for the target request |
| `--proxy <url>` | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `--level <1-5>` | payload aggressiveness level |
| `--timeout <sec>` | request timeout |
| `--verbose` | verbose output |

## Modules

| Module | Purpose |
|--------|---------|
| `readfiles` | read local files via file:// (e.g. /etc/passwd) |
| `portscan` | internal port scanning via SSRF |
| `networkscan` | internal network discovery |
| `redis` | exploit Redis via SSRF (write crontab/SSH key) |
| `memcache` | read/write Memcached via gopher:// |
| `mysql` | dump MySQL data via gopher:// |
| `fastcgi` | exploit PHP-FPM via gopher:// |
| `smtp` | send email via gopher:// |
| `zabbix` | exploit Zabbix agent via SSRF |
| `docker` | interact with Docker API via SSRF |
| `custom` | custom URL payload |
| `tomcat` | exploit Tomcat manager via SSRF |
| `alibaba` | Alibaba Cloud metadata |
| `aws` | AWS metadata (169.254.169.254) |
| `gce` | GCP metadata |
| `digitalocean` | DigitalOcean metadata |
| `azure` | Azure metadata |

## Request File Format

Burp-style raw HTTP request (save from Burp/mitmproxy):

```
POST /api/fetch HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=abc123

url=https://example.com&format=json
```

## Gotchas (bbflow-specific)

1. **Needs saved request file** — does NOT accept a URL directly; must save the HTTP request to a file first (Burp: right-click > Save item)
2. **Exploitation tool** — only use on targets where you have confirmed SSRF AND explicit authorization; never run speculatively
3. **`-p` matches parameter name** — it replaces the value of the named parameter with SSRF payloads
4. **gopher:// modules need careful targeting** — Redis/MySQL/FastCGI modules generate gopher:// payloads; target must support gopher scheme
5. **Cloud metadata modules** — `aws`/`gce`/`azure` modules test IMDSv1; IMDSv2 requires token header (not supported)
6. **VPS-only** — never run exploitation modules from local machine

## bbflow Usage Pattern

```bash
# Read local files via confirmed SSRF
python3 ~/Tools/SSRFmap/ssrfmap.py \
  -r "$OUT_DIR/request.txt" \
  -p url \
  -m readfiles

# Cloud metadata extraction
python3 ~/Tools/SSRFmap/ssrfmap.py \
  -r "$OUT_DIR/request.txt" \
  -p url \
  -m aws,gce,azure

# Internal port scan via SSRF
python3 ~/Tools/SSRFmap/ssrfmap.py \
  -r "$OUT_DIR/request.txt" \
  -p url \
  -m portscan

# With proxy (for logging)
python3 ~/Tools/SSRFmap/ssrfmap.py \
  -r "$OUT_DIR/request.txt" \
  -p url \
  -m readfiles \
  --proxy http://127.0.0.1:8080
```
