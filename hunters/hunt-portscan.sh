#!/usr/bin/env bash
# hunt-portscan.sh — Fast port scan + service detection
#
# Pipeline: rustscan (fast SYN) → nmap (service/version on open ports)
# Falls back to nmap-only if rustscan not found.
#
# Usage:
#   OUT_DIR=/path hunt-portscan.sh <url-or-ip>

set -uo pipefail
TARGET="${1:-}"
[ -z "$TARGET" ] && { echo "usage: $0 <url-or-ip>"; exit 1; }
OUT_DIR="${OUT_DIR:-/tmp/bb-portscan-$$}"
mkdir -p "$OUT_DIR"

# Strip protocol/path to get hostname/IP
HOST=$(echo "$TARGET" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
[ -z "$HOST" ] && { echo "✗ cannot extract host from: $TARGET"; exit 1; }

SLUG=$(echo "$HOST" | tr '/:' '__')
OUTFILE="$OUT_DIR/${SLUG}.txt"

RUSTSCAN="$(command -v rustscan 2>/dev/null || echo '')"
NMAP="$(command -v nmap 2>/dev/null || echo '')"

[ -z "$NMAP" ] && { echo "✗ nmap not found (sudo apt install nmap)"; exit 0; }

echo "[$(date +%H:%M:%S)] === port scan: $HOST ==="

# ── Phase 1: fast port discovery ─────────────────────────────
if [ -n "$RUSTSCAN" ]; then
  echo "  using rustscan → nmap pipeline"
  OPEN_PORTS=$("$RUSTSCAN" -a "$HOST" --ulimit 5000 -q --no-nmap 2>/dev/null \
    | grep -oE '^[0-9]+' | tr '\n' ',' | sed 's/,$//' || echo "")
else
  echo "  rustscan not found — using nmap top-1000"
  OPEN_PORTS=""
fi

# ── Phase 2: nmap service/version detection ───────────────────
NMAP_OUT="$OUT_DIR/${SLUG}_nmap.txt"
if [ -n "$OPEN_PORTS" ]; then
  "$NMAP" -sV -sC -p "$OPEN_PORTS" --open -T4 "$HOST" -oN "$NMAP_OUT" 2>/dev/null || true
else
  "$NMAP" -sV -sC --top-ports 1000 --open -T4 "$HOST" -oN "$NMAP_OUT" 2>/dev/null || true
fi

# ── Parse & print interesting findings ───────────────────────
{
  echo ""
  python3 - "$NMAP_OUT" <<'PYEOF' 2>/dev/null || true
import sys, re

INTERESTING = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 636: "LDAPS", 873: "rsync", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker API (unauth!)", 2376: "Docker TLS", 3306: "MySQL",
    3389: "RDP", 4243: "Docker API", 4848: "GlassFish Admin", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC", 6379: "Redis",
    7001: "WebLogic", 7474: "Neo4j", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    8500: "Consul", 8888: "Jupyter/misc", 9000: "SonarQube/misc",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch cluster",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB", 50000: "Kubernetes API",
}
HIGH_RISK = {2375, 6379, 9200, 27017, 11211, 5601, 9090, 8500, 4848, 7001}

nmap_file = sys.argv[1]
try:
    content = open(nmap_file).read()
except Exception:
    print("  (no nmap output)")
    sys.exit(0)

port_lines = re.findall(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', content)
if not port_lines:
    print("  (no open ports found)")
    sys.exit(0)

for port_str, service, version in port_lines:
    port = int(port_str)
    ver = version.strip()[:60]
    label = INTERESTING.get(port, service)
    is_high = port in HIGH_RISK or any(x in (service + ver).lower()
              for x in ('unauth', 'anon', 'unauthenticated', 'open'))
    line = f"  port {port}/tcp  {label}"
    if ver:
        line += f"  [{ver}]"
    if is_high:
        print(f"🔴 {line}")
    else:
        print(f"🟡 {line}")
PYEOF
} | tee -a "$OUTFILE"

echo "[$(date +%H:%M:%S)] === done → $OUTFILE ==="
