#!/usr/bin/env bash
# hunt-shodan-ip.sh — Shodan InternetDB passive port/CVE lookup（OSINT Arsenal §16.3）
#
# 對 live host 解析出 IP，查詢 Shodan InternetDB free API（無需 API key）。
# 回傳：開放 port、CPE 軟體版本、已知 CVE、hostname 清單。
#
# Severity mapping（§16.3）：
#   CRITICAL — CVE-known vuln 或 port 2375/3389/445/5432 exposed
#   HIGH     — port 22/23/21/161/389/873/1433/1521/2049 exposed
#   MEDIUM   — port 3000/3306/5601/6379/8080/8888/9200 exposed
#   LOW      — port 80/443/8443 only（standard web）
#
# 用法（host 模式，bbflow run_hunter 呼叫）：
#   ./hunt-shodan-ip.sh https://api.example.com

set -uo pipefail

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <host-url>"; exit 1; }
HOST=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1)

OUT_DIR="${OUT_DIR:-./shodan_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟠 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }

log "=== Shodan InternetDB: $HOST ==="

# 解析 IP（跳過 CNAME 鏈）
IP=$(dig +short A "$HOST" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
if [ -z "$IP" ]; then
  log "  $HOST: DNS resolution failed, skipping"
  exit 0
fi
log "  Resolved: $HOST → $IP"

sleep 1  # rate limit

RESP=$(curl -sk -m 20 "https://internetdb.shodan.io/${IP}" 2>/dev/null)
[ -z "$RESP" ] && { log "  no response from InternetDB"; exit 0; }

# 檢查是否為「no information」
echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('ports') or d.get('vulns') else 1)" 2>/dev/null || {
  log "  $IP: no Shodan data"
  exit 0
}

PORTS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(str(p) for p in d.get('ports',[])))" 2>/dev/null)
VULNS=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d.get('vulns',[])))" 2>/dev/null)
CPES=$(echo "$RESP"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(' | '.join(d.get('cpes',[])[:5]))" 2>/dev/null)
TAGS=$(echo "$RESP"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d.get('tags',[])))" 2>/dev/null)
HOSTNAMES=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(','.join(d.get('hostnames',[])[:5]))" 2>/dev/null)

log "  IP: $IP | Ports: ${PORTS:-none} | Tags: ${TAGS:-none}"
[ -n "$CPES" ]      && info_hit "  CPEs: $CPES"
[ -n "$HOSTNAMES" ] && info_hit "  Hostnames: $HOSTNAMES"

# CVE → CRITICAL 直接
if [ -n "$VULNS" ] && [ "$VULNS" != "" ]; then
  hit "[CRITICAL] $HOST ($IP) — known CVEs: $VULNS"
fi

# High-risk port mapping
CRITICAL_PORTS=(2375 2376 3389 445 5900)
HIGH_PORTS=(21 22 23 25 111 135 139 161 389 873 1433 1521 2049 6379 27017 9200 5601)
MEDIUM_PORTS=(3000 3306 5432 8080 8888 8443 9090 4848 7001)

for p in ${CRITICAL_PORTS[@]}; do
  echo ",$PORTS," | grep -q ",$p," && hit "[CRITICAL] $HOST ($IP) — port $p open ($(case $p in 2375) echo 'Docker unauth API';; 3389) echo 'RDP';; 445) echo 'SMB EternalBlue';; 5900) echo 'VNC';; 2376) echo 'Docker TLS';; esac))"
done

for p in ${HIGH_PORTS[@]}; do
  echo ",$PORTS," | grep -q ",$p," && warn "[HIGH] $HOST ($IP) — port $p open"
done

for p in ${MEDIUM_PORTS[@]}; do
  echo ",$PORTS," | grep -q ",$p," && info_hit "[MEDIUM] $HOST ($IP) — port $p open"
done

log "=== done: $HOST ($IP) ==="
