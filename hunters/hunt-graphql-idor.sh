#!/usr/bin/env bash
# hunt-graphql-idor.sh — GraphQL 無認證 resolver + 整數 IDOR 探測
# 來源：public GraphQL IDOR writeup api.example.com（shipment(id:N) + companies + companyLookup）
#      disclosed GraphQL API writeup（__typename probe）
#
# 檢測：
#   1. __typename 無認證
#   2. Field suggestion（schema 洩漏）
#   3. 常見 root field 無認證枚舉（companies, users, nodes, orders, tickets, shipments）
#   4. Integer ID IDOR 序列探測（1..N 步進）
#
# 用法：
#   ./hunt-graphql-idor.sh https://api.example.com
#   ./hunt-graphql-idor.sh https://api.example.com /graphql
set -uo pipefail

HOST="${1:-}"
PATH_="${2:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host> [/path]"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./graphql_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }

PATHS=( "/graphql" "/api/graphql" "/v1/graphql" "/query" "/api/v2/graphql" "/" )
[ -n "$PATH_" ] && PATHS=( "$PATH_" )

log "=== GraphQL hunt: $HOST ==="

FOUND=""
for P in "${PATHS[@]}"; do
  URL="$HOST$P"
  RESP=$(curl -sk --max-time 8 -X POST "$URL" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}')
  if echo "$RESP" | grep -qE '"__typename":"(Query|Mutation)"'; then
    hit "GraphQL endpoint unauth: $URL"
    FOUND="$URL"
    break
  fi
done
[ -z "$FOUND" ] && { log "no unauth graphql"; exit 0; }

# Introspection
INTRO=$(curl -sk --max-time 10 -X POST "$FOUND" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name type { name } } } } }"}')
if echo "$INTRO" | grep -q '"fields":\['; then
  hit "introspection ON"
  echo "$INTRO" > "$OUT_DIR/${SLUG}_schema.json"
  # Extract root fields
  ROOT_FIELDS=$(echo "$INTRO" | python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  for f in d.get('data',{}).get('__schema',{}).get('queryType',{}).get('fields',[]):
    print(f.get('name',''))
except: pass")
  echo "$ROOT_FIELDS" | while read f; do
    [ -z "$f" ] && continue
    echo "   root: $f" >> "$OUT"
  done
else
  # field suggestion attack
  SUG=$(curl -sk --max-time 8 -X POST "$FOUND" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ xyznonexistent }"}')
  if echo "$SUG" | grep -qi "did you mean"; then
    hit "field suggestion enabled (schema leak via typo)"
    echo "$SUG" > "$OUT_DIR/${SLUG}_suggest.json"
  fi
fi

# Common unauth resolvers (public GraphQL IDOR writeup)
for Q in "companies" "users" "nodes" "orders" "tickets" "shipments" "organizations"; do
  RESP=$(curl -sk --max-time 8 -X POST "$FOUND" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ ${Q} { id } }\"}")
  if echo "$RESP" | grep -q "\"data\":{\"${Q}\":\["; then
    COUNT=$(echo "$RESP" | python3 -c "
import json,sys
try:
  print(len(json.load(sys.stdin)['data']['$Q']))
except: print('?')")
    hit "unauth list query { $Q }: $COUNT records"
  fi
done

# Integer IDOR on singular resolvers (shipment/order/user/ticket)
for Q in "shipment" "order" "user" "ticket" "node"; do
  R=$(curl -sk --max-time 8 -X POST "$FOUND" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ ${Q}(id: 1) { id } }\"}")
  if echo "$R" | grep -q "\"data\":{\"${Q}\":{\"id\""; then
    hit "integer IDOR candidate: { $Q(id: 1) } resolved unauth"
    # Try a few more IDs to confirm it's sequential (not just default demo)
    for ID in 100 1000 10000 50000; do
      RR=$(curl -sk --max-time 6 -X POST "$FOUND" \
        -H "Content-Type: application/json" \
        -d "{\"query\":\"{ ${Q}(id: $ID) { id } }\"}")
      if echo "$RR" | grep -q "\"id\""; then
        echo "     ${Q}(id: $ID) → resolved" >> "$OUT"
      fi
    done
  fi
done

log "=== done → $OUT ==="
