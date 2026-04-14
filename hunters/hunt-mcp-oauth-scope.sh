#!/usr/bin/env bash
# hunt-mcp-oauth-scope.sh — MCP OAuth scope mismatch / consent screen 與 token 能力差異
# 來源：Intercom 2026-04-14 ready-to-submit
#        F3 consent 只顯示 View，但 token 含 create_article → Article 14619495 已驗證
#
# 流程：
#   1. 探測 /.well-known/oauth-authorization-server（RFC 8414）
#   2. 探測 /.well-known/openid-configuration
#   3. 探測 MCP server endpoints（/mcp、/sse、/stream、標準 JSON-RPC）
#   4. 如果 authorize endpoint 存在 → 提取公告 scope 清單
#   5. 如果有 token (env MCP_TOKEN) → 呼叫 tools/list 對比實際能力
#   6. 探測 known MCP paths（初始化、tools/list、resources/list、prompts/list）
#
# 用法：
#   ./hunt-mcp-oauth-scope.sh https://target.com
#   MCP_TOKEN=<bearer> ./hunt-mcp-oauth-scope.sh https://target.com
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./mcp_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
info(){ echo "   $*" >> "$OUT"; }

log "=== MCP OAuth scope hunt: $HOST ==="

# ── 1. RFC 8414 OAuth discovery ────────────────────────────────
for WK in "/.well-known/oauth-authorization-server" "/.well-known/oauth-authorization-server/mcp" "/.well-known/openid-configuration"; do
  RESP=$(curl -sk --max-time 6 "${HOST}${WK}")
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "${HOST}${WK}")
  if [[ "$CODE" =~ ^2 ]] && echo "$RESP" | grep -q '"authorization_endpoint"\|"issuer"'; then
    hit "OAuth discovery: ${HOST}${WK}"
    echo "$RESP" > "$OUT_DIR/${SLUG}_oauth_disc.json"
    # Extract endpoints + supported scopes
    echo "$RESP" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for k in ['issuer','authorization_endpoint','token_endpoint','userinfo_endpoint','registration_endpoint','revocation_endpoint','jwks_uri','introspection_endpoint']:
        if d.get(k): print(f'     {k}: {d[k]}')
    if 'scopes_supported' in d:
        print(f'     scopes_supported: {d[\"scopes_supported\"]}')
    if 'response_types_supported' in d:
        print(f'     response_types: {d[\"response_types_supported\"]}')
    if 'code_challenge_methods_supported' in d:
        print(f'     pkce_methods: {d[\"code_challenge_methods_supported\"]}')
except: pass" >> "$OUT"
  fi
done

# ── 2. MCP server paths ────────────────────────────────────────
for MP in "/mcp" "/mcp/sse" "/mcp/stream" "/sse" "/api/mcp" "/v1/mcp"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 "${HOST}${MP}")
  HEADERS=$(curl -skI --max-time 6 "${HOST}${MP}")
  if [[ "$CODE" =~ ^(200|401|405|406) ]]; then
    CT=$(echo "$HEADERS" | grep -i "^content-type:" | head -1 | tr -d '\r')
    if echo "$CT" | grep -qiE "event-stream|json|stream"; then
      hit "MCP endpoint candidate: ${HOST}${MP} [$CODE] ($CT)"
      MCP_URL="${HOST}${MP}"
    fi
  fi
done

# ── 3. MCP JSON-RPC probes（無 token） ─────────────────────────
if [ -n "${MCP_URL:-}" ]; then
  # initialize
  INIT=$(curl -sk --max-time 8 -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"hunt","version":"1.0"}}}' \
    "$MCP_URL")
  if echo "$INIT" | grep -q '"serverInfo"\|"protocolVersion"'; then
    hit "MCP initialize responded unauth"
    echo "$INIT" | head -c 500 >> "$OUT"
    echo "" >> "$OUT"
  fi

  # tools/list（無認證情況下能列出工具 = 部分洩漏）
  TOOLS=$(curl -sk --max-time 8 -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' "$MCP_URL")
  if echo "$TOOLS" | grep -q '"tools":'; then
    hit "MCP tools/list exposed unauth"
    echo "$TOOLS" > "$OUT_DIR/${SLUG}_tools.json"
    echo "$TOOLS" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    for t in d.get('result',{}).get('tools',[]):
        print(f'     tool: {t.get(\"name\")}  {t.get(\"description\",\"\")[:80]}')
except: pass" >> "$OUT"
  fi
fi

# ── 4. 若有 token，列出實際可用工具 → 對比 consent scope ──────
if [ -n "${MCP_TOKEN:-}" ] && [ -n "${MCP_URL:-}" ]; then
  log "authed tools/list with MCP_TOKEN"
  AUTH_TOOLS=$(curl -sk --max-time 10 -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${MCP_TOKEN}" \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' "$MCP_URL")
  if echo "$AUTH_TOOLS" | grep -q '"tools":'; then
    echo "$AUTH_TOOLS" > "$OUT_DIR/${SLUG}_tools_authed.json"
    # Look for WRITE-level tools (create/update/delete/execute)
    WRITE_TOOLS=$(echo "$AUTH_TOOLS" | python3 -c "
import json, sys, re
try:
    d = json.load(sys.stdin)
    for t in d.get('result',{}).get('tools',[]):
        name = t.get('name','')
        if re.search(r'create|update|delete|write|execute|send|post|modify|edit|remove', name, re.I):
            print(f'{name}')
except: pass")
    if [ -n "$WRITE_TOOLS" ]; then
      hit "authed token has WRITE-level tools:"
      echo "$WRITE_TOOLS" | while read t; do echo "     $t" >> "$OUT"; done
      hit "❗ scope mismatch candidate: 比對 consent screen 是否有 ALL of these scopes"
      hit "   若 consent 只顯示 read/view，但 token 可 create/update/delete → P3 confirmed"
    fi
  fi
fi

# ── 5. Prompt injection via get_* tools（Intercom F4 pattern）─
if [ -n "${MCP_TOKEN:-}" ] && [ -n "${MCP_URL:-}" ]; then
  info "prompt injection test slot: check if any get_* tool returns LLM-controllable content"
  info "  (manual follow-up: call get_conversation / get_article with attacker-controlled content)"
fi

log "=== done → $OUT ==="
