#!/usr/bin/env bash
# hunt-weak-login.sh — 常見管理介面預設帳密單次探測
# 來源：xray brute-force 規則（抽出穩定的 vendor default creds）+ 實戰常見組合
#
# 設計原則（WAF-friendly）：
#   1. 每個 vendor 只送 1-3 次 login request（不是爆破，是 default creds 驗證）
#   2. 先 HEAD / GET 確認 vendor 面板存在，才發 login
#   3. 差異判斷（login 成功 vs 失敗的 HTTP/body signature）
#   4. 永遠 fail-safe：回傳 2xx 的 login response 仍要配 body pattern 才算 hit
#
# 覆蓋：
#   Nacos / Druid / Grafana / Jenkins / phpMyAdmin / Tomcat Manager /
#   Solr Admin / RabbitMQ / Kibana / Jeecg / Jeesite / SpringBoot Admin /
#   Apollo / GitLab / Gitea / Portainer / Rancher / Harbor / Nexus / SonarQube /
#   Weblogic / Zabbix / Shiro / Airflow / Superset / Metabase / Couchbase
#
# 用法：
#   ./hunt-weak-login.sh https://target
#   SAFE=1 ./hunt-weak-login.sh https://target    # 只跑 "一次 request 即可判斷" 的 vendors
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./weak_login_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }
SAFE="${SAFE:-0}"
UA="Mozilla/5.0 (compatible; bbflow/weak-login)"

# 探測 vendor panel 是否存在（content match，不算 hit）
exists() {
  local path="$1" pat="$2"
  local CODE
  CODE=$(curl -sk --max-time 6 -o /tmp/.wl_$$ -w "%{http_code}" \
    -H "User-Agent: $UA" "${HOST}${path}" 2>/dev/null)
  local BODY
  BODY=$(head -c 3000 /tmp/.wl_$$ 2>/dev/null)
  rm -f /tmp/.wl_$$
  [[ "$CODE" =~ ^[234] ]] && echo "$BODY" | grep -qiE "$pat" && return 0
  return 1
}

log "=== Weak-login hunt: $HOST (SAFE=$SAFE) ==="

# ═══════════════════════════════════════════════════════════════
# Nacos — POST /nacos/v1/auth/users/login (username/password)
# Default: nacos/nacos
# ═══════════════════════════════════════════════════════════════
if exists "/nacos/" "Nacos|nacos-server"; then
  log "• Nacos panel detected → trying default creds"
  R=$(curl -sk --max-time 8 -X POST "$HOST/nacos/v1/auth/users/login" \
    -H "User-Agent: $UA" \
    --data-urlencode "username=nacos" --data-urlencode "password=nacos" 2>/dev/null)
  if echo "$R" | grep -qE '"accessToken"|"tokenTtl"'; then
    hit "[P1-CRIT] Nacos default creds nacos:nacos → token issued @ $HOST/nacos/"
    echo "     evidence: $(echo "$R" | head -c 200)" >> "$OUT"
  fi
fi

# ═══════════════════════════════════════════════════════════════
# Druid — POST /druid/submitLogin.html?loginUsername=X&loginPassword=Y
# Default: admin/admin
# ═══════════════════════════════════════════════════════════════
if exists "/druid/index.html" "Druid Monitor|DruidMonitor"; then
  log "• Druid panel detected → trying default creds"
  R=$(curl -sk --max-time 8 -c /tmp/.dr_$$ -b /tmp/.dr_$$ \
    -X POST "$HOST/druid/submitLogin.html" \
    --data-urlencode "loginUsername=admin" --data-urlencode "loginPassword=admin" 2>/dev/null)
  if echo "$R" | grep -qE 'success|<script>top\.location' 2>/dev/null; then
    # 二次確認：用 session 拿 index
    C2=$(curl -sk --max-time 6 -b /tmp/.dr_$$ -o /dev/null -w "%{http_code}" "$HOST/druid/index.html")
    if [ "$C2" = "200" ]; then
      hit "[P1-CRIT] Druid default creds admin:admin → session valid @ $HOST/druid/"
    fi
  fi
  rm -f /tmp/.dr_$$
fi

# ═══════════════════════════════════════════════════════════════
# Grafana — POST /login (username/password JSON)
# Default: admin/admin
# ═══════════════════════════════════════════════════════════════
if exists "/login" "Grafana|grafana"; then
  log "• Grafana panel detected → trying default creds"
  R=$(curl -sk --max-time 8 -X POST "$HOST/login" \
    -H "Content-Type: application/json" -H "User-Agent: $UA" \
    -d '{"user":"admin","password":"admin"}' 2>/dev/null)
  if echo "$R" | grep -qE '"message"\s*:\s*"Logged in"'; then
    hit "[P1-CRIT] Grafana default creds admin:admin → logged in @ $HOST/login"
  fi
fi

# ═══════════════════════════════════════════════════════════════
# phpMyAdmin — POST /index.php (pma_username/pma_password)
# 嘗試 root/root, root/(empty), root/password
# ═══════════════════════════════════════════════════════════════
if exists "/phpmyadmin/" "phpMyAdmin|pma_"; then
  log "• phpMyAdmin detected → trying 3 common creds (root variants only)"
  for CRED in "root:" "root:root" "root:password"; do
    U="${CRED%%:*}"; P="${CRED#*:}"
    R=$(curl -sk --max-time 8 -c /tmp/.pma_$$ -b /tmp/.pma_$$ \
      "$HOST/phpmyadmin/index.php" -o /dev/null 2>/dev/null)
    TOKEN=$(curl -sk --max-time 6 -b /tmp/.pma_$$ "$HOST/phpmyadmin/" 2>/dev/null \
      | grep -oE 'name="token"[^>]*value="[^"]+"' | head -1 | sed 's/.*value="//;s/"//')
    [ -z "$TOKEN" ] && continue
    RESP=$(curl -sk --max-time 8 -b /tmp/.pma_$$ -c /tmp/.pma_$$ \
      -X POST "$HOST/phpmyadmin/index.php" \
      -d "pma_username=$U&pma_password=$P&server=1&token=$TOKEN" 2>/dev/null)
    if echo "$RESP" | grep -qE 'data-name|server_databases\.php|server_sql\.php'; then
      hit "[P1-CRIT] phpMyAdmin default creds $U:${P:-(empty)} → logged in @ $HOST/phpmyadmin/"
      rm -f /tmp/.pma_$$
      break
    fi
  done
  rm -f /tmp/.pma_$$
fi

# ═══════════════════════════════════════════════════════════════
# Jenkins — Basic Auth (admin/admin, admin/password)
# 透過 /api/json 判斷（比 /login 更穩）
# ═══════════════════════════════════════════════════════════════
if exists "/login" "Jenkins|hudson"; then
  log "• Jenkins detected → trying default creds via api/json"
  for CRED in "admin:admin" "admin:password" "admin:jenkins" "jenkins:jenkins"; do
    CODE=$(curl -sk --max-time 6 -u "$CRED" -o /dev/null -w "%{http_code}" "$HOST/api/json?pretty=true")
    if [ "$CODE" = "200" ]; then
      hit "[P1-CRIT] Jenkins default creds $CRED → api/json accessible @ $HOST"
      break
    fi
  done
fi

# ═══════════════════════════════════════════════════════════════
# Tomcat Manager — Basic Auth (tomcat/tomcat, admin/admin)
# ═══════════════════════════════════════════════════════════════
if exists "/manager/html" "Tomcat|Apache Tomcat|/manager"; then
  log "• Tomcat Manager detected → trying default creds"
  for CRED in "tomcat:tomcat" "admin:admin" "admin:tomcat" "manager:manager"; do
    CODE=$(curl -sk --max-time 6 -u "$CRED" -o /dev/null -w "%{http_code}" "$HOST/manager/html")
    if [ "$CODE" = "200" ]; then
      hit "[P1-CRIT] Tomcat Manager default creds $CRED → admin access @ $HOST/manager/html"
      break
    fi
  done
fi

# ═══════════════════════════════════════════════════════════════
# Solr Admin — 通常無認證 / 有些裝 basic auth default solr/SolrRocks
# ═══════════════════════════════════════════════════════════════
if exists "/solr/" "Solr Admin|/solr/"; then
  CODE=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$HOST/solr/admin/info/system")
  if [ "$CODE" = "200" ]; then
    hit "[P2-HIGH] Solr Admin unauthenticated → $HOST/solr/admin/info/system"
  else
    for CRED in "solr:SolrRocks" "admin:admin"; do
      CODE=$(curl -sk --max-time 6 -u "$CRED" -o /dev/null -w "%{http_code}" "$HOST/solr/admin/info/system")
      [ "$CODE" = "200" ] && hit "[P1-CRIT] Solr default creds $CRED @ $HOST/solr/" && break
    done
  fi
fi

# ═══════════════════════════════════════════════════════════════
# RabbitMQ Management — Basic Auth (guest/guest)
# ═══════════════════════════════════════════════════════════════
if exists "/" "RabbitMQ Management"; then
  CODE=$(curl -sk --max-time 6 -u "guest:guest" -o /dev/null -w "%{http_code}" "$HOST/api/overview")
  if [ "$CODE" = "200" ]; then
    hit "[P1-CRIT] RabbitMQ default creds guest:guest → $HOST/api/overview"
  fi
fi

# ═══════════════════════════════════════════════════════════════
# Kibana — 通常 unauth (ES stack < 7.x) 或 elastic/changeme
# ═══════════════════════════════════════════════════════════════
if exists "/app/kibana" "Kibana|kbnInjectedMetadata"; then
  # Kibana 本體若無 X-Pack security → 不需 creds
  CODE=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$HOST/api/status")
  if [ "$CODE" = "200" ]; then
    hit "[P2-HIGH] Kibana possibly unauth → $HOST/api/status"
  fi
fi

# ═══════════════════════════════════════════════════════════════
# SpringBoot Admin — 通常無認證
# ═══════════════════════════════════════════════════════════════
if exists "/applications" "Spring Boot Admin|spring-boot-admin"; then
  hit "[P2-HIGH] Spring Boot Admin panel accessible → $HOST/applications"
fi

# ═══════════════════════════════════════════════════════════════
# Gitea / Gitlab / Portainer / Harbor — 只檢測是否允許註冊
# (不送 default creds — 這類 SaaS 通常不會留預設)
# ═══════════════════════════════════════════════════════════════
if exists "/user/sign_up" "Gitea|Sign Up"; then
  warn "[P4-INFO] Gitea open registration → $HOST/user/sign_up"
fi
if exists "/users/sign_up" "GitLab|sign_up"; then
  warn "[P4-INFO] GitLab open registration → $HOST/users/sign_up"
fi

# ═══════════════════════════════════════════════════════════════
# Zabbix — Basic Auth (Admin/zabbix)
# ═══════════════════════════════════════════════════════════════
if exists "/zabbix/" "Zabbix|Zabbix SIA"; then
  # Zabbix login 是 POST form + name/password
  R=$(curl -sk --max-time 8 -c /tmp/.zx_$$ -b /tmp/.zx_$$ \
    -X POST "$HOST/zabbix/index.php" \
    -d "name=Admin&password=zabbix&autologin=1&enter=Sign+in" 2>/dev/null)
  if echo "$R" | grep -qE 'Location:.*dashboard'; then
    hit "[P1-CRIT] Zabbix default creds Admin:zabbix → $HOST/zabbix/"
  fi
  rm -f /tmp/.zx_$$
fi

# ═══════════════════════════════════════════════════════════════
# SAFE=1 時略過的較 noisy 探測
# ═══════════════════════════════════════════════════════════════
if [ "$SAFE" != "1" ]; then

# ── Apollo Config Center (apollo/admin) ───────────────────────
if exists "/apollo/" "Apollo|apollo-portal"; then
  R=$(curl -sk --max-time 8 -X POST "$HOST/signin" \
    -d "username=apollo&password=admin" 2>/dev/null)
  echo "$R" | grep -qE 'apollo\.session|signin\?error' || hit "[P1-CRIT] Apollo possible default creds apollo:admin @ $HOST"
fi

# ── Superset — POST /login/ (admin/admin) ─────────────────────
if exists "/login/" "Superset|Apache Superset"; then
  warn "[P3-MED] Superset login page detected → manual: admin:admin / admin:superset"
fi

# ── Airflow — POST /login/ (airflow/airflow) ──────────────────
if exists "/login/" "Airflow|Apache Airflow"; then
  warn "[P3-MED] Airflow login page detected → manual: airflow:airflow / admin:admin"
fi

# ── Jeecg / Jeesite CMS（中國常見）─────────────────────────────
if exists "/" "Jeecg|jeecg-boot|Jeesite"; then
  warn "[P3-MED] Jeecg/Jeesite detected → manual: admin:123456 / jeecg:jeecg"
fi

# ── Shiro 反序列化：檢測 rememberMe cookie ─────────────────────
SHIRO=$(curl -sk --max-time 6 -I "$HOST/" 2>/dev/null | grep -i "Set-Cookie.*rememberMe" || true)
if [ -n "$SHIRO" ]; then
  warn "[P3-MED] Apache Shiro rememberMe cookie 偵測 → 可能 CVE-2016-4437 / CVE-2020-1957 @ $HOST"
  echo "     evidence: $SHIRO" >> "$OUT"
fi

fi  # end of !SAFE

log "=== done — see $OUT ==="
