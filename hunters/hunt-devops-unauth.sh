#!/usr/bin/env bash
# hunt-devops-unauth.sh — DevOps / infra 工具無認證路徑探測
# 來源：public DevOps console leak pattern (Harbor public + ArgoCD /api/v1/settings）+ Prometheus (public pattern) /metrics
#
# 涵蓋：
#   Harbor / ArgoCD / Jenkins / Grafana / Prometheus / Kibana / Consul / etcd
#   / K8s API / Docker Registry v2 / Gitea / GitLab / SonarQube / Nexus /
#   Artifactory / Rancher / Portainer / Vault / Traefik / Rundeck
#
# 用法：
#   ./hunt-devops-unauth.sh https://target
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./devops_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }

probe() {
  local label="$1" path="$2" content_re="$3"
  local URL="${HOST}${path}"
  local RESP CODE
  RESP=$(curl -sk --max-time 6 -o /tmp/.dv_$$ -w "%{http_code}" "$URL")
  CODE="$RESP"
  local BODY
  BODY=$(head -c 500 /tmp/.dv_$$ 2>/dev/null)
  rm -f /tmp/.dv_$$
  if [[ "$CODE" =~ ^2 ]] && echo "$BODY" | grep -qE "$content_re"; then
    hit "$label: $URL [$CODE]"
    return 0
  fi
  return 1
}

log "=== DevOps unauth hunt: $HOST ==="

# ── Harbor (public DevOps console leak case) ───────────────────────────────────────
probe "Harbor projects"     "/api/v2.0/projects"          '"project_id"|"name"'
probe "Harbor users"        "/api/v2.0/users"             '"user_id"|"username"'
probe "Harbor repositories" "/api/v2.0/repositories"      '"repository_id"|"name"'
probe "Harbor statistics"   "/api/v2.0/statistics"        'total_project_count|private_repo_count'

# ── ArgoCD (public DevOps console leak case) ───────────────────────────────────────
probe "ArgoCD version"       "/api/version"               '"Version"'
probe "ArgoCD settings"      "/api/v1/settings"           'oidcConfig|dexConfig|appLabelKey|execEnabled'
probe "ArgoCD userinfo"      "/api/v1/session/userinfo"   'loggedIn|iss'
probe "ArgoCD applications"  "/api/v1/applications"       '"items"'

# ── Jenkins ────────────────────────────────────────────────────
probe "Jenkins root api"     "/api/json"                  '"mode"|"nodeName"|"jobs"'
probe "Jenkins people api"   "/asynchPeople/api/json"     '"users"'
probe "Jenkins script"       "/script"                    'Groovy|script console'
probe "Jenkins cli"          "/cli"                       'Jenkins CLI|remoting'
probe "Jenkins credentials"  "/credentials/store/system/domain/_/api/json"  '"credentials"'

# ── Grafana ────────────────────────────────────────────────────
probe "Grafana datasources"  "/api/datasources"           '"type"|"uid"'
probe "Grafana orgs"         "/api/orgs"                  '"orgId"|"name"'
probe "Grafana users"        "/api/users"                 '"login"'
probe "Grafana stats"        "/api/admin/stats"           'users|orgs|dashboards'

# ── Prometheus (differential response pattern) ────────────────────────────
probe "Prometheus metrics"   "/metrics"                   '# HELP|go_gc_duration|process_cpu'
probe "Prometheus query"     "/api/v1/query?query=up"     '"status":"success"'
probe "Prometheus targets"   "/api/v1/targets"            '"activeTargets"'
probe "Prometheus config"    "/api/v1/status/config"      'global:|scrape_configs'
probe "Prometheus flags"     "/api/v1/status/flags"       '"web.listen-address"'

# ── Kibana ─────────────────────────────────────────────────────
probe "Kibana status"        "/api/status"                '"version"|"overall"'
probe "Kibana .kibana index" "/.kibana"                   '"index"|"_source"'

# ── Consul ─────────────────────────────────────────────────────
probe "Consul agent self"    "/v1/agent/self"             '"Config"|"NodeName"'
probe "Consul catalog nodes" "/v1/catalog/nodes"          '"Node"|"Address"'
probe "Consul KV recursive"  "/v1/kv/?recurse"            '"Key"|"Value"'
probe "Consul services"      "/v1/catalog/services"       '^\{'

# ── etcd ───────────────────────────────────────────────────────
probe "etcd v2 keys"         "/v2/keys?recursive=true"    '"action"|"node"'
probe "etcd v2 members"      "/v2/members"                '"members"'
probe "etcd v2 stats"        "/v2/stats/self"             '"name"|"leaderInfo"'
probe "etcd v3 version"      "/version"                   'etcdserver'

# ── Kubernetes API ─────────────────────────────────────────────
probe "K8s /api/v1"          "/api/v1"                    '"resources"|"kind":"APIResourceList"'
probe "K8s /apis"            "/apis"                      '"groups"'
probe "K8s namespaces"       "/api/v1/namespaces"         '"kind":"NamespaceList"'
probe "K8s pods"             "/api/v1/pods"               '"kind":"PodList"'
probe "K8s /healthz"         "/healthz"                   '^ok$'

# ── Docker Registry v2 ─────────────────────────────────────────
probe "Docker registry v2"   "/v2/"                       '^\{\}'
probe "Docker catalog"       "/v2/_catalog"               '"repositories"'

# ── Gitea ──────────────────────────────────────────────────────
probe "Gitea users"          "/api/v1/users/search"       '"data"|"login"'
probe "Gitea repos"          "/api/v1/repos/search"       '"data"|"full_name"'

# ── GitLab ─────────────────────────────────────────────────────
probe "GitLab projects"      "/api/v4/projects"           '\[.*"id"'
probe "GitLab users"         "/api/v4/users"              '\[.*"id"|\[.*"username"'

# ── SonarQube ──────────────────────────────────────────────────
probe "SonarQube version"    "/api/server/version"        '^[0-9]+\.[0-9]+'
probe "SonarQube projects"   "/api/projects/search"       '"components"'

# ── Nexus / Artifactory ────────────────────────────────────────
probe "Nexus repositories"   "/service/rest/v1/repositories"  '\[|"name"'
probe "Artifactory ping"     "/artifactory/api/system/ping"   '^OK'
probe "Artifactory repos"    "/artifactory/api/repositories"  '"key"|"type"'

# ── Rancher / Portainer ────────────────────────────────────────
probe "Rancher version"      "/v3/settings/server-version"    '"value"'
probe "Portainer status"     "/api/system/status"             '"Version"'

# ── Vault (unauth sys status) ──────────────────────────────────
probe "Vault sys health"     "/v1/sys/health"             '"initialized"|"sealed"'
probe "Vault sys seal"       "/v1/sys/seal-status"        '"sealed"|"n"'

# ── Traefik ────────────────────────────────────────────────────
probe "Traefik routers"      "/api/http/routers"          '\[|"status"'
probe "Traefik services"     "/api/http/services"         '\[|"serverStatus"'

# ── Rundeck ────────────────────────────────────────────────────
probe "Rundeck system info"  "/api/41/system/info"        '"system"|"rundeck"'

log "=== done → $OUT ==="
