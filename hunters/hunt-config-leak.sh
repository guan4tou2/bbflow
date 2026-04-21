#!/usr/bin/env bash
# hunt-config-leak.sh — xray-inspired 配置洩漏掃描器
# 來源：chaitin/xray dirscan + phantasm 規則 + Nuclei exposures/configs + 實戰經驗
#
# 為什麼這個 hunter 值得有：
#   1. 每個路徑只送 1 次 GET（WAF 極低觸發率）
#   2. 100+ 路徑全部用 content-match 驗證（不是 HTTP 200 就算 hit）
#   3. 涵蓋 xray 最穩的 PoC-none 規則（SCM、IDE、.env、backup、WEB-INF、Swagger、debug console）
#   4. 適合政府站、防火牆後的標的 — 不爆破，只精準確認已知敏感檔案
#
# 用法：
#   ./hunt-config-leak.sh https://target
#   FAST=1 ./hunt-config-leak.sh https://target   # 只跑 P1/P2 高信心路徑（24 個）
set -uo pipefail

HOST="${1:-}"
[ -z "$HOST" ] && { echo "Usage: $0 <https://host>"; exit 1; }
HOST="${HOST%/}"
OUT_DIR="${OUT_DIR:-./config_leak_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$HOST" | sed 's|https\?://||;s|[/:]|_|g')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟡 $*" | tee -a "$OUT"; }
FAST="${FAST:-0}"

# 送單次 GET，body 緩存到 /tmp，判斷 (HTTP code ∈ 2xx) AND (body 符合 content regex)
probe() {
  local label="$1" path="$2" content_re="$3" severity="${4:-high}"
  local URL="${HOST}${path}"
  local CODE BODY
  CODE=$(curl -sk --max-time 6 -o "/tmp/.cl_$$" -w "%{http_code}" \
    -H "User-Agent: Mozilla/5.0 (compatible; bbflow/config-leak)" "$URL" 2>/dev/null)
  BODY=$(head -c 2000 "/tmp/.cl_$$" 2>/dev/null)
  rm -f "/tmp/.cl_$$"
  # 200 / 206 才算，並且 body 必須符合正則
  if [[ "$CODE" =~ ^2 ]] && echo "$BODY" | grep -qiE "$content_re" 2>/dev/null; then
    case "$severity" in
      critical) hit "[P1-CRIT] $label: $URL [$CODE]" ;;
      high)     hit "[P2-HIGH] $label: $URL [$CODE]" ;;
      medium)   warn "[P3-MED]  $label: $URL [$CODE]" ;;
      *)        warn "[P4-INFO] $label: $URL [$CODE]" ;;
    esac
    # 貼第一行 body 當證據
    local EVI
    EVI=$(echo "$BODY" | tr -d '\r' | head -c 200 | tr '\n' ' ')
    echo "     evidence: $EVI" >> "$OUT"
    return 0
  fi
  return 1
}

log "=== Config leak hunt: $HOST (FAST=$FAST) ==="

# ═══════════════════════════════════════════════════════════════
# P1 / P2：高信心 — 一定要跑（即使 FAST=1）
# ═══════════════════════════════════════════════════════════════

# ── SCM 洩漏（.git/.svn/.hg/.bzr）─ xray/phantasm
probe ".git/config"           "/.git/config"         'repositoryformatversion|\[core\]|\[remote ' critical
probe ".git/HEAD"             "/.git/HEAD"           'ref: refs/heads/'                          critical
probe ".git/index"            "/.git/index"          'DIRC|\x00\x00\x00[\x02-\x09]'              critical
probe ".git/logs/HEAD"        "/.git/logs/HEAD"      '^[0-9a-f]{40} [0-9a-f]{40}'                critical
probe ".svn/entries"          "/.svn/entries"        '^[0-9]+$|dir|file'                         critical
probe ".svn/wc.db"            "/.svn/wc.db"          'SQLite format'                             critical
probe ".hg/hgrc"              "/.hg/hgrc"            '\[paths\]|default ='                       critical
probe ".bzr/branch-format"    "/.bzr/branch-format"  'Bazaar'                                    high

# ── IDE / 編輯器殘留 ───────────────────────────────────────────
probe ".idea/workspace.xml"   "/.idea/workspace.xml" '<project|<component'                       critical
probe ".idea/modules.xml"     "/.idea/modules.xml"   '<modules|<module fileurl'                  high
probe ".vscode/settings.json" "/.vscode/settings.json" '\{|"editor'                              high
probe ".vscode/launch.json"   "/.vscode/launch.json" '\{|"configurations'                        high
probe ".DS_Store"             "/.DS_Store"           'Bud1|\x00\x00\x00\x01Bud1'                 high

# ── .env / 敏感設定檔 ──────────────────────────────────────────
probe ".env"                  "/.env"                'DB_PASSWORD|APP_KEY|SECRET_KEY|AWS_|_TOKEN|MAIL_PASSWORD' critical
probe ".env.local"            "/.env.local"          'DB_PASSWORD|APP_KEY|SECRET|_TOKEN'         critical
probe ".env.production"       "/.env.production"     'DB_PASSWORD|APP_KEY|SECRET|_TOKEN'         critical
probe ".env.backup"           "/.env.backup"         'DB_PASSWORD|APP_KEY|SECRET'                critical
probe "env.js"                "/env.js"              'window\.|apiKey|BASE_URL|ENV\s*='          high
probe "config.js"             "/config.js"           'apiKey|clientId|SECRET|window\.config'     high
probe "config.json"           "/config.json"         '"apiKey|"secret|"password|"dbHost'         high
probe "appsettings.json"      "/appsettings.json"    'ConnectionStrings|AppSettings|Jwt|Secret'  critical
probe "appsettings.Development" "/appsettings.Development.json" 'ConnectionStrings|Logging'     high

# ── WEB-INF 暴露（J2EE webapp）────────────────────────────────
probe "WEB-INF/web.xml"       "/WEB-INF/web.xml"     '<web-app|<servlet|<filter'                 critical
probe "WEB-INF/classes"       "/WEB-INF/classes/"    'classes|Index of'                          high
probe "WEB-INF/lib"           "/WEB-INF/lib/"        '\.jar|Index of'                            medium

# ── phpinfo / debug endpoints ─────────────────────────────────
probe "phpinfo.php"           "/phpinfo.php"         'phpinfo\(\)|PHP Version|System|Configuration File' critical
probe "info.php"              "/info.php"            'phpinfo\(\)|PHP Version'                   critical
probe "test.php"              "/test.php"            'phpinfo\(\)|PHP Version'                   high
probe "debug.php"             "/debug.php"           'phpinfo|var_dump|print_r'                  high
probe "phpmyadmin/"           "/phpmyadmin/"         'phpMyAdmin|pma_|setup\.php'                high
probe "pma/"                  "/pma/"                'phpMyAdmin|pma_'                           high

# ── Spring Boot Actuator（xray/phantasm actuator 規則）─────────
probe "/actuator"             "/actuator"            '"_links"|"self"|"href"|beans|env|mappings' critical
probe "/actuator/env"         "/actuator/env"        '"activeProfiles"|"propertySources"'        critical
probe "/actuator/heapdump"    "/actuator/heapdump"   'JAVA PROFILE|HPROF'                        critical
probe "/actuator/mappings"    "/actuator/mappings"   '"dispatcherServlet"|"handler"'             high
probe "/env"                  "/env"                 '"activeProfiles"|"propertySources"'        critical
probe "/heapdump"             "/heapdump"            'JAVA PROFILE|HPROF'                        critical

# ── Swagger / API docs（可能洩漏內部 endpoint）────────────────
probe "swagger-ui.html"       "/swagger-ui.html"     'Swagger UI|swagger-ui|<title>Swagger'      high
probe "swagger/index.html"    "/swagger/index.html"  'Swagger UI|swagger-ui|<title>Swagger'      high
probe "swagger.json"          "/swagger.json"        '"swagger"|"openapi"|"paths"'               high
probe "openapi.json"          "/openapi.json"        '"openapi"|"paths"'                         high
probe "/v2/api-docs"          "/v2/api-docs"         '"swagger"|"openapi"|"paths"'               high
probe "/v3/api-docs"          "/v3/api-docs"         '"openapi"|"paths"'                         high
probe "api-docs"              "/api-docs"            '"swagger"|"openapi"|"paths"'               high

# ── Java / Spring 其他 leak 類型 ──────────────────────────────
probe "druid/index.html"      "/druid/index.html"    'Druid Monitor|DruidMonitor'                critical
probe "druid/login.html"      "/druid/login.html"    'Druid Monitor|DruidMonitor'                high
probe "nacos/"                "/nacos/"              'Nacos|nacos-server'                        high
probe "nacos/v1/console"      "/nacos/v1/console/server/state" '"version"|"mode"|"startup_mode"' high

# ═══════════════════════════════════════════════════════════════
# P3 / P4：中低信心 — FAST=1 時跳過
# ═══════════════════════════════════════════════════════════════
if [ "$FAST" != "1" ]; then

# ── crossdomain / robots / sitemap ────────────────────────────
probe "crossdomain.xml"       "/crossdomain.xml"     '<cross-domain-policy|<allow-access-from'   medium
probe "clientaccesspolicy"    "/clientaccesspolicy.xml" '<access-policy|<cross-domain-access'    medium
probe "sitemap.xml"           "/sitemap.xml"         '<urlset|<sitemapindex'                     info

# ── backup / dump 常見檔名 ────────────────────────────────────
probe "backup.zip"            "/backup.zip"          'PK\x03\x04|Rar!|7z|^<'                     critical
probe "backup.tar.gz"         "/backup.tar.gz"       '\x1f\x8b'                                  critical
probe "backup.sql"            "/backup.sql"          'CREATE TABLE|INSERT INTO|DROP TABLE'       critical
probe "db.sql"                "/db.sql"              'CREATE TABLE|INSERT INTO|mysqldump'        critical
probe "dump.sql"              "/dump.sql"            'CREATE TABLE|INSERT INTO|mysqldump'        critical
probe "www.zip"               "/www.zip"             'PK\x03\x04'                                critical
probe "site.zip"              "/site.zip"            'PK\x03\x04'                                critical
probe "web.zip"               "/web.zip"             'PK\x03\x04'                                critical
probe "wwwroot.zip"           "/wwwroot.zip"         'PK\x03\x04'                                critical

# ── 依賴管理檔 ────────────────────────────────────────────────
probe "composer.json"         "/composer.json"       '"require"|"autoload"|"name"'               medium
probe "composer.lock"         "/composer.lock"       '"packages"|"_readme"'                      medium
probe "package.json"          "/package.json"        '"dependencies"|"name"'                     medium
probe "package-lock.json"     "/package-lock.json"   '"lockfileVersion"|"packages"'              medium
probe "yarn.lock"             "/yarn.lock"           '# yarn lockfile'                           medium
probe "Gemfile"               "/Gemfile"             'source |gem '                              medium
probe "Gemfile.lock"          "/Gemfile.lock"        'GEM|PLATFORMS|DEPENDENCIES'                medium
probe "requirements.txt"      "/requirements.txt"    '^[a-zA-Z].*==|^[a-zA-Z].*>='               medium
probe "Pipfile"               "/Pipfile"             '\[\[source\]\]|\[packages\]'               medium
probe "Pipfile.lock"          "/Pipfile.lock"        '"_meta"|"sources"'                         medium
probe "pom.xml"               "/pom.xml"             '<project|<dependencies|<groupId'           medium
probe "build.gradle"          "/build.gradle"        'apply plugin|dependencies \{|repositories' medium
probe "go.mod"                "/go.mod"              'module |require |go '                      medium
probe "go.sum"                "/go.sum"              'h1:[A-Za-z0-9+/=]+'                        medium

# ── 部署 / CI 檔 ──────────────────────────────────────────────
probe ".gitlab-ci.yml"        "/.gitlab-ci.yml"      'stages:|script:|image:'                    high
probe ".travis.yml"           "/.travis.yml"         'language:|script:|install:'                high
probe ".circleci/config.yml"  "/.circleci/config.yml" 'version:|jobs:|steps:'                    high
probe "Dockerfile"            "/Dockerfile"          '^FROM |^RUN |^COPY |^WORKDIR'              medium
probe "docker-compose.yml"    "/docker-compose.yml"  'version:|services:|image:'                 medium
probe "docker-compose.yaml"   "/docker-compose.yaml" 'version:|services:|image:'                 medium
probe "Jenkinsfile"           "/Jenkinsfile"         'pipeline|stage|steps'                      medium
probe "buildspec.yml"         "/buildspec.yml"       'version:|phases:|commands:'                medium

# ── Apache / Nginx 設定洩漏 ───────────────────────────────────
probe ".htaccess"             "/.htaccess"           'RewriteEngine|AuthType|Options |AddType'   high
probe ".htpasswd"             "/.htpasswd"           '^[a-zA-Z0-9]+:\$'                          critical
probe "web.config"            "/web.config"          '<configuration|<system\.web'               high
probe "nginx.conf"            "/nginx.conf"          'server \{|location|upstream'               high

# ── CMS 特定 ─────────────────────────────────────────────────
probe "wp-config.php.bak"     "/wp-config.php.bak"   'DB_PASSWORD|DB_USER|wp-config'             critical
probe "wp-config.php~"        "/wp-config.php~"      'DB_PASSWORD|DB_USER|wp-config'             critical
probe "wp-config.old"         "/wp-config.old"       'DB_PASSWORD|DB_USER|wp-config'             critical
probe "config.php.bak"        "/config.php.bak"      '<\?php|DB_|password'                       critical
probe ".user.ini"             "/.user.ini"           'auto_prepend_file|auto_append_file'        medium

# ── 其他高價值路徑 ────────────────────────────────────────────
probe "security.txt"          "/security.txt"        'Contact|Expires'                           info
probe ".well-known/security"  "/.well-known/security.txt" 'Contact|Expires'                      info
probe "server-status"         "/server-status"       'Apache Server Status|Scoreboard'           high
probe "server-info"           "/server-info"         'Apache Server Information'                 high
probe "status"                "/status"              'pm.status_path|active processes'           medium
probe "CHANGELOG.md"          "/CHANGELOG.md"        '^#|## \['                                  info
probe "README.md"             "/README.md"           '^#|## '                                    info
probe "TODO"                  "/TODO"                '^-|TODO'                                   info
probe ".gitignore"            "/.gitignore"          '^[a-zA-Z./*]'                              info

fi  # end of !FAST

log "=== done — see $OUT ==="
