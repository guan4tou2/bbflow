#!/usr/bin/env bash
# hunt-email-security.sh — Email Security Audit（OSINT Arsenal §16.14）
#
# 稽核 SPF / DMARC / DKIM / MTA-STS / BIMI 設定，推斷 IdP / MX provider，
# 評估 email spoof feasibility 並偵測 SaaS tenant token。
#
# Severity mapping：
#   HIGH   — 無 SPF（任意主機可偽裝），或 DMARC p=none + 無 SPF
#   MEDIUM — DMARC p=none（監控模式，不阻擋），或 SPF +all（允許所有）
#   LOW    — SPF ~all（軟失敗），DKIM selector 缺失，MTA-STS missing
#   INFO   — 完整保護（-all + quarantine/reject + MTA-STS）
#
# 用法（domain 模式，bbflow 從 ROOT_DOMAIN 呼叫）：
#   ./hunt-email-security.sh example.com

set -uo pipefail

INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <domain>"; exit 1; }
DOMAIN=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')

OUT_DIR="${OUT_DIR:-./email_security_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit(){ echo "🔴 $*" | tee -a "$OUT"; }
warn(){ echo "🟠 $*" | tee -a "$OUT"; }
info_hit(){ echo "🟡 $*" | tee -a "$OUT"; }
ok(){ echo "🟢 $*" | tee -a "$OUT"; }

log "=== Email Security Audit: $DOMAIN ==="

SPOOF_RISK="NONE"  # 最終 spoof feasibility: NONE/LOW/MEDIUM/HIGH

# ── 1. MX Record → IdP 識別 ──────────────────────────────────────────────────
MX_RAW=$(dig +short MX "$DOMAIN" 2>/dev/null | sort -n | head -5)
MX_HOST=$(echo "$MX_RAW" | head -1 | awk '{print $2}' | sed 's/\.$//')

IDP=""
MX_PROVIDER=""
if echo "$MX_RAW" | grep -qi "google\|aspmx\|googlemail"; then
  MX_PROVIDER="Google Workspace"
  IDP="Google Workspace"
elif echo "$MX_RAW" | grep -qi "outlook\|protection\.outlook\|mail\.protection"; then
  MX_PROVIDER="Microsoft 365"
  IDP="Microsoft 365 / Entra ID"
elif echo "$MX_RAW" | grep -qi "zoho"; then
  MX_PROVIDER="Zoho Mail"
  IDP="Zoho"
elif echo "$MX_RAW" | grep -qi "mimecast"; then
  MX_PROVIDER="Mimecast"
elif echo "$MX_RAW" | grep -qi "proofpoint\|pphosted"; then
  MX_PROVIDER="Proofpoint"
elif echo "$MX_RAW" | grep -qi "barracuda"; then
  MX_PROVIDER="Barracuda"
elif [ -n "$MX_HOST" ]; then
  MX_PROVIDER="$MX_HOST"
fi

if [ -n "$MX_RAW" ]; then
  log "MX records:"
  echo "$MX_RAW" | while read -r line; do log "  $line"; done
  [ -n "$MX_PROVIDER" ] && info_hit "MX Provider: $MX_PROVIDER"
  [ -n "$IDP" ] && info_hit "IdP inferred: $IDP"
else
  log "  No MX records found"
fi

# ── 2. SPF ─────────────────────────────────────────────────────────────────────
SPF_RAW=$(dig +short TXT "$DOMAIN" 2>/dev/null | grep -i 'v=spf1' | head -1 | tr -d '"')

if [ -z "$SPF_RAW" ]; then
  hit "NO SPF RECORD — any host can spoof @${DOMAIN}"
  SPOOF_RISK="HIGH"
else
  log "SPF: $SPF_RAW"
  if echo "$SPF_RAW" | grep -q '+all'; then
    hit "SPF +all — permits ALL senders (equivalent to no SPF)"
    SPOOF_RISK="HIGH"
  elif echo "$SPF_RAW" | grep -q '\?all'; then
    warn "SPF ?all — neutral; no enforcement"
    [ "$SPOOF_RISK" = "NONE" ] && SPOOF_RISK="MEDIUM"
  elif echo "$SPF_RAW" | grep -q '~all'; then
    warn "SPF ~all (softfail) — spoofed mail may still be delivered"
    [ "$SPOOF_RISK" = "NONE" ] && SPOOF_RISK="LOW"
  elif echo "$SPF_RAW" | grep -q '\-all'; then
    ok "SPF -all (hardfail) — good"
  else
    info_hit "SPF record found but no explicit all mechanism"
    [ "$SPOOF_RISK" = "NONE" ] && SPOOF_RISK="LOW"
  fi

  # Count include: mechanisms for complexity audit
  INCLUDE_COUNT=$(echo "$SPF_RAW" | grep -o 'include:' | wc -l | tr -d ' ')
  [ "$INCLUDE_COUNT" -gt 10 ] && warn "SPF has $INCLUDE_COUNT includes — may hit 10-lookup DNS limit (permerror)"
fi

# ── 3. DMARC ──────────────────────────────────────────────────────────────────
DMARC_RAW=$(dig +short TXT "_dmarc.${DOMAIN}" 2>/dev/null | grep -i 'v=DMARC1' | head -1 | tr -d '"')

if [ -z "$DMARC_RAW" ]; then
  hit "NO DMARC RECORD — spoofed mail will not be reported or quarantined"
  [ "$SPOOF_RISK" != "HIGH" ] && SPOOF_RISK="MEDIUM"
else
  log "DMARC: $DMARC_RAW"
  DMARC_P=$(echo "$DMARC_RAW" | grep -oE 'p=(none|quarantine|reject)' | cut -d= -f2)
  DMARC_SP=$(echo "$DMARC_RAW" | grep -oE 'sp=(none|quarantine|reject)' | cut -d= -f2)
  DMARC_PCT=$(echo "$DMARC_RAW" | grep -oE 'pct=[0-9]+' | cut -d= -f2)
  DMARC_RUA=$(echo "$DMARC_RAW" | grep -oE 'rua=[^;]+' | cut -d= -f2)

  case "$DMARC_P" in
    none)
      warn "DMARC p=none — monitoring only; spoofed mail is NOT blocked"
      [ "$SPOOF_RISK" = "NONE" ] && SPOOF_RISK="MEDIUM"
      ;;
    quarantine)
      info_hit "DMARC p=quarantine — spoofed mail goes to spam (partial protection)"
      [ "$SPOOF_RISK" = "NONE" ] && SPOOF_RISK="LOW"
      ;;
    reject)
      ok "DMARC p=reject — spoofed mail is rejected"
      ;;
    *)
      warn "DMARC p value not recognized: '$DMARC_P'"
      ;;
  esac

  [ -n "$DMARC_SP" ] && [ "$DMARC_SP" = "none" ] && \
    warn "DMARC sp=none — subdomains have no enforcement"

  if [ -n "$DMARC_PCT" ] && [ "$DMARC_PCT" -lt 100 ] 2>/dev/null; then
    warn "DMARC pct=${DMARC_PCT}% — policy applies to only ${DMARC_PCT}% of mail"
  fi

  [ -z "$DMARC_RUA" ] && info_hit "No DMARC rua (no aggregate reports) — blind spot"
fi

# ── 4. DKIM selector sweep ────────────────────────────────────────────────────
DKIM_SELECTORS=(
  default google selector1 selector2 mail k1 k2
  amazonses mandrill mailchimp sendgrid postmark
  s1 s2 dkim email proddkim
  20161025 20230601 20210112
)

log "DKIM selector sweep (${#DKIM_SELECTORS[@]} selectors)..."
DKIM_FOUND=0
for sel in "${DKIM_SELECTORS[@]}"; do
  DKIM_KEY=$(dig +short TXT "${sel}._domainkey.${DOMAIN}" 2>/dev/null | grep -i 'p=' | head -1)
  if [ -n "$DKIM_KEY" ]; then
    DKIM_FOUND=$((DKIM_FOUND + 1))
    info_hit "DKIM selector found: ${sel}._domainkey.${DOMAIN}"
    # Check for weak key (short p= value)
    KEY_VAL=$(echo "$DKIM_KEY" | grep -oP '(?<=p=)[A-Za-z0-9+/]+' | head -1)
    KEY_LEN=${#KEY_VAL}
    [ "$KEY_LEN" -lt 100 ] && [ "$KEY_LEN" -gt 0 ] && \
      warn "  DKIM key may be short ($KEY_LEN chars encoded) — possible 512-bit weak key"
    sleep 0.2
  fi
done
[ "$DKIM_FOUND" -eq 0 ] && warn "No DKIM selectors found in common list — spoofed mail passes DKIM"

# ── 5. MTA-STS ─────────────────────────────────────────────────────────────────
MTA_STS_TXT=$(dig +short TXT "_mta-sts.${DOMAIN}" 2>/dev/null | head -1 | tr -d '"')
if [ -z "$MTA_STS_TXT" ]; then
  info_hit "No MTA-STS TXT record — downgrade attacks possible (STARTTLS stripping)"
else
  log "MTA-STS TXT: $MTA_STS_TXT"
  MTA_STS_POLICY=$(curl -sk -m 10 "https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt" 2>/dev/null)
  if [ -z "$MTA_STS_POLICY" ]; then
    warn "MTA-STS TXT found but policy file unreachable at https://mta-sts.${DOMAIN}/.well-known/mta-sts.txt"
  else
    MTA_MODE=$(echo "$MTA_STS_POLICY" | grep -i '^mode:' | cut -d: -f2 | tr -d ' \r')
    log "  MTA-STS mode: ${MTA_MODE:-unknown}"
    [ "$MTA_MODE" = "testing" ] && info_hit "MTA-STS mode=testing — not enforced"
    [ "$MTA_MODE" = "enforce" ] && ok "MTA-STS mode=enforce — STARTTLS required"
  fi
fi

# ── 6. BIMI ────────────────────────────────────────────────────────────────────
BIMI=$(dig +short TXT "default._bimi.${DOMAIN}" 2>/dev/null | head -1 | tr -d '"')
if [ -n "$BIMI" ]; then
  ok "BIMI found — brand indicator (DMARC reject implied): $BIMI"
fi

# ── 7. TXT 租戶 token 掃描 ────────────────────────────────────────────────────
TXT_ALL=$(dig +short TXT "$DOMAIN" 2>/dev/null)
log "Scanning TXT tokens for SaaS tenants..."

echo "$TXT_ALL" | grep -qi "MS=" && \
  info_hit "Microsoft tenant verification token found (MS=...)"
echo "$TXT_ALL" | grep -qi "atlassian-domain-verification" && \
  info_hit "Atlassian (Jira/Confluence Cloud) tenant token found"
echo "$TXT_ALL" | grep -qi "slack-domain-verification\|slack_uid" && \
  info_hit "Slack workspace tenant token found"
echo "$TXT_ALL" | grep -qi "workday" && \
  info_hit "Workday tenant token found"
echo "$TXT_ALL" | grep -qi "adobe-idp-site-verification\|adobe-sign" && \
  info_hit "Adobe Identity tenant token found"
echo "$TXT_ALL" | grep -qi "docusign" && \
  info_hit "DocuSign tenant token found"
echo "$TXT_ALL" | grep -qi "salesforce\|_salesforce" && \
  info_hit "Salesforce tenant token found"
echo "$TXT_ALL" | grep -qi "zoom-domain-verification\|zoommtg" && \
  info_hit "Zoom tenant token found"
echo "$TXT_ALL" | grep -qi "facebook-domain-verification" && \
  info_hit "Facebook domain verification token found"
echo "$TXT_ALL" | grep -qi "apple-domain-verification" && \
  info_hit "Apple domain verification token found"
echo "$TXT_ALL" | grep -qi "google-site-verification" && \
  info_hit "Google site verification token found"

# ── 8. autodiscover / autoconfig（IdP 旁路偵測）───────────────────────────────
AUTODISC_A=$(dig +short A "autodiscover.${DOMAIN}" 2>/dev/null | head -1)
AUTOCONF_A=$(dig +short A "autoconfig.${DOMAIN}" 2>/dev/null | head -1)

[ -n "$AUTODISC_A" ] && info_hit "autodiscover.${DOMAIN} → $AUTODISC_A (Outlook/Exchange autodiscovery)"
[ -n "$AUTOCONF_A" ] && info_hit "autoconfig.${DOMAIN} → $AUTOCONF_A (Thunderbird autoconfig)"

# Legacy mail hostnames (§15.2 SSO_EXPOSURE legacy pattern)
for legacy in mail webmail owa; do
  IP=$(dig +short A "${legacy}.${DOMAIN}" 2>/dev/null | head -1)
  if [ -n "$IP" ]; then
    info_hit "${legacy}.${DOMAIN} → $IP (legacy mail host)"
  else
    # NXDOMAIN but MX→cloud = migration pattern (§15.2)
    if [ -n "$IDP" ]; then
      info_hit "${legacy}.${DOMAIN} → NXDOMAIN + MX→${IDP} — potential legacy SSO migration pattern"
    fi
  fi
done

# ── 9. 彙整 spoof feasibility ──────────────────────────────────────────────────
echo "" >> "$OUT"
log "=== Spoof Feasibility Summary for $DOMAIN ==="

case "$SPOOF_RISK" in
  HIGH)
    hit "SPOOF FEASIBILITY: HIGH — @${DOMAIN} addresses can likely be spoofed"
    hit "  → Missing or misconfigured SPF/DMARC; no effective enforcement"
    [ -n "$IDP" ] && hit "  → IdP: $IDP — phishing email could trick SSO users"
    ;;
  MEDIUM)
    warn "SPOOF FEASIBILITY: MEDIUM — DMARC p=none; mail may be delivered to inbox"
    [ -n "$IDP" ] && warn "  → IdP: $IDP — spear-phishing risk"
    ;;
  LOW)
    info_hit "SPOOF FEASIBILITY: LOW — SPF ~all; spoofed mail likely flagged as spam"
    ;;
  NONE)
    ok "SPOOF FEASIBILITY: NONE — SPF -all + DMARC enforce; spoofing blocked"
    ;;
esac
