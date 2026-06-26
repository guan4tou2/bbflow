#!/usr/bin/env bash
# hunt-dns-deep.sh — Deep DNS recon: zone transfer, wildcard, record enum via dnsx
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../configs/tool-profiles.sh" 2>/dev/null || true

# ─── Input ───────────────────────────────────────────────────────────────────
INPUT="${1:-}"
[ -z "$INPUT" ] && { echo "Usage: $0 <domain|URL>"; exit 1; }
DOMAIN=$(echo "$INPUT" | sed -E 's|^https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/^www\.//')

OUT_DIR="${OUT_DIR:-./dns_deep_out}"
mkdir -p "$OUT_DIR"
SLUG=$(echo "$DOMAIN" | tr '.' '_')
OUT="$OUT_DIR/${SLUG}.txt"
: > "$OUT"

log()     { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT"; }
hit()     { echo "🔴 $*" | tee -a "$OUT"; }
warn()    { echo "🟡 $*" | tee -a "$OUT"; }
ok()      { echo "🟢 $*" | tee -a "$OUT"; }
section() { echo "" | tee -a "$OUT"; echo "──── $* ────" | tee -a "$OUT"; }

log "=== Deep DNS Recon: $DOMAIN ==="
log "Output: $OUT"

# ─── Tool checks ─────────────────────────────────────────────────────────────
HAS_DNSX=0; HAS_DIG=0; HAS_WHOIS=0
command -v dnsx  &>/dev/null && HAS_DNSX=1
command -v dig   &>/dev/null && HAS_DIG=1
command -v whois &>/dev/null && HAS_WHOIS=1
[ $HAS_DIG -eq 0 ]   && log "[WARN] dig not found — zone transfer checks skipped"
[ $HAS_DNSX -eq 0 ]  && log "[WARN] dnsx not found — record enum via dig fallback"

# ─── 1. NS Enumeration ───────────────────────────────────────────────────────
section "1. NS Servers"
NS_LIST=""
if [ $HAS_DIG -eq 1 ]; then
  NS_LIST=$(dig +short NS "$DOMAIN" 2>/dev/null | sed 's/\.$//' | sort -u)
  if [ -n "$NS_LIST" ]; then
    log "NS servers for $DOMAIN:"
    echo "$NS_LIST" | while read -r ns; do
      log "  $ns"
      # Resolve NS to IP for scope check
      NS_IP=$(dig +short A "$ns" 2>/dev/null | head -1)
      [ -n "$NS_IP" ] && log "    → $NS_IP"
    done
  else
    log "  No NS records found"
  fi
else
  NS_LIST=$(nslookup -type=NS "$DOMAIN" 2>/dev/null | grep 'nameserver' | awk '{print $NF}' | sed 's/\.$//')
fi

# ─── 2. Zone Transfer (AXFR) ─────────────────────────────────────────────────
section "2. Zone Transfer Attempt (AXFR)"
AXFR_SUCCESS=0
if [ $HAS_DIG -eq 1 ] && [ -n "$NS_LIST" ]; then
  echo "$NS_LIST" | while read -r ns; do
    [ -z "$ns" ] && continue
    log "  Attempting AXFR from $ns..."
    AXFR_OUT=$(dig axfr "$DOMAIN" "@$ns" 2>/dev/null)
    # A successful AXFR returns multiple records; a failure returns just SOA or error
    AXFR_LINES=$(echo "$AXFR_OUT" | grep -v '^;' | grep -v '^$' | wc -l | tr -d ' ')
    if [ "$AXFR_LINES" -gt 5 ]; then
      hit "ZONE TRANSFER SUCCESS via $ns — $AXFR_LINES records leaked!"
      echo "$AXFR_OUT" >> "$OUT"
      AXFR_SUCCESS=1
    else
      AXFR_ERR=$(echo "$AXFR_OUT" | grep -i 'Transfer failed\|REFUSED\|SERVFAIL\|not authoritative' | head -1)
      if [ -n "$AXFR_ERR" ]; then
        ok "  AXFR refused by $ns (expected)"
      else
        log "  AXFR returned $AXFR_LINES records from $ns (no full transfer)"
      fi
    fi
  done
else
  log "  Skipped (no NS list or dig unavailable)"
fi

# ─── 3. Wildcard Detection ───────────────────────────────────────────────────
section "3. Wildcard Detection"
RANDOM_SUB="bbflow-nxtest-$(head -c6 /dev/urandom | xxd -p | head -c8).${DOMAIN}"
if [ $HAS_DIG -eq 1 ]; then
  WILDCARD_IP=$(dig +short A "$RANDOM_SUB" 2>/dev/null | head -1)
  if [ -n "$WILDCARD_IP" ]; then
    hit "WILDCARD DNS detected: *.${DOMAIN} → $WILDCARD_IP"
    warn "Wildcard subdomain abuse potential — any subdomain resolves to $WILDCARD_IP"
    warn "Subdomain takeover candidates may be masked by wildcard"
  else
    ok "No wildcard: $RANDOM_SUB → NXDOMAIN (expected)"
  fi
elif [ $HAS_DNSX -eq 1 ]; then
  WILDCARD_OUT=$(echo "$RANDOM_SUB" | dnsx -silent -a -resp 2>/dev/null)
  if [ -n "$WILDCARD_OUT" ]; then
    hit "WILDCARD DNS detected via dnsx: $WILDCARD_OUT"
  else
    ok "No wildcard detected"
  fi
else
  log "  Skipped (no dig or dnsx)"
fi

# ─── 4. DNS Record Enumeration via dnsx ──────────────────────────────────────
section "4. DNS Record Enumeration"
if [ $HAS_DNSX -eq 1 ]; then
  log "Running dnsx record enum on $DOMAIN..."
  DNSX_OUT=$(echo "$DOMAIN" | dnsx -silent \
    -a -aaaa -cname -mx -ns -txt -soa \
    -resp 2>/dev/null)
  if [ -n "$DNSX_OUT" ]; then
    echo "$DNSX_OUT" | tee -a "$OUT"
  else
    log "  dnsx returned no output"
  fi
elif [ $HAS_DIG -eq 1 ]; then
  log "dnsx not available — using dig fallback"
  for RTYPE in A AAAA CNAME MX NS TXT SOA; do
    RES=$(dig +short "$RTYPE" "$DOMAIN" 2>/dev/null)
    if [ -n "$RES" ]; then
      log "  $RTYPE:"
      echo "$RES" | while read -r r; do log "    $r"; done
    fi
  done
else
  log "  Skipped (no dnsx or dig)"
fi

# ─── 5. Interesting TXT Records ──────────────────────────────────────────────
section "5. Interesting TXT Records"
TXT_RAW=$(dig +short TXT "$DOMAIN" 2>/dev/null 2>/dev/null)
DMARC_RAW=$(dig +short TXT "_dmarc.$DOMAIN" 2>/dev/null)

if [ -n "$TXT_RAW" ]; then
  log "TXT records for $DOMAIN:"

  # SPF
  SPF=$(echo "$TXT_RAW" | grep -i 'v=spf1')
  if [ -n "$SPF" ]; then
    log "  SPF: $SPF"
    if echo "$SPF" | grep -q '+all'; then
      hit "SPF +all — allows ALL senders to spoof! Email spoofing trivially possible."
    elif echo "$SPF" | grep -q '~all'; then
      warn "SPF ~all (softfail) — spoofed mail may pass; depends on DMARC policy"
    elif echo "$SPF" | grep -q '-all'; then
      ok "SPF -all (strict reject)"
    fi
  else
    hit "No SPF record — any host can spoof mail as $DOMAIN"
  fi

  # Verification tokens (recon gold)
  echo "$TXT_RAW" | grep -i 'google-site-verification' | while read -r tok; do
    warn "Google site verification token: $tok"
  done
  echo "$TXT_RAW" | grep -i 'facebook-domain-verification' | while read -r tok; do
    warn "Facebook domain verification token: $tok"
  done
  echo "$TXT_RAW" | grep -i 'apple-domain-verification\|apple-developer-verification' | while read -r tok; do
    warn "Apple domain verification token: $tok"
  done
  echo "$TXT_RAW" | grep -i 'MS=' | while read -r tok; do
    warn "Microsoft tenant verification token: $tok"
  done
  echo "$TXT_RAW" | grep -i 'atlassian-domain-verification' | while read -r tok; do
    warn "Atlassian verification token: $tok"
  done
  echo "$TXT_RAW" | grep -i 'stripe\|twilio\|sendgrid\|mailchimp\|hubspot\|docusign\|zoom\|adobe' | while read -r tok; do
    warn "SaaS tenant token: $tok"
  done
fi

# DMARC
log "DMARC (_dmarc.$DOMAIN):"
if [ -n "$DMARC_RAW" ]; then
  log "  $DMARC_RAW"
  if echo "$DMARC_RAW" | grep -q 'p=none'; then
    warn "DMARC p=none — monitoring only, spoofed mail NOT rejected"
  elif echo "$DMARC_RAW" | grep -q 'p=quarantine'; then
    ok "DMARC p=quarantine"
  elif echo "$DMARC_RAW" | grep -q 'p=reject'; then
    ok "DMARC p=reject (strict)"
  fi
else
  hit "No DMARC record — combined with weak SPF enables email spoofing"
fi

# DKIM (try common selectors)
log "DKIM selector probe (common selectors):"
for SEL in default google k1 s1 s2 mail smtp dkim selector1 selector2 20230601 20210112; do
  DKIM_RES=$(dig +short TXT "${SEL}._domainkey.${DOMAIN}" 2>/dev/null | head -1)
  if [ -n "$DKIM_RES" ]; then
    warn "DKIM selector found: ${SEL}._domainkey.${DOMAIN}"
    log "    $DKIM_RES"
  fi
done

# MTA-STS
MTA_STS=$(dig +short TXT "_mta-sts.$DOMAIN" 2>/dev/null)
if [ -n "$MTA_STS" ]; then
  ok "MTA-STS present: $MTA_STS"
else
  warn "No MTA-STS record — SMTP downgrade attacks possible"
fi

# ─── 6. MX Inspection ────────────────────────────────────────────────────────
section "6. MX Record Inspection"
MX_RAW=$(dig +short MX "$DOMAIN" 2>/dev/null | sort -n)
if [ -n "$MX_RAW" ]; then
  log "MX records:"
  echo "$MX_RAW" | while read -r prio host; do
    host_clean=$(echo "$host" | sed 's/\.$//')
    MX_IP=$(dig +short A "$host_clean" 2>/dev/null | head -1)
    log "  Priority $prio → $host_clean (${MX_IP:-unresolved})"
    # Tag known mail providers
    if echo "$host_clean" | grep -qi 'google\|aspmx\|googlemail'; then
      warn "  Mail provider: Google Workspace"
    elif echo "$host_clean" | grep -qi 'outlook\|protection\.outlook\|mail\.protection'; then
      warn "  Mail provider: Microsoft 365"
    elif echo "$host_clean" | grep -qi 'mimecast'; then
      warn "  Mail provider: Mimecast (email security gateway)"
    elif echo "$host_clean" | grep -qi 'proofpoint\|pphosted'; then
      warn "  Mail provider: Proofpoint"
    elif echo "$host_clean" | grep -qi 'mailgun\|sendgrid\|ses\.amazonaws\|amazonses'; then
      warn "  Transactional mail: $(echo "$host_clean" | grep -oiE 'mailgun|sendgrid|amazonses')"
    fi
  done
else
  log "  No MX records found"
fi

# ─── 7. ASN Lookup for Main IP ───────────────────────────────────────────────
section "7. ASN Lookup"
MAIN_IP=$(dig +short A "$DOMAIN" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
if [ -n "$MAIN_IP" ]; then
  log "Main IP: $MAIN_IP"
  if [ $HAS_WHOIS -eq 1 ]; then
    ASN_INFO=$(whois "$MAIN_IP" 2>/dev/null | grep -E '^(OriginAS|ASName|OrgName|netname|org-name|descr|route)' | head -6)
    if [ -n "$ASN_INFO" ]; then
      log "ASN/Org info:"
      echo "$ASN_INFO" | while read -r line; do log "  $line"; done
    else
      log "  whois returned no ASN info"
    fi
    # Cloud provider detection
    if whois "$MAIN_IP" 2>/dev/null | grep -qi 'amazon\|AWS'; then
      warn "Hosted on AWS — check for S3/CloudFront/ELB misconfigs"
    elif whois "$MAIN_IP" 2>/dev/null | grep -qi 'Google\|GOOGLE'; then
      warn "Hosted on GCP"
    elif whois "$MAIN_IP" 2>/dev/null | grep -qi 'Microsoft\|Azure'; then
      warn "Hosted on Azure"
    elif whois "$MAIN_IP" 2>/dev/null | grep -qi 'Cloudflare'; then
      warn "Behind Cloudflare — real IP may differ; check for CF bypass"
    elif whois "$MAIN_IP" 2>/dev/null | grep -qi 'Fastly\|Akamai\|CDN'; then
      warn "Behind CDN — real origin IP may be exposed in DNS history"
    fi
  else
    log "  whois not available — skipping ASN lookup"
    # Fallback: try /etc/hosts or system resolver
    log "  (install whois for ASN info)"
  fi
else
  log "  $DOMAIN does not resolve to an IPv4 address"
fi

# ─── 8. Subdomain Mass Resolution (if subs file exists) ──────────────────────
section "8. Subdomain Mass Resolution"

# Look for subdomain files in sibling output directories
SUBS_FILE=""
for CANDIDATE in \
  "$OUT_DIR/../recon_out/${SLUG}_subs.txt" \
  "$OUT_DIR/../subfinder_out/${SLUG}.txt" \
  "$OUT_DIR/../subs_out/${SLUG}.txt" \
  "$(dirname "$OUT_DIR")/subs.txt" \
  "./subs.txt" \
  "./subdomains.txt" \
  "./${SLUG}_subs.txt"; do
  if [ -f "$CANDIDATE" ]; then
    SUBS_FILE="$CANDIDATE"
    break
  fi
done

if [ -n "$SUBS_FILE" ]; then
  SUB_COUNT=$(wc -l < "$SUBS_FILE" | tr -d ' ')
  log "Found subdomain file: $SUBS_FILE ($SUB_COUNT entries)"

  if [ $HAS_DNSX -eq 1 ]; then
    log "Running dnsx mass resolution..."
    DNSX_MASS_OUT="$OUT_DIR/${SLUG}_mass_resolved.txt"
    cat "$SUBS_FILE" | dnsx -silent -a -resp 2>/dev/null | tee "$DNSX_MASS_OUT" | tee -a "$OUT" > /dev/null
    log "Mass resolution saved: $DNSX_MASS_OUT"

    # Flag internal IPs
    log "Checking for internal IP resolutions..."
    INTERNAL=$(grep -E '\[(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|127\.[0-9]+\.[0-9]+\.[0-9]+)\]' "$DNSX_MASS_OUT" 2>/dev/null || true)
    if [ -n "$INTERNAL" ]; then
      hit "INTERNAL IP RESOLUTION DETECTED:"
      echo "$INTERNAL" | while read -r line; do
        hit "  $line"
      done
    else
      ok "No internal IPs detected in subdomain resolutions"
    fi

    # Count resolved vs total
    RESOLVED=$(wc -l < "$DNSX_MASS_OUT" | tr -d ' ')
    log "Resolved: $RESOLVED / $SUB_COUNT subdomains"

  elif [ $HAS_DIG -eq 1 ]; then
    log "dnsx not available — spot-checking with dig (first 50 subs)..."
    head -50 "$SUBS_FILE" | while read -r sub; do
      IP=$(dig +short A "$sub" 2>/dev/null | head -1)
      [ -z "$IP" ] && continue
      if echo "$IP" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)'; then
        hit "INTERNAL IP: $sub → $IP"
      fi
    done
  else
    log "  No tools available for mass resolution"
  fi
else
  log "No subdomain file found in standard locations"
  log "  Checked: ./subs.txt, ./subdomains.txt, sibling recon_out/, subfinder_out/"
  log "  Pass subdomains file path via OUT_DIR or run subdomain enum first"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
section "Summary"
log "DNS deep recon complete for $DOMAIN"
log "Full output: $OUT"

HITS=$(grep -c '🔴' "$OUT" 2>/dev/null || echo 0)
WARNS=$(grep -c '🟡' "$OUT" 2>/dev/null || echo 0)
log "🔴 Critical findings: $HITS"
log "🟡 Notable items:     $WARNS"

if [ "$HITS" -gt 0 ]; then
  log ""
  log "🔴 Critical findings recap:"
  grep '🔴' "$OUT" | while read -r line; do log "  $line"; done
fi
