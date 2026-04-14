#!/bin/bash
# workspace.sh — 一鍵建立 Bug Bounty 工作區 + 執行 BBOT recon
# 來源：baler3ion structured workflow
# 使用方式：
#   bash tools/workspace.sh <target-name> [domain]
#   bash tools/workspace.sh underarmour underarmour.com
#
# 選項：
#   --no-recon     只建立目錄結構，不跑 BBOT
#   --bbot         使用 BBOT（預設，需要安裝）
#   --osmedeus     使用 Osmedeus 取代 BBOT

TARGET="${1:-new-target}"
DOMAIN="${2:-}"
BASE="$(cd "$(dirname "$0")/.." && pwd)/research/$TARGET"

# 解析旗標
NO_RECON=false
RECON_TOOL="bbot"
for arg in "$@"; do
  case $arg in
    --no-recon)  NO_RECON=true ;;
    --bbot)      RECON_TOOL="bbot" ;;
    --osmedeus)  RECON_TOOL="osmedeus" ;;
  esac
done

# ─────────────────────────────────────────────
# 1. 建立目錄結構
# ─────────────────────────────────────────────
if [ -d "$BASE" ]; then
  echo "⚠️  工作區已存在：$BASE"
  echo "如需重建請先刪除或改名。"
  exit 1
fi

mkdir -p "$BASE"/{info,recon/{subdomains,urls,bbot-out,osmedeus-out},analysis/{javascript,api-endpoints},testing,reports,screenshots}

# ─────────────────────────────────────────────
# 2. 建立初始文件
# ─────────────────────────────────────────────

cat > "$BASE/notes.md" << EOF
# $TARGET — Notes

## $(date +%Y-%m-%d)

### 初步觀察
-

### 有趣的 Endpoint
-

### 線索（待追蹤）
-
EOF

cat > "$BASE/questions.md" << EOF
# $TARGET — Questions to Answer

## 認證與授權
- [ ] App 如何識別用戶？（JWT / session cookie / API key）
- [ ] Role 設計：user / admin / moderator？
- [ ] Token 如何生成？可預測嗎？
- [ ] 忘記密碼 token 有效期？可重用？
- [ ] SSO / OAuth 流程有沒有 state 驗證？

## 資料流
- [ ] 用戶資料存在哪裡？（DB / S3 / Redis）
- [ ] 哪些 endpoint 接受 ID 參數？
- [ ] 有沒有 GraphQL / REST 雙 API？
- [ ] 第三方整合（Stripe / Salesforce / Okta）？

## 歷史
- [ ] 有沒有 disclosed reports？（HackerOne/Bugcrowd hacktivity）
- [ ] Wayback Machine 有舊版 endpoint 嗎？
- [ ] 最近有重大改版嗎？（新功能 = 新漏洞）

## 業務邏輯
- [ ] 付款流程的每個步驟有驗證嗎？
- [ ] 可以跳過步驟嗎？（直接 step 1 → step 5）
- [ ] 優惠碼、折扣有正確驗證嗎？
- [ ] 多租戶架構？（tenant isolation）
EOF

cat > "$BASE/whitepaper.md" << EOF
# $TARGET — Attack Ideas & Payloads

## 未測試的想法（依優先度）

### High Priority
-

### Medium Priority
-

### Moonshots（理論上可行但難度高）
-

## Payload 草稿
\`\`\`
// 在這裡記 payload，不管有沒有測過
\`\`\`
EOF

cat > "$BASE/info/scope.md" << EOF
# $TARGET — Scope

## In-Scope Assets

## Out-of-Scope

## Excluded Vulnerability Types

## Bounty Range
- P1 Critical:
- P2 High:
- P3 Medium:
- P4 Low:

## Program URL

## Safe Harbor
EOF

cat > "$BASE/info/accounts.md" << EOF
# $TARGET — Test Accounts

## Account A（主要）
- Email:
- Password:
- Role:
- customerNo / userId:
- Bearer Token:
- Refresh Token:
- Session Cookie:

## Account B（跨帳號驗證）
- Email:
- Password:
- Role:
- Resource IDs:
  - basket:
  - address:
  - order:

## Privileges Notes
-
EOF

cat > "$BASE/analysis/javascript/notes.md" << EOF
# JS Analysis — $TARGET

## Hidden Endpoints Found
| Endpoint | Source File | Notes |
|---------|------------|-------|
| | | |

## API Keys / Secrets
| Key | Value (partial) | Service | Severity |
|-----|----------------|---------|---------|
| | | | |

## Interesting Business Logic
-
EOF

cat > "$BASE/analysis/api-endpoints/notes.md" << EOF
# API Endpoints — $TARGET

## High Priority（IDOR / Auth bypass candidates）
| Endpoint | Method | Parameters | Notes |
|---------|--------|-----------|-------|
| | | | |

## Tested
| Endpoint | Result | Finding |
|---------|--------|---------|
| | | |
EOF

echo ""
echo "✅ 工作區建立完成：$BASE"
find "$BASE" -type f | sed "s|$BASE/||" | sort

# ─────────────────────────────────────────────
# 3. Recon（如果有提供 domain）
# ─────────────────────────────────────────────
if [ "$NO_RECON" = true ] || [ -z "$DOMAIN" ]; then
  echo ""
  echo "⏭  跳過 recon（未指定 domain 或 --no-recon）"
  echo "   手動執行：bash tools/workspace.sh $TARGET <domain>"
  echo ""
  echo "下一步："
  echo "  1. 填寫 info/scope.md"
  echo "  2. 填寫 info/accounts.md"
  echo "  3. 跑 recon：bash tools/workspace.sh $TARGET <domain>"
  exit 0
fi

echo ""
echo "🔍 開始 recon：$DOMAIN"

# ─── Wayback URL 收集（不依賴 BBOT/Osmedeus）─────
echo ""
echo "📦 Wayback URL 收集..."
if command -v waybackurls &>/dev/null; then
  echo "$DOMAIN" | waybackurls > "$BASE/recon/urls/wayback.txt"
  echo "   waybackurls: $(wc -l < "$BASE/recon/urls/wayback.txt") URLs"
else
  echo "   ⚠️  waybackurls 未安裝（go install github.com/tomnomnom/waybackurls@latest）"
fi

if command -v gau &>/dev/null; then
  gau --subs "$DOMAIN" > "$BASE/recon/urls/gau.txt" 2>/dev/null
  echo "   gau: $(wc -l < "$BASE/recon/urls/gau.txt") URLs"
else
  echo "   ⚠️  gau 未安裝（go install github.com/lc/gau/v2/cmd/gau@latest）"
fi

# 合併去重
cat "$BASE/recon/urls/"*.txt 2>/dev/null | sort -u > "$BASE/recon/urls/all.txt"
echo "   合計: $(wc -l < "$BASE/recon/urls/all.txt") unique URLs"

# gf 過濾（如果安裝了）
if command -v gf &>/dev/null; then
  echo ""
  echo "🎯 gf 漏洞分類過濾..."
  for pattern in sqli xss idor ssrf redirect rce lfi; do
    count=$(cat "$BASE/recon/urls/all.txt" | gf $pattern 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
      cat "$BASE/recon/urls/all.txt" | gf $pattern > "$BASE/recon/urls/gf-$pattern.txt"
      echo "   $pattern: $count URLs → gf-$pattern.txt"
    fi
  done
fi

# ─── 主 recon 工具 ─────────────────────────────
if [ "$RECON_TOOL" = "bbot" ]; then
  if command -v bbot &>/dev/null; then
    echo ""
    echo "🤖 BBOT subdomain enum..."
    bbot -t "$DOMAIN" \
      -p subdomain-enum \
      --allow-deadly \
      -o "$BASE/recon/bbot-out" \
      --silent 2>/dev/null &
    BBOT_PID=$!
    echo "   BBOT PID: $BBOT_PID（後台執行，輸出在 recon/bbot-out/）"
    echo "   等待基礎掃描（30s）..."
    sleep 30

    # 嘗試提取子域名
    if [ -f "$BASE/recon/bbot-out/output.txt" ]; then
      grep "DNS_NAME" "$BASE/recon/bbot-out/output.txt" \
        | awk '{print $2}' \
        | sort -u > "$BASE/recon/subdomains/bbot.txt"
      echo "   BBOT 子域名: $(wc -l < "$BASE/recon/subdomains/bbot.txt")"
    fi
  else
    echo ""
    echo "   ⚠️  BBOT 未安裝"
    echo "   安裝：pip install bbot"
    echo "   改用 subfinder..."
    _run_subfinder "$DOMAIN" "$BASE"
  fi

elif [ "$RECON_TOOL" = "osmedeus" ]; then
  if command -v osmedeus &>/dev/null; then
    echo ""
    echo "⚡ Osmedeus recon..."
    osmedeus scan -t "$DOMAIN" \
      --wfFolder "$BASE/recon/osmedeus-out" &
    echo "   Osmedeus PID: $!（後台執行）"
  else
    echo "   ⚠️  Osmedeus 未安裝：https://github.com/j3ssie/osmedeus"
  fi
fi

# ─── 存活子域名確認 ─────────────────────────────
echo ""
echo "🌐 存活確認..."
ALL_SUBS="$BASE/recon/subdomains/all.txt"
cat "$BASE/recon/subdomains/"*.txt 2>/dev/null | sort -u > "$ALL_SUBS"

if command -v httpx &>/dev/null && [ -s "$ALL_SUBS" ]; then
  cat "$ALL_SUBS" | httpx -silent -status-code -mc 200,301,302,403,500 \
    > "$BASE/recon/subdomains/live.txt" 2>/dev/null
  echo "   存活: $(wc -l < "$BASE/recon/subdomains/live.txt") subdomains"
else
  echo "   ⚠️  httpx 未安裝或無子域名資料"
fi

# ─── 完成 ──────────────────────────────────────
echo ""
echo "✅ Recon 完成！"
echo ""
echo "下一步："
echo "  1. 填寫 info/scope.md 和 info/accounts.md"
echo "  2. 查看 recon/subdomains/live.txt"
echo "  3. 查看 recon/urls/gf-*.txt（高價值 URL）"
echo "  4. 開始記錄 notes.md"
