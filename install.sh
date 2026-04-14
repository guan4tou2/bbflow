#!/usr/bin/env bash
# install.sh — 安裝 bbflow 需要的所有依賴（macOS / Linux）
#
# 用法：
#   ./tools/install.sh             # 互動式（問每個工具）
#   ./tools/install.sh --all       # 全部自動安裝
#   ./tools/install.sh --check     # 只檢查，不安裝（等同 bbflow doctor）
#
# 涵蓋：
#   必要：curl python3 dig bash (系統內建)
#   推薦：bbot httpx subfinder dnsx nuclei
#   --dump 才需要：git-dumper waymore
#   可選：jq ripgrep fd
set -uo pipefail

ALL=0
CHECK_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --all) ALL=1; shift;;
    --check) CHECK_ONLY=1; shift;;
    -h|--help) echo "Usage: $0 [--all|--check]"; exit 0;;
    *) shift;;
  esac
done

# ── Detect OS / package manager ───────────────────────────────
OS="$(uname -s)"
PKG=""
if [ "$OS" = "Darwin" ]; then
  if command -v brew >/dev/null 2>&1; then PKG="brew"; fi
elif [ "$OS" = "Linux" ]; then
  if command -v apt >/dev/null 2>&1; then PKG="apt"
  elif command -v dnf >/dev/null 2>&1; then PKG="dnf"
  elif command -v pacman >/dev/null 2>&1; then PKG="pacman"
  elif command -v apk >/dev/null 2>&1; then PKG="apk"
  fi
fi

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
ok(){ echo "${G}✓${N} $*"; }
info(){ echo "${C}→${N} $*"; }
warn(){ echo "${Y}!${N} $*"; }
err(){ echo "${R}✗${N} $*"; }

echo "${C}== bbflow installer ==${N}"
echo "OS: $OS"
echo "Package manager: ${PKG:-none (manual install only)}"
echo ""

# ── Table: tool | check cmd | install method ────────────────────
check_and_install() {
  local tool="$1" check="$2" install_cmd="$3" purpose="$4"
  if eval "$check" >/dev/null 2>&1; then
    ok "$tool ($purpose)"
    return 0
  fi
  warn "$tool missing ($purpose)"
  [ "$CHECK_ONLY" = "1" ] && return 1
  if [ -z "$install_cmd" ]; then
    err "  no installer for this platform — install manually"
    return 1
  fi
  if [ "$ALL" = "0" ]; then
    read -p "  Install $tool? [y/N] " ans </dev/tty
    [ "$ans" != "y" ] && [ "$ans" != "Y" ] && { info "skipped"; return 0; }
  fi
  info "  installing: $install_cmd"
  eval "$install_cmd" && ok "$tool installed" || err "$tool install failed"
}

# ── System requirements (must exist, no auto-install) ──────────
echo "${C}-- System requirements --${N}"
for T in curl python3 bash dig awk sed grep sort; do
  if command -v "$T" >/dev/null 2>&1; then ok "$T"; else err "$T MISSING (install via system package)"; fi
done

# ── Core recon tools ───────────────────────────────────────────
echo ""
echo "${C}-- Core recon tools --${N}"

# BBOT (via pipx)
case "$PKG" in
  brew) BBOT_INSTALL="brew install pipx && pipx install bbot";;
  apt)  BBOT_INSTALL="sudo apt install -y pipx && pipx install bbot";;
  dnf)  BBOT_INSTALL="sudo dnf install -y pipx && pipx install bbot";;
  pacman) BBOT_INSTALL="sudo pacman -S --noconfirm python-pipx && pipx install bbot";;
  *)    BBOT_INSTALL="python3 -m pip install --user pipx && pipx install bbot";;
esac
check_and_install "bbot" "command -v bbot" "$BBOT_INSTALL" "passive + active recon"

# httpx (ProjectDiscovery)
HTTPX_INSTALL="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
[ "$PKG" = "brew" ] && HTTPX_INSTALL="brew install httpx"
check_and_install "httpx" "command -v httpx || [ -x $(dirname "$0")/httpx ]" "$HTTPX_INSTALL" "live host probe"

# subfinder
SUBF_INSTALL="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
[ "$PKG" = "brew" ] && SUBF_INSTALL="brew install subfinder"
check_and_install "subfinder" "command -v subfinder || [ -x $(dirname "$0")/subfinder ]" "$SUBF_INSTALL" "passive subdomain"

# dnsx
DNSX_INSTALL="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
[ "$PKG" = "brew" ] && DNSX_INSTALL="brew install dnsx"
check_and_install "dnsx" "command -v dnsx" "$DNSX_INSTALL" "fast DNS probing"

# nuclei
NUCLEI_INSTALL="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
[ "$PKG" = "brew" ] && NUCLEI_INSTALL="brew install nuclei"
check_and_install "nuclei" "command -v nuclei || [ -x $(dirname "$0")/nuclei ]" "$NUCLEI_INSTALL" "template vuln scan"

# ── Git dump tools (--dump 才需要) ─────────────────────────────
echo ""
echo "${C}-- git-exposure --dump tools --${N}"
GD_INSTALL="python3 -m pip install --user git-dumper"
check_and_install "git-dumper" "python3 -m git_dumper --version 2>/dev/null || command -v git-dumper" "$GD_INSTALL" ".git dump (nested .git CMS pattern)"

# waymore (historical URL discovery, used by nxdomain hunter)
WM_INSTALL="python3 -m pip install --user waymore"
check_and_install "waymore" "command -v waymore" "$WM_INSTALL" "historical URL (nxdomain hunter)"

# ── Optional niceties ──────────────────────────────────────────
echo ""
echo "${C}-- Optional (quality-of-life) --${N}"
case "$PKG" in
  brew)   JQ_INST="brew install jq";;
  apt)    JQ_INST="sudo apt install -y jq";;
  dnf)    JQ_INST="sudo dnf install -y jq";;
  pacman) JQ_INST="sudo pacman -S --noconfirm jq";;
  *)      JQ_INST="";;
esac
check_and_install "jq" "command -v jq" "$JQ_INST" "JSON parsing in shell"

# ── Summary ────────────────────────────────────────────────────
echo ""
echo "${C}== Summary ==${N}"
if [ "$CHECK_ONLY" = "1" ]; then
  info "check only — no changes made"
else
  info "run './tools/bbflow.sh doctor' to verify"
  info "run './tools/bbflow.sh test' to smoke-test all hunters"
fi
