#!/usr/bin/env bash
# install.sh — bbflow 依賴安裝器（Linux 優先，macOS 兼容）
#
# 用法：
#   ./install.sh             # 互動式（問每個工具）
#   ./install.sh --all       # 全部自動安裝（CI / VPS 用）
#   ./install.sh --check     # 只檢查，不安裝
set -uo pipefail

ALL=0; CHECK_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --all)   ALL=1;        shift;;
    --check) CHECK_ONLY=1; shift;;
    -h|--help) echo "Usage: $0 [--all|--check]"; exit 0;;
    *) shift;;
  esac
done

# ── Detect OS / package manager ───────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"
PKG=""
if [ "$OS" = "Linux" ]; then
  command -v apt    >/dev/null 2>&1 && PKG="apt"
  command -v dnf    >/dev/null 2>&1 && PKG="dnf"
  command -v pacman >/dev/null 2>&1 && PKG="pacman"
  command -v apk    >/dev/null 2>&1 && PKG="apk"
elif [ "$OS" = "Darwin" ]; then
  command -v brew   >/dev/null 2>&1 && PKG="brew"
fi
HAS_GO=$(command -v go >/dev/null 2>&1 && echo 1 || echo 0)

R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
ok()  { echo "${G}✓${N} $*"; }
info(){ echo "${C}→${N} $*"; }
warn(){ echo "${Y}!${N} $*"; }
err() { echo "${R}✗${N} $*"; }

echo "${C}== bbflow installer ==${N}"
echo "OS: $OS ($ARCH)  pkg: ${PKG:-none}"
echo ""

# ── Helper ────────────────────────────────────────────────────
check_and_install() {
  local tool="$1" check_cmd="$2" install_cmd="$3" purpose="$4"
  if eval "$check_cmd" >/dev/null 2>&1; then
    ok "$tool  ($purpose)"
    return 0
  fi
  warn "$tool  missing  ($purpose)"
  [ "$CHECK_ONLY" = "1" ] && return 1
  if [ -z "$install_cmd" ]; then
    err "  no installer for this platform — see README"
    return 1
  fi
  if [ "$ALL" = "0" ]; then
    read -r -p "  Install $tool? [y/N] " ans </dev/tty
    [[ "$ans" != [yY] ]] && { info "skipped"; return 0; }
  fi
  info "  running: $install_cmd"
  eval "$install_cmd" && ok "$tool installed" || err "$tool install failed"
}

go_install() {
  # go install ... + ensure ~/go/bin in PATH for this session
  [ "$HAS_GO" = "0" ] && { err "go not found — install Go first: https://go.dev/dl/"; return 1; }
  eval "$1" && export PATH="$HOME/go/bin:$PATH"
}

pip_install() {
  # try pip3 with --break-system-packages (PEP 668); fall back to --user
  python3 -m pip install "$@" --break-system-packages 2>/dev/null \
    || python3 -m pip install "$@" --user
}

# ── System requirements ────────────────────────────────────────
echo "${C}-- System requirements --${N}"
for T in curl python3 bash dig awk sed grep sort; do
  command -v "$T" >/dev/null 2>&1 && ok "$T" || err "$T MISSING (install via system package)"
done

# Go toolchain (most tools are go install)
if [ "$HAS_GO" = "0" ]; then
  warn "go not found — most tools require Go"
  case "$PKG" in
    apt)    info "  sudo apt install -y golang-go  OR  https://go.dev/dl/";;
    dnf)    info "  sudo dnf install -y golang";;
    pacman) info "  sudo pacman -S --noconfirm go";;
    brew)   info "  brew install go";;
    *)      info "  https://go.dev/dl/";;
  esac
fi

# ── BBOT ───────────────────────────────────────────────────────
echo ""
echo "${C}-- Recon engine --${N}"
case "$PKG" in
  apt)    BBOT_INSTALL="sudo apt install -y pipx && pipx install bbot && pipx ensurepath";;
  dnf)    BBOT_INSTALL="sudo dnf install -y pipx && pipx install bbot && pipx ensurepath";;
  pacman) BBOT_INSTALL="sudo pacman -S --noconfirm python-pipx && pipx install bbot && pipx ensurepath";;
  brew)   BBOT_INSTALL="brew install pipx && pipx install bbot && pipx ensurepath";;
  *)      BBOT_INSTALL="python3 -m pip install --user pipx && python3 -m pipx install bbot && pipx ensurepath";;
esac
check_and_install "bbot" "command -v bbot || [ -x $HOME/.local/bin/bbot ]" "$BBOT_INSTALL" "passive+active subdomain recon"

# ── ProjectDiscovery core tools ────────────────────────────────
echo ""
echo "${C}-- ProjectDiscovery tools (go install) --${N}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pd_tool() {
  local name="$1" pkg="$2" purpose="$3"
  local brew_name="${4:-$name}"
  local check="command -v $name || [ -x $SCRIPT_DIR/$name ]"
  local inst
  if [ "$PKG" = "brew" ]; then
    inst="brew install $brew_name"
  else
    inst="go_install 'go install $pkg@latest'"
  fi
  check_and_install "$name" "$check" "$inst" "$purpose"
}

pd_tool httpx     "github.com/projectdiscovery/httpx/cmd/httpx"                   "live host probe"
pd_tool subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"        "passive subdomain enum"
pd_tool nuclei    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"              "template vuln scan"
pd_tool katana    "github.com/projectdiscovery/katana/cmd/katana"                 "JS-aware crawl"
pd_tool dnsx      "github.com/projectdiscovery/dnsx/cmd/dnsx"                     "DNS probing"

# ── URL / param discovery tools ────────────────────────────────
echo ""
echo "${C}-- URL & param discovery --${N}"

# gau
if [ "$PKG" = "brew" ]; then
  GAU_INST="brew install gau"
else
  GAU_INST="go_install 'go install github.com/lc/gau/v2/cmd/gau@latest'"
fi
check_and_install "gau" "command -v gau" "$GAU_INST" "historical URL (wayback+commoncrawl+otx)"

# waybackurls
if [ "$PKG" = "brew" ]; then
  WB_INST="brew install waybackurls"
else
  WB_INST="go_install 'go install github.com/tomnomnom/waybackurls@latest'"
fi
check_and_install "waybackurls" "command -v waybackurls" "$WB_INST" "Wayback Machine URLs"

# gf + patterns
if [ "$PKG" = "brew" ]; then
  GF_INST="brew install gf"
else
  GF_INST="go_install 'go install github.com/tomnomnom/gf@latest'"
fi
check_and_install "gf" "command -v gf" "$GF_INST" "URL pattern filter (sqli/xss/ssrf/lfi)"
if command -v gf >/dev/null 2>&1 && [ ! -d "$HOME/.gf" ]; then
  info "gf: downloading patterns..."
  mkdir -p "$HOME/.gf"
  curl -sL "https://raw.githubusercontent.com/tomnomnom/gf/master/examples/redirect.json" -o "$HOME/.gf/redirect.json" 2>/dev/null || true
  for pat in sqli ssrf lfi ssti xss idor; do
    curl -sL "https://raw.githubusercontent.com/1ndianl33t/Gf-Patterns/master/${pat}.json" \
      -o "$HOME/.gf/${pat}.json" 2>/dev/null || true
  done
  ok "gf: $(ls "$HOME/.gf"/*.json 2>/dev/null | wc -l | tr -d ' ') patterns installed"
fi

# uro (Python)
check_and_install "uro" "command -v uro" \
  "pip_install uro" "URL deduplication (same param pattern)"

# ── Fuzzing & XSS ──────────────────────────────────────────────
echo ""
echo "${C}-- Fuzzing & XSS tools --${N}"

# ffuf
if [ "$PKG" = "brew" ]; then
  FFUF_INST="brew install ffuf"
else
  FFUF_INST="go_install 'go install github.com/ffuf/ffuf/v2@latest'"
fi
check_and_install "ffuf" "command -v ffuf" "$FFUF_INST" "directory/file fuzzing"

# dalfox
if [ "$PKG" = "brew" ]; then
  DFX_INST="brew install dalfox"
else
  DFX_INST="go_install 'go install github.com/hahwul/dalfox/v2@latest'"
fi
check_and_install "dalfox" "command -v dalfox" "$DFX_INST" "XSS scanner (blind + reflected)"

# arjun (Python)
check_and_install "arjun" "command -v arjun" \
  "pip_install arjun" "hidden parameter discovery"

# trufflehog
TFH_CHECK="command -v trufflehog"
if [ "$PKG" = "brew" ]; then
  TFH_INST="brew install trufflehog"
elif [ "$OS" = "Linux" ]; then
  TFH_INST='curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin'
else
  TFH_INST="go_install 'go install github.com/trufflesecurity/trufflehog/v3@latest'"
fi
check_and_install "trufflehog" "$TFH_CHECK" "$TFH_INST" "git secret scan (100+ detectors)"

# ── Git dump tools ─────────────────────────────────────────────
echo ""
echo "${C}-- Git exposure tools --${N}"
check_and_install "git-dumper" \
  "python3 -m git_dumper --version 2>/dev/null || command -v git-dumper" \
  "pip_install git-dumper" ".git dump"
check_and_install "waymore" "command -v waymore" \
  "pip_install waymore" "historical URL (nxdomain hunter)"

# ── SecLists ───────────────────────────────────────────────────
echo ""
echo "${C}-- SecLists (wordlists for ffuf/arjun/dalfox) --${N}"
SECLISTS_DST="$HOME/Tools/SecLists"
if [ -d "$SECLISTS_DST/Discovery/Web-Content" ]; then
  WL=$(find "$SECLISTS_DST/Discovery/Web-Content" -name "*.txt" 2>/dev/null | wc -l | tr -d ' ')
  ok "SecLists → $SECLISTS_DST ($WL wordlists)"
else
  warn "SecLists not found at $SECLISTS_DST"
  [ "$CHECK_ONLY" = "1" ] && true || {
    if [ "$ALL" = "0" ]; then
      read -r -p "  Install SecLists (sparse clone, ~200MB)? [y/N] " ans </dev/tty
      [[ "$ans" != [yY] ]] && { info "skipped"; true; } || {
        mkdir -p "$HOME/Tools"
        git clone --depth=1 --filter=blob:none --sparse \
          https://github.com/danielmiessler/SecLists.git "$SECLISTS_DST" && \
        git -C "$SECLISTS_DST" sparse-checkout set Discovery/Web-Content Fuzzing/XSS && \
        ok "SecLists installed"
      }
    else
      mkdir -p "$HOME/Tools"
      git clone --depth=1 --filter=blob:none --sparse \
        https://github.com/danielmiessler/SecLists.git "$SECLISTS_DST" && \
      git -C "$SECLISTS_DST" sparse-checkout set Discovery/Web-Content Fuzzing/XSS && \
      ok "SecLists installed"
    fi
  }
fi

# ── nuclei templates ───────────────────────────────────────────
echo ""
echo "${C}-- nuclei templates --${N}"
if command -v nuclei >/dev/null 2>&1; then
  NTMPL="$HOME/nuclei-templates"
  if [ -d "$NTMPL" ]; then
    ok "nuclei-templates → $NTMPL"
  else
    warn "nuclei-templates not found"
    [ "$CHECK_ONLY" = "0" ] && {
      if [ "$ALL" = "0" ]; then
        read -r -p "  Run nuclei -update-templates? [y/N] " ans </dev/tty
        [[ "$ans" == [yY] ]] && nuclei -update-templates 2>/dev/null && ok "templates updated"
      else
        nuclei -update-templates 2>/dev/null && ok "templates updated"
      fi
    }
  fi
else
  info "nuclei not installed — skipping template check"
fi

# ── Optional ───────────────────────────────────────────────────
echo ""
echo "${C}-- Optional --${N}"
case "$PKG" in
  apt)    JQ_INST="sudo apt install -y jq";;
  dnf)    JQ_INST="sudo dnf install -y jq";;
  pacman) JQ_INST="sudo pacman -S --noconfirm jq";;
  brew)   JQ_INST="brew install jq";;
  *)      JQ_INST="";;
esac
check_and_install "jq" "command -v jq" "$JQ_INST" "JSON parsing"

# ── bbflow CLI symlink ─────────────────────────────────────────
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$CHECK_ONLY" = "0" ]; then
  # Try ~/.local/bin first (no sudo), fallback to /usr/local/bin
  for BIN_DIR in "$HOME/.local/bin" "/usr/local/bin"; do
    if [ -d "$BIN_DIR" ] || mkdir -p "$BIN_DIR" 2>/dev/null; then
      if ln -sf "$TOOLS_DIR/bbflow.sh" "$BIN_DIR/bbflow" 2>/dev/null; then
        ok "bbflow → $BIN_DIR/bbflow  (symlink created)"
        # Ensure the bin dir is in PATH hint
        echo "$PATH" | grep -q "$BIN_DIR" || warn "add to shell: export PATH=\"$BIN_DIR:\$PATH\""
        break
      fi
    fi
  done
fi

# ── Final summary ──────────────────────────────────────────────
echo ""
echo "${C}== Done ==${N}"
if [ "$CHECK_ONLY" = "1" ]; then
  info "check only — no changes made"
else
  info "run: bbflow doctor         (verify all paths)"
  info "run: bbflow test           (smoke test hunters against example.com)"
  info "tip: export BBFLOW_WORKSPACE=~/work  (set research/ output dir)"
fi
