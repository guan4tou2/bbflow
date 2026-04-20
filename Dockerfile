# ─────────────────────────────────────────────────────────────────────────────
# bbflow — multi-stage Docker image
# Stage 1: compile all Go tools
# Stage 2: runtime (python:3.12-slim-bookworm + Go bins + pip tools + data)
#
# Build:   docker build -t bbflow .
# Pull:    docker pull ghcr.io/guan4tou2/bbflow:latest
#
# Image size: ~1.5 GB (nuclei-templates + SecLists baked in)
# Override with volumes to use host copies instead:
#   -v ~/nuclei-templates:/root/nuclei-templates
#   -v ~/Tools/SecLists:/root/Tools/SecLists
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Go tool compilation ─────────────────────────────────────────────
FROM golang:1.23-bookworm AS go-builder

# Install all Go-based tools in one layer for cache efficiency
RUN go install \
    github.com/projectdiscovery/httpx/cmd/httpx@latest \
    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    github.com/projectdiscovery/katana/cmd/katana@latest \
    github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    github.com/lc/gau/v2/cmd/gau@latest \
    github.com/tomnomnom/waybackurls@latest \
    github.com/tomnomnom/gf@latest \
    github.com/ffuf/ffuf/v2@latest \
    github.com/hahwul/dalfox/v2@latest \
    2>&1

# ── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    # bbflow looks for tools in $TOOLS_DIR/bin first, then PATH
    PATH="/bbflow/bin:/bbflow:/usr/local/bin:/root/go/bin:${PATH}" \
    # workspace: mount -v $(pwd):/workspace to read/write research/ here
    BBFLOW_WORKSPACE=/workspace \
    # tools data paths (override by mounting your local copies)
    SECLISTS=/root/Tools/SecLists \
    NUCLEI_COMMUNITY=/root/nuclei-templates

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git dnsutils ca-certificates \
    bash grep sed gawk coreutils \
    # chromium for katana JS-crawl mode
    chromium chromium-driver \
    # nmap for hunt-portscan.sh service detection
    nmap \
    && rm -rf /var/lib/apt/lists/*

# ── rustscan + feroxbuster (port scan + dir fuzzing fallback) ────────────────
RUN ARCH="$(uname -m)" \
    && case "$ARCH" in \
         x86_64)  FB_URL="https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz"; \
                  RS_URL="https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb";; \
         aarch64) FB_URL="https://github.com/epi052/feroxbuster/releases/latest/download/aarch64-linux-feroxbuster.tar.gz"; \
                  RS_URL="";; \
       esac \
    && if [ -n "$FB_URL" ]; then \
         curl -sL "$FB_URL" | tar -xz -C /usr/local/bin feroxbuster 2>/dev/null || true; \
         chmod +x /usr/local/bin/feroxbuster 2>/dev/null || true; \
       fi \
    && if [ -n "$RS_URL" ]; then \
         curl -sL "$RS_URL" -o /tmp/rustscan.deb && dpkg -i /tmp/rustscan.deb 2>/dev/null || true; \
         rm -f /tmp/rustscan.deb; \
       fi

# ── Go binaries (from stage 1) ────────────────────────────────────────────────
COPY --from=go-builder /go/bin/ /usr/local/bin/

# ── Python tools ─────────────────────────────────────────────────────────────
RUN pip3 install --no-cache-dir arjun uro git-dumper waymore

# ── trufflehog ────────────────────────────────────────────────────────────────
RUN curl -sSfL \
    https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin

# ── gf patterns ───────────────────────────────────────────────────────────────
RUN mkdir -p /root/.gf \
    && for p in sqli ssrf lfi ssti xss idor redirect; do \
         curl -sSL \
           "https://raw.githubusercontent.com/1ndianl33t/Gf-Patterns/master/${p}.json" \
           -o /root/.gf/${p}.json || true; \
       done

# ── nuclei templates (baked in; mount /root/nuclei-templates to override) ────
RUN nuclei -update-templates -silent 2>/dev/null || true

# ── SecLists sparse clone (baked in; mount /root/Tools/SecLists to override) ─
RUN mkdir -p /root/Tools \
    && git clone --depth=1 --filter=blob:none --sparse \
         https://github.com/danielmiessler/SecLists.git /root/Tools/SecLists \
    && git -C /root/Tools/SecLists sparse-checkout set Discovery/Web-Content Fuzzing/XSS \
    && rm -rf /root/Tools/SecLists/.git

# ── bbflow source ─────────────────────────────────────────────────────────────
COPY . /bbflow/
RUN chmod +x /bbflow/bbflow.sh /bbflow/install.sh \
    && find /bbflow/hunters -name "*.sh" -exec chmod +x {} + \
    && chmod +x /bbflow/bin/*

# ── Workspace volume (research/ + reports/ go here) ──────────────────────────
WORKDIR /workspace
VOLUME ["/workspace"]

ENTRYPOINT ["/bbflow/bbflow.sh"]
CMD ["doctor"]
