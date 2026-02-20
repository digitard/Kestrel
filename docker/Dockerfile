# Kestrel Tools Image
# Kali Linux-based security toolset for Kestrel bug bounty automation.
# Supports ARM64 (Apple Silicon, Raspberry Pi) and AMD64 (Intel/AMD x86_64).
#
# Build (multi-arch):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t kestrel-tools:latest --push .
#
# Build (local, current arch):
#   docker build -t kestrel-tools:latest .
#
# Run (managed by DockerManager, but can be run manually):
#   docker run -d --name kestrel-tools \
#     -v kestrel-workspace:/workspace \
#     --network host \
#     kestrel-tools:latest tail -f /dev/null

FROM kalilinux/kali-rolling

# Build argument for target architecture (set automatically by BuildKit)
ARG TARGETARCH

# Metadata
LABEL maintainer="Kestrel"
LABEL description="Kali Linux security toolset for Kestrel bug bounty automation"
LABEL version="1.0.0"

# ─────────────────────────────────────────────────────────────────────
# Base system update
# ─────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    # Core utilities
    curl \
    wget \
    git \
    jq \
    unzip \
    python3 \
    python3-pip \
    # Network fundamentals
    net-tools \
    iputils-ping \
    dnsutils \
    whois \
    # Required by several tools
    libpcap-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────────────────────────────
# Tier 1: Wrapped tools (structured I/O, parsers built for these)
# ─────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    gobuster \
    nikto \
    sqlmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────────────────────────────
# Tier 2: Discovery and enumeration
# ─────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Web crawling / fingerprinting
    whatweb \
    dirb \
    # DNS
    dnsenum \
    dnsrecon \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────────────────────────────
# Tier 2: Go-based tools (installed via pre-built binaries)
# ─────────────────────────────────────────────────────────────────────

# ffuf — fast web fuzzer
RUN ARCH=$(dpkg --print-architecture) && \
    FFUF_VERSION="2.1.0" && \
    if [ "$ARCH" = "arm64" ]; then \
        FFUF_ARCH="linux_arm64"; \
    else \
        FFUF_ARCH="linux_amd64"; \
    fi && \
    curl -sSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_${FFUF_ARCH}.tar.gz" \
        -o /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /tmp && \
    mv /tmp/ffuf /usr/local/bin/ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm -f /tmp/ffuf.tar.gz

# subfinder — subdomain discovery
RUN ARCH=$(dpkg --print-architecture) && \
    SF_VERSION="2.6.6" && \
    if [ "$ARCH" = "arm64" ]; then \
        SF_ARCH="linux_arm64"; \
    else \
        SF_ARCH="linux_amd64"; \
    fi && \
    curl -sSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SF_VERSION}/subfinder_${SF_VERSION}_${SF_ARCH}.zip" \
        -o /tmp/subfinder.zip && \
    unzip -q /tmp/subfinder.zip -d /tmp/subfinder && \
    mv /tmp/subfinder/subfinder /usr/local/bin/subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm -rf /tmp/subfinder.zip /tmp/subfinder

# httpx — fast HTTP prober and fingerprinter
RUN ARCH=$(dpkg --print-architecture) && \
    HTTPX_VERSION="1.6.8" && \
    if [ "$ARCH" = "arm64" ]; then \
        HTTPX_ARCH="linux_arm64"; \
    else \
        HTTPX_ARCH="linux_amd64"; \
    fi && \
    curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_${HTTPX_ARCH}.zip" \
        -o /tmp/httpx.zip && \
    unzip -q /tmp/httpx.zip -d /tmp/httpx && \
    mv /tmp/httpx/httpx /usr/local/bin/httpx && \
    chmod +x /usr/local/bin/httpx && \
    rm -rf /tmp/httpx.zip /tmp/httpx

# nuclei — vulnerability scanner with templates
RUN ARCH=$(dpkg --print-architecture) && \
    NUCLEI_VERSION="3.3.7" && \
    if [ "$ARCH" = "arm64" ]; then \
        NUCLEI_ARCH="linux_arm64"; \
    else \
        NUCLEI_ARCH="linux_amd64"; \
    fi && \
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${NUCLEI_ARCH}.zip" \
        -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei && \
    mv /tmp/nuclei/nuclei /usr/local/bin/nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei.zip /tmp/nuclei

# ─────────────────────────────────────────────────────────────────────
# Exploit-DB / searchsploit (offline CVE → exploit lookup)
# ─────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    exploitdb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ─────────────────────────────────────────────────────────────────────
# Wordlists
# ─────────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    wordlists \
    seclists \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* && \
    # Decompress rockyou if needed
    [ -f /usr/share/wordlists/rockyou.txt.gz ] && \
        gunzip /usr/share/wordlists/rockyou.txt.gz || true

# ─────────────────────────────────────────────────────────────────────
# Workspace
# ─────────────────────────────────────────────────────────────────────
RUN mkdir -p /workspace /workspace/output /workspace/scans /workspace/loot
WORKDIR /workspace

# ─────────────────────────────────────────────────────────────────────
# Healthcheck — verify core tools are present
# ─────────────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nmap --version > /dev/null && gobuster --help > /dev/null 2>&1 || exit 1

# Keep container running so DockerManager can exec into it
CMD ["tail", "-f", "/dev/null"]
