# Builder stage: compiles httptap (needs a newer Go than Debian bookworm's apt package provides)
FROM golang:1.23-bookworm AS httptap-builder
RUN go install github.com/monasticacademy/httptap@v0.1.1

FROM mcr.microsoft.com/devcontainers/python:3.13-bookworm

# Remove stale Yarn APT repository with expired GPG key (NO_PUBKEY 62D54FD4003F6525)
# This must happen before any feature installation runs apt-get update
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && rm -f /etc/apt/keyrings/yarn.gpg \
    && apt-get update

# --- Security/analysis tools + PDF report generation libraries ---
# Pinned/baked in at build time instead of postCreateCommand for fast, reproducible container startup.
RUN apt-get install -y --no-install-recommends \
    nmap \
    dirb \
    netcat-traditional \
    tcpdump \
    net-tools \
    dnsutils \
    curl \
    wget \
    jq \
    tree \
    htop \
    file \
    binutils \
    unzip \
    zip \
    git \
    build-essential \
    libpcap-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libfontconfig1 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    wkhtmltopdf \
    fonts-noto-color-emoji \
    docker-compose \
    ruby \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# --- Git LFS ---
RUN curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | bash \
    && apt-get install -y git-lfs \
    && rm -rf /var/lib/apt/lists/*

# --- Nikto (pinned release, not master branch) ---
RUN curl -fsSL https://github.com/sullo/nikto/archive/refs/tags/2.6.1.tar.gz -o /tmp/nikto.tar.gz \
    && mkdir -p /opt/security-tools \
    && tar -xzf /tmp/nikto.tar.gz -C /opt/security-tools \
    && mv /opt/security-tools/nikto-2.6.1 /opt/security-tools/nikto \
    && chmod +x /opt/security-tools/nikto/program/nikto.pl \
    && ln -sf /opt/security-tools/nikto/program/nikto.pl /usr/local/bin/nikto \
    && rm -f /tmp/nikto.tar.gz

# --- Gobuster (pinned release) ---
RUN curl -fsSL https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz -o /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /tmp gobuster \
    && mv /tmp/gobuster /usr/local/bin/gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm -f /tmp/gobuster.tar.gz

# --- WhatWeb (pinned release, not master branch) ---
RUN curl -fsSL https://github.com/urbanadventurer/WhatWeb/archive/refs/tags/v0.6.4.tar.gz -o /tmp/whatweb.tar.gz \
    && mkdir -p /opt/security-tools \
    && tar -xzf /tmp/whatweb.tar.gz -C /opt/security-tools \
    && mv /opt/security-tools/WhatWeb-0.6.4 /opt/security-tools/WhatWeb \
    && chmod +x /opt/security-tools/WhatWeb/whatweb \
    && ln -sf /opt/security-tools/WhatWeb/whatweb /usr/local/bin/whatweb \
    && rm -f /tmp/whatweb.tar.gz \
    && gem install --no-document addressable

# --- httptap (built in the builder stage above; used for Exercise 5 TLS/DNS stream visualization) ---
COPY --from=httptap-builder /go/bin/httptap /usr/local/bin/httptap

# --- Python dependencies (changes most often; copy requirements.txt in for cache-friendly layering) ---
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --no-cache-dir --upgrade pip \
    && python3 -m pip install --no-cache-dir -r /tmp/requirements.txt

