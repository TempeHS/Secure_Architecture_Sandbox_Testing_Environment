# Lightweight Dockerfile optimized for Codespaces and educational use
FROM mcr.microsoft.com/devcontainers/python:3.11-bullseye

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/workspace/src

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Essential security tools (lightweight versions)
    nmap \
    dirb \
    # Network tools
    netcat-traditional \
    tcpdump \
    net-tools \
    dnsutils \
    # Web tools and languages
    nodejs \
    npm \
    # Analysis and utility tools
    curl \
    wget \
    jq \
    tree \
    htop \
    file \
    binutils \
    # Text processing
    grep \
    sed \
    gawk \
    # Additional tools
    unzip \
    zip \
    git \
    # Clean up to reduce image size
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Install additional security tools that need manual installation
RUN cd /opt && \
    # Install Nikto
    git clone https://github.com/sullo/nikto.git && \
    cd nikto/program && \
    chmod +x nikto.pl && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    cd /opt && \
    # Install Gobuster
    wget https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz && \
    tar -xzf gobuster_Linux_x86_64.tar.gz && \
    mv gobuster /usr/local/bin/ && \
    rm gobuster_Linux_x86_64.tar.gz && \
    # Install WhatWeb
    git clone https://github.com/urbanadventurer/WhatWeb.git && \
    cd WhatWeb && \
    chmod +x whatweb && \
    ln -s /opt/WhatWeb/whatweb /usr/local/bin/whatweb

# Install Python security and analysis packages
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir \
    # Security analysis tools
    bandit \
    safety \
    semgrep \
    # Web and network libraries
    requests \
    beautifulsoup4 \
    python-nmap \
    # Web frameworks for sample apps
    flask \
    # Report generation
    reportlab \
    jinja2 \
    # Data handling
    pyyaml \
    # Development tools
    pytest \
    black \
    flake8

# Create application directories with proper permissions
RUN mkdir -p /workspace/src/sandbox \
             /workspace/src/analyzer \
             /workspace/src/reporter \
             /workspace/samples/web-app \
             /workspace/samples/scripts \
             /workspace/docs/lesson-plans \
             /workspace/docs/exercises \
             /workspace/reports \
             /workspace/logs && \
    chown -R vscode:vscode /workspace

# Set working directory
WORKDIR /workspace

# Create basic Python package structure as root then fix permissions
RUN touch /workspace/src/__init__.py && \
    touch /workspace/src/sandbox/__init__.py && \
    touch /workspace/src/analyzer/__init__.py && \
    touch /workspace/src/reporter/__init__.py && \
    chown -R vscode:vscode /workspace

# Create a non-root user for enhanced security (already exists in base image)
USER vscode

# Expose common ports for educational testing
EXPOSE 8080 8000 3000 5000

# Health check to ensure container is ready
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import requests; print('Container is healthy')" || exit 1

# Default command
CMD ["/bin/bash"]