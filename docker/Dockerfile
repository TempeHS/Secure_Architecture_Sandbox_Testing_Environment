# Lightweight Dockerfile optimized for Codespaces and educational use
FROM mcr.microsoft.com/devcontainers/python:3.11-bullseye

# Set environment variables to avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/workspace/src

# Install system dependencies and security tools (alphabetical for better caching)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Analysis and utility tools
    binutils \
    curl \
    dirb \
    dnsutils \
    file \
    # Text processing tools
    gawk \
    git \
    grep \
    htop \
    jq \
    # Network tools
    net-tools \
    netcat-traditional \
    # Security tools
    nmap \
    # Web tools and languages
    nodejs \
    npm \
    # Text processing continued
    sed \
    tcpdump \
    tree \
    # Archive tools
    unzip \
    wget \
    zip \
    # Clean up to reduce image size
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Install additional security tools with optimized downloads
RUN mkdir -p /opt/tools && cd /opt/tools && \
    # Download all tools in parallel using wget for better caching
    wget -q https://github.com/sullo/nikto/archive/refs/heads/master.tar.gz -O nikto-master.tar.gz & \
    wget -q https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz & \
    wget -q https://github.com/urbanadventurer/WhatWeb/archive/refs/heads/master.tar.gz -O whatweb-master.tar.gz & \
    wait && \
    # Extract and install Nikto
    tar -xzf nikto-master.tar.gz && \
    chmod +x nikto-master/program/nikto.pl && \
    ln -s /opt/tools/nikto-master/program/nikto.pl /usr/local/bin/nikto && \
    # Extract and install Gobuster
    tar -xzf gobuster_Linux_x86_64.tar.gz && \
    mv gobuster /usr/local/bin/ && \
    # Extract and install WhatWeb
    tar -xzf whatweb-master.tar.gz && \
    chmod +x WhatWeb-master/whatweb && \
    ln -s /opt/tools/WhatWeb-master/whatweb /usr/local/bin/whatweb && \
    # Clean up downloaded archives
    rm -f *.tar.gz

# Install standard wordlists to avoid runtime downloads
RUN mkdir -p /usr/share/wordlists && \
    echo -e "admin\ntest\nbackup\nconfig\n.git\n.env\ndebug\nlogin\napi\nindex\ndata\nfiles\nimages\nuser\npassword\ndashboard\nsettings\nhelp\nabout\ncontact\npublic\nprivate\ntemp\ntmp\nupload\ndownload" > /usr/share/wordlists/common.txt && \
    chmod 644 /usr/share/wordlists/common.txt

# Install Python security and analysis packages
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel

# Copy all requirements files for consolidated installation
COPY requirements.txt /tmp/requirements.txt
COPY samples/vulnerable-flask-app/requirements.txt /tmp/flask-requirements.txt
COPY samples/unsecure-pwa/requirements.txt /tmp/pwa-requirements.txt

# Install Python packages in optimized order (dependencies first, then requirements)
RUN pip install --no-cache-dir \
    # Core dependencies first (most stable, installed in many packages)
    requests==2.31.0 \
    beautifulsoup4==4.12.2 \
    lxml==4.9.3 \
    pyyaml==6.0.1 \
    # Security analysis tools with pinned versions
    bandit==1.7.5 \
    safety==2.3.5 \
    semgrep==1.45.0 \
    # Network analysis tools
    scapy==2.5.0 \
    python-nmap==0.7.1 \
    # Web testing tools
    selenium==4.15.0 \
    # Development tools
    pytest==7.4.3 \
    black==23.9.1 \
    flake8==6.1.0 \
    # Install all requirements files
    -r /tmp/requirements.txt \
    -r /tmp/flask-requirements.txt \
    -r /tmp/pwa-requirements.txt \
    # Clean up pip cache and temporary files
    && pip cache purge \
    && rm -rf /tmp/*.txt /root/.cache/pip

# Set working directory and copy files (using PWA pattern for file copying)
WORKDIR /workspace
COPY . /workspace/

# Ensure Flask app files are properly accessible and create required directories
RUN mkdir -p /workspace/samples/vulnerable-flask-app/files \
    && mkdir -p /workspace/samples/vulnerable-flask-app/uploads \
    && echo "This is a sample file for path traversal testing." > /workspace/samples/vulnerable-flask-app/files/sample.txt \
    && chmod -R 755 /workspace/samples/vulnerable-flask-app

# Set proper permissions for vscode user
RUN chown -R vscode:vscode /workspace

# Create a non-root user for enhanced security (already exists in base image)
USER vscode

# Expose common ports for educational testing
EXPOSE 8080 8000 3000 9090

# Default command - keep container alive and allow manual Flask app start
CMD ["sh", "-c", "echo 'Sandbox container ready. Use docker exec to start applications.' && tail -f /dev/null"]