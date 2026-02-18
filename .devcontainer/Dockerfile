FROM mcr.microsoft.com/devcontainers/python:1-3.11-bookworm

# Remove stale Yarn APT repository with expired GPG key (NO_PUBKEY 62D54FD4003F6525)
# This must happen before any feature installation runs apt-get update
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && rm -f /etc/apt/keyrings/yarn.gpg \
    && apt-get update
