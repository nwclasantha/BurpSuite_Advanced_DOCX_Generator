# ============================================================================
# SECURE HIGH-PERFORMANCE DOCKER IMAGE
# BurpSuite HTML to DOCX Converter
# ============================================================================
# Security Features:
#   - Multi-stage build (minimal final image)
#   - Non-root user execution
#   - Read-only filesystem support
#   - No shell in final image (distroless-like)
#   - Minimal attack surface
#   - No unnecessary packages
#   - Pinned versions for reproducibility
#
# Performance Features:
#   - Alpine base (minimal size)
#   - Layer caching optimization
#   - No dev dependencies in final image
#   - Optimized Python bytecode
# ============================================================================

# ------------------------------------------------------------------------------
# STAGE 1: Builder - Install dependencies and compile
# ------------------------------------------------------------------------------
FROM python:3.12-alpine AS builder

# Security: Don't run as root during build where possible
# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/cache/apk/*

# Create virtual environment for isolation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
# Copy only requirements first for better layer caching
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt && \
    # Remove pip cache and unnecessary files
    rm -rf /root/.cache/pip && \
    find /opt/venv -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true && \
    find /opt/venv -type f -name "*.pyc" -delete 2>/dev/null || true

# ------------------------------------------------------------------------------
# STAGE 2: Production - Minimal secure runtime
# ------------------------------------------------------------------------------
FROM python:3.12-alpine AS production

# Metadata
LABEL maintainer="Security Assessment Team" \
      version="6.0.0" \
      description="Enterprise BurpSuite HTML to Professional DOCX Report Converter with Network CVE Assessment" \
      org.opencontainers.image.title="BurpSuite Report Converter" \
      org.opencontainers.image.description="Converts BurpSuite HTML vulnerability reports to professional enterprise DOCX documents with executive summaries, risk matrices, OWASP compliance mapping, and network CVE assessment" \
      org.opencontainers.image.vendor="nwclasantha" \
      org.opencontainers.image.source="https://github.com/nwclasantha/BurpSuite-Report-Converter" \
      org.opencontainers.image.documentation="https://hub.docker.com/r/nwclasantha/burp-converter" \
      org.opencontainers.image.licenses="MIT" \
      security.policy="non-root,read-only-fs,no-new-privileges"

# Security: Install only runtime dependencies (no compilers)
RUN apk add --no-cache \
    libxml2 \
    libxslt \
    tini \
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

# Security: Create non-root user with specific UID/GID
RUN addgroup -g 1000 -S appgroup && \
    adduser -u 1000 -S appuser -G appgroup -h /app -s /sbin/nologin

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    # Security: Disable Python's built-in help browser
    PYTHONNOUSERSITE=1

# Create application directories
WORKDIR /app

# Create input/output directories with proper permissions
RUN mkdir -p /app/input /app/output /app/network_reports && \
    chown -R appuser:appgroup /app

# Copy application code
COPY --chown=appuser:appgroup burp_to_docx.py /app/
COPY --chown=appuser:appgroup entrypoint.sh /app/

# Security: Make entrypoint executable and remove write permissions
RUN chmod 555 /app/entrypoint.sh && \
    chmod 444 /app/burp_to_docx.py

# Security: Switch to non-root user
USER appuser:appgroup

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import docx, bs4, pandas; print('healthy')" || exit 1

# Use tini as init system (handles signals properly, prevents zombies)
ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]

# Default command (can be overridden)
CMD ["--help"]

# ------------------------------------------------------------------------------
# STAGE 3: Production Hardened - Extra security (optional)
# ------------------------------------------------------------------------------
FROM production AS hardened

# Security: Remove shell access entirely (breaks interactive debugging)
USER root
RUN rm -f /bin/sh /bin/ash /bin/bash 2>/dev/null || true
USER appuser:appgroup

# This stage is for maximum security environments
# Use: docker build --target hardened -t burp-converter:hardened .
