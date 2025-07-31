# HawkEye - MCP Security Reconnaissance Tool
# Multi-stage Docker build for production deployment

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION=1.0.0

# Set environment variables for build
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    git \
    libssl-dev \
    libffi-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements first for better caching
COPY requirements.txt requirements-prod.txt ./

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt && \
    pip install -r requirements-prod.txt

# Copy source code
COPY . /app
WORKDIR /app

# Install HawkEye in the virtual environment
RUN pip install -e .

# Production stage
FROM python:3.11-slim as production

# Set build labels
LABEL org.opencontainers.image.title="HawkEye" \
      org.opencontainers.image.description="MCP Security Reconnaissance Tool" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.vendor="HawkEye Security Team" \
      org.opencontainers.image.url="https://github.com/yourusername/hawkeye" \
      org.opencontainers.image.source="https://github.com/yourusername/hawkeye" \
      org.opencontainers.image.documentation="https://github.com/yourusername/hawkeye/docs" \
      org.opencontainers.image.licenses="MIT"

# Set production environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    HAWKEYE_CONFIG="/app/config/hawkeye.yaml" \
    HAWKEYE_LOG_LEVEL="INFO" \
    HAWKEYE_DATA_DIR="/app/data" \
    HAWKEYE_RESULTS_DIR="/app/results" \
    HAWKEYE_LOGS_DIR="/app/logs"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    nmap \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    # System tools
    curl \
    wget \
    ca-certificates \
    # Process tools
    procps \
    # Security tools
    tcpdump \
    # Cleanup
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r hawkeye && \
    useradd -r -g hawkeye -d /app -s /bin/bash hawkeye

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create application directories
RUN mkdir -p /app/config /app/data /app/results /app/logs /app/temp && \
    chown -R hawkeye:hawkeye /app

# Copy application files
COPY --chown=hawkeye:hawkeye . /app/
WORKDIR /app

# Copy configuration files
COPY --chown=hawkeye:hawkeye config/hawkeye.yaml.example /app/config/hawkeye.yaml

# Set proper permissions
RUN chmod +x /app/application.py && \
    chmod 755 /app/docker/entrypoint.sh && \
    chmod 644 /app/config/hawkeye.yaml

# Create volume mount points
VOLUME ["/app/config", "/app/data", "/app/results", "/app/logs"]

# Expose ports (if web interface is enabled)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python application.py health-check || exit 1

# Switch to non-root user
USER hawkeye

# Set entrypoint
ENTRYPOINT ["/app/docker/entrypoint.sh"]

# Default command
CMD ["scan", "--help"]

# Development stage (for development builds)
FROM production as development

# Switch back to root for development tools installation
USER root

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    less \
    tree \
    htop \
    strace \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages
COPY requirements-dev.txt ./
RUN pip install -r requirements-dev.txt

# Install additional debugging tools
RUN pip install ipython ipdb

# Create development configuration
COPY config/hawkeye-dev.yaml.example /app/config/hawkeye-dev.yaml

# Set development environment variables
ENV HAWKEYE_CONFIG="/app/config/hawkeye-dev.yaml" \
    HAWKEYE_LOG_LEVEL="DEBUG" \
    HAWKEYE_DEBUG="1"

# Switch back to hawkeye user
USER hawkeye

# Override entrypoint for development
ENTRYPOINT ["/bin/bash"]

# Testing stage (for CI/CD)
FROM builder as testing

# Install test dependencies
COPY requirements-test.txt ./
RUN pip install -r requirements-test.txt

# Copy test files
COPY tests/ /app/tests/
COPY pytest.ini /app/
COPY .coveragerc /app/

# Run tests
WORKDIR /app
RUN python -m pytest tests/ --cov=hawkeye --cov-report=xml --cov-report=term

# Security scanning stage
FROM production as security-scan

USER root

# Install security scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Vulnerability scanners
    lynis \
    chkrootkit \
    # Network security tools
    nmap \
    masscan \
    # File integrity
    aide \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools
RUN pip install bandit safety pip-audit

# Run security scans
COPY docker/security-scan.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/security-scan.sh

USER hawkeye

# Default to running security scan
CMD ["/usr/local/bin/security-scan.sh"] 