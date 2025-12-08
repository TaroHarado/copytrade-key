# Privy Signing Service - Hardened Docker Image
# =============================================

FROM python:3.12-slim

# Security: Create non-root user
RUN useradd -m -u 1000 -s /bin/bash signing && \
    mkdir -p /app && \
    chown -R signing:signing /app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install poetry

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root --only main

# Copy application code
COPY --chown=signing:signing . .

# Copy startup scripts
COPY startup_scripts/ /app/startup_scripts/
RUN chmod +x /app/startup_scripts/*.sh

# Switch to non-root user
USER signing

# Expose port (internal only)
EXPOSE 8010

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8010/health')"

# Run application via entrypoint
CMD ["/app/startup_scripts/entrypoint.sh"]
