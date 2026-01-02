FROM python:3.11-slim

WORKDIR /app

# Install git for Sigma rules auto-updater
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/

# Create directories and set ownership
RUN mkdir -p /app/data /app/logs /var/log \
    && chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Default command
CMD ["python", "src/main.py"]
