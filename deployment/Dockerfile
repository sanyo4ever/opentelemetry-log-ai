FROM python:3.11-slim

WORKDIR /app

# Install git for Sigma rules auto-updater
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/

# Create log directory
RUN mkdir -p /var/log

# Default command
CMD ["python", "src/main.py"]
