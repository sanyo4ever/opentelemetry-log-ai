FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/

# Create log directory
RUN mkdir -p /var/log

# Default command
CMD ["python", "src/main.py"]
