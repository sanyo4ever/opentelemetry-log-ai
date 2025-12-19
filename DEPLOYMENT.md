# Deployment Guide

This guide covers how to deploy and update the Security Log Analysis Service on your server.

## Quick Update (Existing Installation)

```bash
# 1. SSH to your server
ssh user@your-server

# 2. Navigate to project directory
cd /path/to/opentelemetry-log-ai

# 3. Pull latest changes
git pull origin main

# 4. Run install script (handles update automatically)
./install.sh
```

The `install.sh` script will:
- Detect if this is an update or fresh install
- Backup checkpoint automatically
- Stop the service
- Update dependencies
- Apply configuration changes
- Restart the service
- Verify everything is working

### Zero-Downtime Update (Multiple Instances)

If you have multiple instances behind a load balancer:

```bash
# For each instance:
# 1. Remove instance from load balancer
# 2. Run: git pull && ./install.sh
# 3. Add instance back to load balancer
# 4. Repeat for other instances
```

---

## First-Time Installation

### Prerequisites

```bash
# Python 3.9+
python3 --version

# Git
git --version

# Optional: Redis (for distributed deduplication)
redis-server --version
```

### Installation Steps

```bash
# 1. Clone repository
cd /opt  # or your preferred location
git clone https://github.com/sanyo4ever/opentelemetry-log-ai.git
cd opentelemetry-log-ai

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create required directories
mkdir -p data logs

# 5. Configure the service
cp config/config.yaml config/config.local.yaml
nano config/config.local.yaml

# Update these settings:
# - clickhouse.host (your ClickHouse server)
# - clickhouse.user/password (if auth enabled)
# - alerting.keep_webhook_url (your Keep webhook)
# - logging.file (log file path)
```

### Configuration for Production

```yaml
# config/config.local.yaml

clickhouse:
  host: your-clickhouse-server.example.com
  port: 9000
  database: signoz_logs
  table: logs_v2
  poll_interval: 5
  batch_size: 1000
  user: security_analyzer
  password: ${CLICKHOUSE_PASSWORD}  # Use environment variable

alerting:
  keep_webhook_url: https://your-keep-instance.com/webhook/xyz
  deduplication_window: 300
  max_alerts_per_minute: 100
  max_retries: 3
  retry_delay: 1
  use_redis: true  # Enable for production

redis:
  host: localhost
  port: 6379
  db: 0
  password: ${REDIS_PASSWORD}  # Use environment variable

checkpoint:
  file: /var/lib/security-analyzer/checkpoint.json

logging:
  level: INFO
  file: /var/log/security-analyzer/security-analyzer.log
```

### Set Environment Variables

```bash
# Create .env file (not committed to git)
nano .env
```

```bash
# .env
CLICKHOUSE_PASSWORD=your_secure_password
REDIS_PASSWORD=your_redis_password
CONFIG_PATH=/opt/opentelemetry-log-ai/config/config.local.yaml
```

Load environment variables:
```bash
export $(cat .env | xargs)
```

---

## Running as a System Service (Recommended)

### Create Systemd Service

```bash
sudo nano /etc/systemd/system/security-log-analyzer.service
```

```ini
[Unit]
Description=Security Log Analysis Service
After=network.target clickhouse-server.service redis.service
Wants=clickhouse-server.service redis.service

[Service]
Type=simple
User=security-analyzer
Group=security-analyzer
WorkingDirectory=/opt/opentelemetry-log-ai
EnvironmentFile=/opt/opentelemetry-log-ai/.env
ExecStart=/opt/opentelemetry-log-ai/venv/bin/python src/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=security-log-analyzer

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/opentelemetry-log-ai/data /var/log/security-analyzer

[Install]
WantedBy=multi-user.target
```

### Create Service User

```bash
# Create dedicated user (no shell access)
sudo useradd -r -s /bin/false security-analyzer

# Set ownership
sudo chown -R security-analyzer:security-analyzer /opt/opentelemetry-log-ai
sudo mkdir -p /var/log/security-analyzer
sudo chown security-analyzer:security-analyzer /var/log/security-analyzer
```

### Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable auto-start on boot
sudo systemctl enable security-log-analyzer

# Start service
sudo systemctl start security-log-analyzer

# Check status
sudo systemctl status security-log-analyzer

# View logs
sudo journalctl -u security-log-analyzer -f
```

---

## Running Without Systemd (Alternative)

### Using Screen/Tmux

```bash
# Using tmux
tmux new -s security-analyzer
source venv/bin/activate
export $(cat .env | xargs)
python src/main.py

# Detach: Ctrl+B, then D
# Reattach: tmux attach -t security-analyzer
```

### Using Supervisor

```bash
sudo apt install supervisor

sudo nano /etc/supervisor/conf.d/security-log-analyzer.conf
```

```ini
[program:security-log-analyzer]
command=/opt/opentelemetry-log-ai/venv/bin/python src/main.py
directory=/opt/opentelemetry-log-ai
user=security-analyzer
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/security-analyzer/supervisor.log
environment=CONFIG_PATH="/opt/opentelemetry-log-ai/config/config.local.yaml"
```

```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start security-log-analyzer
```

---

## Docker Deployment (Advanced)

### Build Docker Image

```bash
# Build image
docker build -t security-log-analyzer:latest -f deployment/Dockerfile .

# Or use docker-compose
docker-compose up -d
```

### Docker Compose Example

```yaml
# docker-compose.yml
version: '3.8'

services:
  security-analyzer:
    build: .
    container_name: security-log-analyzer
    restart: unless-stopped
    environment:
      - CONFIG_PATH=/app/config/config.yaml
      - CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD}
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    volumes:
      - ./config:/app/config:ro
      - ./data:/app/data
      - ./logs:/app/logs
    networks:
      - monitoring
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    container_name: security-analyzer-redis
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    networks:
      - monitoring

networks:
  monitoring:
    external: true

volumes:
  redis-data:
```

---

## Update Procedure

Simply run the install script after pulling changes:

```bash
cd /path/to/opentelemetry-log-ai
git pull origin main
./install.sh
```

The `install.sh` script handles all update logic automatically.

---

## Verification After Update

### 1. Check Service Status

```bash
# Systemd
sudo systemctl status security-log-analyzer

# View recent logs
sudo journalctl -u security-log-analyzer -n 50

# Check if process is running
ps aux | grep main.py
```

### 2. Check Application Logs

```bash
# Tail logs
tail -f logs/security-analyzer.log

# Look for these indicators:
# - "Starting Security Log Analysis Service"
# - "All components initialized successfully"
# - "Entering main processing loop"
# - No ERROR messages
```

### 3. Verify Checkpoint

```bash
# Check checkpoint file exists and is being updated
ls -lh data/checkpoint.json
cat data/checkpoint.json

# Should show recent timestamp
```

### 4. Test Alert Flow (Optional)

```bash
# Monitor logs for alert processing
tail -f logs/security-analyzer.log | grep -i alert

# Check if alerts are being sent to Keep
# (monitor Keep platform for incoming alerts)
```

### 5. Check Statistics

```bash
# Logs should show periodic statistics every 60 seconds
grep "System Statistics" logs/security-analyzer.log
```

---

## Rollback Procedure

If the update causes issues:

```bash
# 1. Stop service
sudo systemctl stop security-log-analyzer

# 2. Rollback code
git reset --hard HEAD~1  # Go back one commit
# OR:
# git checkout <previous-commit-hash>

# 3. Restore checkpoint if needed
cp data/checkpoint.json.backup data/checkpoint.json

# 4. Reinstall old dependencies
source venv/bin/activate
pip install -r requirements.txt

# 5. Start service
sudo systemctl start security-log-analyzer

# 6. Verify
sudo systemctl status security-log-analyzer
```

---

## Monitoring and Maintenance

### Log Rotation

```bash
sudo nano /etc/logrotate.d/security-analyzer
```

```
/var/log/security-analyzer/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 security-analyzer security-analyzer
    sharedscripts
    postrotate
        systemctl reload security-log-analyzer > /dev/null 2>&1 || true
    endscript
}
```

### Health Check

Check if the service is healthy:

```bash
# Check if process is running
pgrep -f "python.*main.py"

# Check recent logs
tail -20 logs/security-analyzer.log

# Check checkpoint updates
ls -lh data/checkpoint.json
cat data/checkpoint.json
```

### Monitoring Integration

```bash
# Prometheus metrics (future enhancement)
# curl http://localhost:9090/metrics

# Alerting on service down
# Configure systemd-notifier or use monitoring tool (Datadog, New Relic, etc.)
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u security-log-analyzer -xe

# Common issues:
# - Config file not found → Check CONFIG_PATH
# - Permission denied → Check file ownership
# - ClickHouse connection failed → Verify credentials and network
# - Import errors → Reinstall dependencies
```

### High Memory Usage

```bash
# Check if Redis deduplication is enabled
# Consider reducing batch_size in config
# Monitor with: htop or ps aux --sort=-%mem
```

### Missing Logs

```bash
# Check checkpoint file
cat data/checkpoint.json

# Reset checkpoint to start fresh (CAUTION: may cause duplicates)
rm data/checkpoint.json
sudo systemctl restart security-log-analyzer
```

### Connection Issues

```bash
# Test ClickHouse connectivity
python3 << EOF
from clickhouse_driver import Client
client = Client(host='your-host', port=9000)
print(client.execute('SELECT 1'))
EOF

# Test Keep webhook
curl -X POST https://your-keep-webhook-url \
  -H "Content-Type: application/json" \
  -d '{"test": "message"}'
```

---

## Security Considerations

1. **Never commit sensitive data**
   - Use `.env` files for secrets
   - Keep `.gitignore` updated

2. **Restrict file permissions**
   ```bash
   chmod 600 .env
   chmod 600 config/config.local.yaml
   ```

3. **Use dedicated service account**
   - Don't run as root
   - Limit file system access

4. **Enable firewall rules**
   ```bash
   # Only allow necessary ports
   sudo ufw allow from your-clickhouse-ip to any port 9000
   ```

5. **Regular security updates**
   ```bash
   pip list --outdated
   pip install --upgrade <package>
   ```

---

## Support

- Documentation: [README.md](README.md), [ARCHITECTURE.md](ARCHITECTURE.md), [IMPROVEMENTS.md](IMPROVEMENTS.md)
- Issues: https://github.com/sanyo4ever/opentelemetry-log-ai/issues
- Logs: Check `logs/security-analyzer.log` for detailed debugging

---

## Quick Reference

```bash
# Install/Update service
git pull origin main && ./install.sh

# Start service
sudo systemctl start security-log-analyzer

# Stop service
sudo systemctl stop security-log-analyzer

# Restart service
sudo systemctl restart security-log-analyzer

# View logs
sudo journalctl -u security-log-analyzer -f
tail -f logs/security-analyzer.log

# Check status
sudo systemctl status security-log-analyzer
```
