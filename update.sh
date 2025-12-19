#!/bin/bash

# Security Log Analyzer - Update Script
# This script updates the service with minimal downtime

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "================================================"
echo "Security Log Analyzer - Update Script"
echo "================================================"
echo

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "WARNING: Running as root. Consider using a dedicated service account."
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Detect service management method
SERVICE_TYPE=""
if systemctl list-units --type=service | grep -q "security-log-analyzer"; then
    SERVICE_TYPE="systemd"
elif command -v supervisorctl &> /dev/null && supervisorctl status security-log-analyzer &> /dev/null; then
    SERVICE_TYPE="supervisor"
else
    echo "WARNING: Service manager not detected. Will stop manually."
    SERVICE_TYPE="manual"
fi

echo "Detected service type: $SERVICE_TYPE"
echo

# Pre-update checks
echo "[1/8] Running pre-update checks..."

if [ ! -d "venv" ]; then
    echo "ERROR: Virtual environment not found. Run installation first."
    exit 1
fi

if [ ! -f "config/config.yaml" ]; then
    echo "ERROR: Configuration file not found."
    exit 1
fi

echo "✓ Pre-checks passed"
echo

# Backup checkpoint
echo "[2/8] Backing up checkpoint..."

if [ -f "data/checkpoint.json" ]; then
    BACKUP_FILE="data/checkpoint.json.backup-$(date +%Y%m%d-%H%M%S)"
    cp data/checkpoint.json "$BACKUP_FILE"
    echo "✓ Checkpoint backed up to: $BACKUP_FILE"
else
    echo "⚠ No checkpoint file found (this is OK for first run)"
fi
echo

# Stop service
echo "[3/8] Stopping service..."

case $SERVICE_TYPE in
    systemd)
        sudo systemctl stop security-log-analyzer
        echo "✓ Service stopped (systemd)"
        ;;
    supervisor)
        sudo supervisorctl stop security-log-analyzer
        echo "✓ Service stopped (supervisor)"
        ;;
    manual)
        pkill -f "python.*main.py" || echo "⚠ No process found to kill"
        sleep 2
        echo "✓ Process terminated"
        ;;
esac
echo

# Pull changes
echo "[4/8] Pulling latest changes..."

CURRENT_COMMIT=$(git rev-parse HEAD)
echo "Current commit: $CURRENT_COMMIT"

git fetch origin
git pull origin main

NEW_COMMIT=$(git rev-parse HEAD)
echo "New commit: $NEW_COMMIT"

if [ "$CURRENT_COMMIT" = "$NEW_COMMIT" ]; then
    echo "⚠ No new commits, already up to date"
else
    echo "✓ Updated to new commit"
fi
echo

# Update dependencies
echo "[5/8] Updating dependencies..."

source venv/bin/activate
pip install -r requirements.txt --upgrade --quiet

echo "✓ Dependencies updated"
echo

# Configuration check
echo "[6/8] Checking configuration..."

python3 << 'PYTHON_EOF'
import yaml
import sys

try:
    with open('config/config.yaml', 'r') as f:
        config = yaml.safe_load(f)

    required_keys = ['clickhouse', 'sigma', 'alerting', 'logging']
    for key in required_keys:
        if key not in config:
            print(f"ERROR: Missing required config section: {key}")
            sys.exit(1)

    print("✓ Configuration validated")
except Exception as e:
    print(f"ERROR: Configuration validation failed: {e}")
    sys.exit(1)
PYTHON_EOF

if [ $? -ne 0 ]; then
    echo
    echo "ERROR: Configuration validation failed"
    exit 1
fi
echo

# Start service
echo "[7/8] Starting service..."

case $SERVICE_TYPE in
    systemd)
        sudo systemctl start security-log-analyzer
        sleep 3
        if systemctl is-active --quiet security-log-analyzer; then
            echo "✓ Service started successfully (systemd)"
        else
            echo "ERROR: Service failed to start"
            sudo systemctl status security-log-analyzer
            exit 1
        fi
        ;;
    supervisor)
        sudo supervisorctl start security-log-analyzer
        sleep 3
        echo "✓ Service started (supervisor)"
        ;;
    manual)
        echo "⚠ Manual mode: Please start the service manually"
        echo "  Run: nohup python src/main.py > /dev/null 2>&1 &"
        ;;
esac
echo

# Verification
echo "[8/8] Verifying update..."

sleep 2

# Check if process is running
if pgrep -f "python.*main.py" > /dev/null; then
    echo "✓ Process is running"
else
    echo "ERROR: Process not found"
    exit 1
fi

# Check logs for startup
if [ -f "logs/security-analyzer.log" ]; then
    if tail -20 logs/security-analyzer.log | grep -q "Starting Security Log Analysis Service"; then
        echo "✓ Service started successfully"
    else
        echo "⚠ Could not verify startup in logs"
    fi

    if tail -20 logs/security-analyzer.log | grep -qi "error"; then
        echo "⚠ WARNING: Errors detected in recent logs"
        echo "  Check: tail -f logs/security-analyzer.log"
    fi
fi

echo
echo "================================================"
echo "Update completed successfully!"
echo "================================================"
echo
echo "Next steps:"
echo "  - Monitor logs: tail -f logs/security-analyzer.log"
echo "  - Check status: sudo systemctl status security-log-analyzer"
echo "  - View stats: grep 'System Statistics' logs/security-analyzer.log"
echo
echo "Rollback if needed:"
echo "  git reset --hard $CURRENT_COMMIT"
echo "  ./update.sh"
echo
