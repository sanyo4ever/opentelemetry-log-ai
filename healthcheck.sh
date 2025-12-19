#!/bin/bash

# Security Log Analyzer - Health Check Script
# Returns exit code 0 if healthy, 1 if unhealthy

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

HEALTHY=0
UNHEALTHY=1

# Configuration
LOG_FILE="logs/security-analyzer.log"
CHECKPOINT_FILE="data/checkpoint.json"
MAX_LOG_AGE=300  # 5 minutes
MAX_CHECKPOINT_AGE=600  # 10 minutes

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_ok() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

EXIT_CODE=$HEALTHY

echo "================================================"
echo "Security Log Analyzer - Health Check"
echo "================================================"
echo

# Check 1: Process is running
echo "Checking process status..."
if pgrep -f "python.*main.py" > /dev/null; then
    PID=$(pgrep -f "python.*main.py")
    print_ok "Process is running (PID: $PID)"
else
    print_error "Process is NOT running"
    EXIT_CODE=$UNHEALTHY
fi
echo

# Check 2: Log file exists and is recent
echo "Checking log file..."
if [ -f "$LOG_FILE" ]; then
    print_ok "Log file exists: $LOG_FILE"

    # Check if log file has been updated recently
    if command -v stat &> /dev/null; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            LAST_MODIFIED=$(stat -f %m "$LOG_FILE")
        else
            # Linux
            LAST_MODIFIED=$(stat -c %Y "$LOG_FILE")
        fi

        NOW=$(date +%s)
        AGE=$((NOW - LAST_MODIFIED))

        if [ $AGE -lt $MAX_LOG_AGE ]; then
            print_ok "Log file is recent (updated ${AGE}s ago)"
        else
            print_warning "Log file is old (updated ${AGE}s ago)"
            EXIT_CODE=$UNHEALTHY
        fi
    fi

    # Check for recent errors in logs
    if tail -50 "$LOG_FILE" | grep -qi "error"; then
        ERROR_COUNT=$(tail -50 "$LOG_FILE" | grep -i "error" | wc -l)
        print_warning "Found $ERROR_COUNT error(s) in recent logs"
    else
        print_ok "No recent errors in logs"
    fi
else
    print_error "Log file not found: $LOG_FILE"
    EXIT_CODE=$UNHEALTHY
fi
echo

# Check 3: Checkpoint file
echo "Checking checkpoint..."
if [ -f "$CHECKPOINT_FILE" ]; then
    print_ok "Checkpoint file exists: $CHECKPOINT_FILE"

    # Parse checkpoint timestamp
    if command -v jq &> /dev/null; then
        CHECKPOINT_TS=$(jq -r '.timestamp' "$CHECKPOINT_FILE" 2>/dev/null)
        UPDATED_AT=$(jq -r '.updated_at' "$CHECKPOINT_FILE" 2>/dev/null)

        if [ "$CHECKPOINT_TS" != "null" ] && [ ! -z "$CHECKPOINT_TS" ]; then
            print_ok "Checkpoint timestamp: $CHECKPOINT_TS"
        fi

        if [ "$UPDATED_AT" != "null" ] && [ ! -z "$UPDATED_AT" ]; then
            print_ok "Last updated: $UPDATED_AT"
        fi
    else
        print_warning "jq not installed, cannot parse checkpoint details"
    fi

    # Check checkpoint age
    if command -v stat &> /dev/null; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            CHECKPOINT_MODIFIED=$(stat -f %m "$CHECKPOINT_FILE")
        else
            CHECKPOINT_MODIFIED=$(stat -c %Y "$CHECKPOINT_FILE")
        fi

        NOW=$(date +%s)
        CHECKPOINT_AGE=$((NOW - CHECKPOINT_MODIFIED))

        if [ $CHECKPOINT_AGE -lt $MAX_CHECKPOINT_AGE ]; then
            print_ok "Checkpoint is being updated (${CHECKPOINT_AGE}s ago)"
        else
            print_warning "Checkpoint hasn't been updated recently (${CHECKPOINT_AGE}s ago)"
            print_warning "Service may not be processing logs"
            EXIT_CODE=$UNHEALTHY
        fi
    fi
else
    print_warning "Checkpoint file not found (OK if first run)"
fi
echo

# Check 4: Configuration file
echo "Checking configuration..."
if [ -f "config/config.yaml" ]; then
    print_ok "Configuration file exists"

    # Validate YAML syntax
    if command -v python3 &> /dev/null; then
        if python3 -c "import yaml; yaml.safe_load(open('config/config.yaml'))" 2>/dev/null; then
            print_ok "Configuration syntax is valid"
        else
            print_error "Configuration has syntax errors"
            EXIT_CODE=$UNHEALTHY
        fi
    fi
else
    print_error "Configuration file not found"
    EXIT_CODE=$UNHEALTHY
fi
echo

# Check 5: Disk space
echo "Checking disk space..."
if command -v df &> /dev/null; then
    DISK_USAGE=$(df -h . | tail -1 | awk '{print $5}' | sed 's/%//')

    if [ $DISK_USAGE -lt 80 ]; then
        print_ok "Disk usage is acceptable (${DISK_USAGE}%)"
    elif [ $DISK_USAGE -lt 90 ]; then
        print_warning "Disk usage is high (${DISK_USAGE}%)"
    else
        print_error "Disk usage is critical (${DISK_USAGE}%)"
        EXIT_CODE=$UNHEALTHY
    fi
else
    print_warning "Cannot check disk usage"
fi
echo

# Check 6: Memory usage (if possible)
echo "Checking memory usage..."
if pgrep -f "python.*main.py" > /dev/null; then
    PID=$(pgrep -f "python.*main.py")

    if command -v ps &> /dev/null; then
        MEM_USAGE=$(ps -o rss= -p $PID 2>/dev/null)
        if [ ! -z "$MEM_USAGE" ]; then
            MEM_MB=$((MEM_USAGE / 1024))
            if [ $MEM_MB -lt 500 ]; then
                print_ok "Memory usage is normal (${MEM_MB}MB)"
            elif [ $MEM_MB -lt 1000 ]; then
                print_warning "Memory usage is elevated (${MEM_MB}MB)"
            else
                print_warning "Memory usage is high (${MEM_MB}MB)"
            fi
        fi
    fi
fi
echo

# Summary
echo "================================================"
if [ $EXIT_CODE -eq $HEALTHY ]; then
    echo -e "${GREEN}STATUS: HEALTHY${NC}"
else
    echo -e "${RED}STATUS: UNHEALTHY${NC}"
fi
echo "================================================"
echo

# Additional info for debugging
if [ $EXIT_CODE -ne $HEALTHY ]; then
    echo "Troubleshooting tips:"
    echo "  - View logs: tail -f $LOG_FILE"
    echo "  - Check service: sudo systemctl status security-log-analyzer"
    echo "  - Restart service: sudo systemctl restart security-log-analyzer"
    echo
fi

exit $EXIT_CODE
