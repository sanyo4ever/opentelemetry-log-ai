#!/bin/bash

# Security Log Analysis Service Installation Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SERVICE_NAME="security-log-analyzer"
CONFIG_DIR="./config"
CONFIG_FILE="$CONFIG_DIR/config.yaml"
DOCKER_COMPOSE_FILE="docker-compose.yml"

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    print_info "Checking dependencies..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! command -v git &> /dev/null; then
        print_error "Git is not installed. Please install git."
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        # Check for 'docker compose' plugin style
        if ! docker compose version &> /dev/null; then
             print_error "Docker Compose is not installed. Please install Docker Compose."
             exit 1
        fi
    fi
    
    print_info "Dependencies found."
}

setup_sigma_rules() {
    print_info "Setting up Sigma rules..."
    RULES_DIR="./config/sigma_rules"
    
    if [ -d "$RULES_DIR/.git" ]; then
        print_info "Sigma rules repository already exists. Pulling latest..."
        cd "$RULES_DIR"
        git pull
        cd - > /dev/null
    elif [ -d "$RULES_DIR" ] && [ "$(ls -A $RULES_DIR)" ]; then
         print_warn "Directory $RULES_DIR exists and is not empty, but is not a git repo. Skipping clone."
    else
        print_info "Cloning Sigma rules from https://github.com/SigmaHQ/sigma..."
        rm -rf "$RULES_DIR" # Ensure clean start if empty dir exists
        git clone --depth 1 https://github.com/SigmaHQ/sigma "$RULES_DIR"
    fi
}

setup_configuration() {
    print_info "Setting up configuration..."
    
    mkdir -p "$CONFIG_DIR"
    
    # Defaults
    DEFAULT_CH_HOST="clickhouse"
    DEFAULT_CH_PORT="9000"
    DEFAULT_WEBHOOK="https://api.keephq.dev/alerts"
    
    # Values
    CH_HOST=""
    CH_PORT=""
    WEBHOOK=""

    if [ -f "$CONFIG_FILE" ]; then
        print_warn "Configuration file exists at $CONFIG_FILE"
        read -p "Do you want to reconfigure? (y/N): " RECONFIGURE
        if [[ "$RECONFIGURE" =~ ^[Yy]$ ]]; then
            mv "$CONFIG_FILE" "${CONFIG_FILE}.bak"
            print_info "Backed up old config to ${CONFIG_FILE}.bak"
        else
            print_info "Using existing configuration."
            return
        fi
    fi

    print_info "Please configure the service:"
    
    read -p "ClickHouse Host [default: $DEFAULT_CH_HOST]: " INPUT_CH_HOST
    CH_HOST=${INPUT_CH_HOST:-$DEFAULT_CH_HOST}
    
    read -p "ClickHouse Port [default: $DEFAULT_CH_PORT]: " INPUT_CH_PORT
    CH_PORT=${INPUT_CH_PORT:-$DEFAULT_CH_PORT}
    
    read -p "Alert Webhook URL [default: $DEFAULT_WEBHOOK]: " INPUT_WEBHOOK
    WEBHOOK=${INPUT_WEBHOOK:-$DEFAULT_WEBHOOK}
    
    # Generate config file
    cat > "$CONFIG_FILE" <<EOF
clickhouse:
  host: $CH_HOST
  port: $CH_PORT
  database: signoz_logs
  table: logs_v2
  poll_interval: 5
  batch_size: 1000

sigma:
  rules_path: ./config/sigma_rules/rules
  enabled_categories:
    - process_creation
    - network_connection
    - file_event
  severity_filter: [high, critical]

alerting:
  keep_webhook_url: $WEBHOOK
  deduplication_window: 300
  max_alerts_per_minute: 100

logging:
  level: INFO
  file: /var/log/security-analyzer.log
EOF

    print_info "Configuration file created at $CONFIG_FILE"
}

start_service() {
    print_info "Starting service with Docker Compose..."
    
    # Check if 'signoz-net' exists, if not warn user
    if ! docker network ls | grep -q "signoz-net"; then
        print_warn "Network 'signoz-net' not found."
        print_warn "If you are running SigNoz, ensure it is up."
        print_warn "Trying to create it if it doesn't exist (though SigNoz usually creates it)..."
        docker network create signoz-net || true
    fi

    docker-compose up -d --build

    if [ $? -eq 0 ]; then
        print_info "Service started successfully!"
    else
        print_error "Failed to start service."
        exit 1
    fi
}

print_summary() {
    echo ""
    print_info "=========================================="
    print_info "Service: $SERVICE_NAME"
    print_info "Status: RUNNING (Docker)"
    echo ""
    print_info "Logs:"
    print_info "  docker-compose logs -f security-analyzer"
    print_info "=========================================="
}

main() {
    print_info "Installing $SERVICE_NAME..."
    
    check_dependencies
    setup_sigma_rules
    setup_configuration
    start_service
    print_summary
}

main "$@"
