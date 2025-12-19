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

validate_env_file() {
    print_info "Checking for .env file..."

    if [ -f ".env" ]; then
        print_info "Found .env file"

        # Source the .env file
        set -a
        source .env
        set +a

        # Validate required variables
        MISSING_VARS=()

        if [ -z "$KEEP_API_KEY" ]; then
            MISSING_VARS+=("KEEP_API_KEY")
        fi

        if [ ${#MISSING_VARS[@]} -gt 0 ]; then
            print_warn "Missing environment variables in .env:"
            for var in "${MISSING_VARS[@]}"; do
                print_warn "  - $var"
            done
            print_warn "Service will start but may not function properly without these"
        else
            print_info "All required environment variables are set"
        fi
    else
        print_warn ".env file not found"
        print_warn "Creating template .env file..."
        cat > .env <<'EOF'
# Keep Platform API Key
KEEP_API_KEY=

# Optional: ClickHouse credentials
# CLICKHOUSE_USER=default
# CLICKHOUSE_PASSWORD=

# Optional: Redis password
# REDIS_PASSWORD=
EOF
        print_warn "Please edit .env file and add your credentials"
        print_warn "  nano .env"
    fi
}

setup_configuration() {
    print_info "Setting up configuration..."

    mkdir -p "$CONFIG_DIR"

    # Defaults
    DEFAULT_CH_HOST="clickhouse"
    DEFAULT_CH_PORT="9000"
    DEFAULT_WEBHOOK="https://api.keephq.dev/alerts/event"

    # Values
    CH_HOST=""
    CH_PORT=""
    WEBHOOK=""
    KEEP_API_KEY=""

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

    read -p "Keep API Key (press Enter to use env var): " INPUT_API_KEY
    if [ -z "$INPUT_API_KEY" ]; then
        KEEP_API_KEY="\${KEEP_API_KEY}"
        print_info "Will use KEEP_API_KEY from environment"
    else
        KEEP_API_KEY="$INPUT_API_KEY"
    fi
    
    # Generate config file
    cat > "$CONFIG_FILE" <<EOF
clickhouse:
  host: $CH_HOST
  port: $CH_PORT
  database: signoz_logs
  table: logs_v2
  poll_interval: 5
  batch_size: 1000
  # Optional: Authentication (uncomment if needed)
  # user: default
  # password: your_password

sigma:
  rules_path: ./config/sigma_rules/rules
  enabled_categories:
    - process_creation
    - network_connection
    - file_event
  severity_filter: [high, critical]

alerting:
  keep_webhook_url: $WEBHOOK
  keep_api_key: "$KEEP_API_KEY"
  deduplication_window: 300
  max_alerts_per_minute: 100
  max_retries: 3
  retry_delay: 1
  use_redis: false

# Optional: Redis configuration for distributed deduplication
redis:
  host: localhost
  port: 6379
  db: 0
  # password: your_redis_password

# Checkpoint configuration
checkpoint:
  file: data/checkpoint.json

logging:
  level: INFO
  file: logs/security-analyzer.log

# Stats reporting interval (seconds)
stats_interval: 60
EOF

    print_info "Configuration file created at $CONFIG_FILE"
}

cleanup_docker() {
    print_info "Cleaning up old Docker resources..."

    # Stop and remove old containers
    docker-compose down 2>/dev/null || true

    # Remove dangling containers
    docker ps -a | grep security-log-analyzer | awk '{print $1}' | xargs docker rm -f 2>/dev/null || true

    # Remove dangling images
    docker images | grep security-log-analyzer | awk '{print $3}' | xargs docker rmi -f 2>/dev/null || true

    # Prune dangling images
    docker image prune -f

    print_info "Cleanup completed"
}

start_service() {
    print_info "Starting service with Docker Compose..."

    # Cleanup old resources first
    cleanup_docker

    # Create required directories
    mkdir -p data logs config

    # Check if 'signoz-net' exists, if not create it
    if ! docker network ls | grep -q "signoz-net"; then
        print_warn "Network 'signoz-net' not found."
        print_info "Creating signoz-net network..."
        docker network create signoz-net || true
    fi

    # Build and start with clean slate
    print_info "Building and starting containers..."
    docker-compose build --no-cache
    docker-compose up -d

    if [ $? -eq 0 ]; then
        print_info "Service started successfully!"

        # Wait for container to be healthy
        sleep 3

        # Check if container is running
        if docker ps | grep -q security-log-analyzer; then
            print_info "Container is running"
        else
            print_error "Container failed to start"
            print_info "Checking logs..."
            docker-compose logs --tail=50
            exit 1
        fi
    else
        print_error "Failed to start service."
        docker-compose logs --tail=50
        exit 1
    fi
}

print_summary() {
    echo ""
    print_info "=========================================="
    print_info "Service: $SERVICE_NAME"
    print_info "Status: RUNNING (Docker)"
    print_info "Restart Policy: unless-stopped"
    echo ""
    print_info "Useful Commands:"
    print_info "  View logs:    docker-compose logs -f security-analyzer"
    print_info "  Restart:      docker-compose restart"
    print_info "  Stop:         docker-compose stop"
    print_info "  Status:       docker ps | grep security-log-analyzer"
    print_info "  Shell access: docker exec -it security-log-analyzer bash"
    echo ""
    print_info "The container will auto-restart on server reboot"
    print_info "=========================================="
}

main() {
    print_info "Installing $SERVICE_NAME..."

    check_dependencies
    validate_env_file
    setup_sigma_rules
    setup_configuration
    start_service
    print_summary
}

main "$@"
