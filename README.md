# Security Log Analysis Service

An automated security log analysis system using OpenTelemetry, ClickHouse, and Sigma rules.

## Overview

This service polls logs from a SigNoz/ClickHouse database, maps them to a Sigma-compatible format, checks for security threats using Sigma rules, and sends alerts to a webhook.

## Prerequisites

- Docker and Docker Compose
- Access to a generic SigNoz ClickHouse instance (or any ClickHouse with OTEL logs).

## Configuration

1.  **ClickHouse Connection**: Edit `config/config.yaml` to set your ClickHouse host, port, and credentials.
    ```yaml
    clickhouse:
      host: clickhouse
      port: 9000
    ```
    *Note: If running in Docker on the same machine as SigNoz, ensure the networks are connected or use `host.docker.internal`.*

2.  **Alerting**: Set your webhook URL in `config/config.yaml`:
    ```yaml
    alerting:
      keep_webhook_url: https://your-webhook-url.com
    ```

3.  **Sigma Rules**: Place your Sigma YAML rules in `config/sigma_rules/rules/`.
    *Currently, a basic built-in rule for "Failed Login (EventID 4625)" is enabled for demonstration.*

## Running the Service

```bash
docker-compose up --build -d
```

## Monitoring

Check logs to see processing status:

```bash
docker-compose logs -f security-analyzer
```

## Testing

Generate test security events to validate Sigma rule matching:

```bash
# Send 100 test events to OTEL collector
./test_otel_events.sh

# Send custom number of events
./test_otel_events.sh 50

# Watch for generated alerts
docker-compose logs -f security-analyzer | grep -i alert
```

The test script generates realistic security events including:
- Failed login attempts (EventID 4625)
- Mimikatz credential dumping (EventID 10)
- Suspicious PowerShell scripts (EventID 4104)
- Privilege escalation (EventID 4728)
- Lateral movement (EventID 4624)

For detailed testing procedures, see [TESTING.md](TESTING.md).

## Development

1.  Create a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run tests:
    ```bash
    python tests/test_basic_flow.py
    ```