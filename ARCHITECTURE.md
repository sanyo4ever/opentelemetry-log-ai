# Security Log Analysis System

## Project Overview

An automated security log analysis system for real-time threat detection from 1000+ hosts (Windows/Linux) using OpenTelemetry, ClickHouse, and Sigma rules.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    1000+ Hosts (Windows/Linux)                  │
│                    OpenTelemetry Collectors                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ OTLP Protocol
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                         SigNoz Server                           │
│                  OpenTelemetry Collector                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Batch Insert
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ClickHouse Database                        │
│                    (Logs Storage + Query)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Stream/Poll
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│              Security Analysis Service (NEW)                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Log Processor                         │  │
│  │  - ClickHouse Consumer (streaming/polling)               │  │
│  │  - OTEL → SIEM format mapper                            │  │
│  │  - Sigma rules engine                                    │  │
│  │  - Alert generator                                       │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Webhook (alerts)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Keep Platform                           │
│                    (Alert Management)                           │
└─────────────────────────────────────────────────────────────────┘
```

## System Components

### 1. Data Sources

**OpenTelemetry Collectors on hosts**
- **Windows**: Security events, Sysmon, Application logs
- **Linux**: Syslog, Auth logs, Audit logs
- **Format**: OTLP (OpenTelemetry Protocol)

### 2. Collection and Storage (existing)

- **SigNoz Server**: Central collector
- **ClickHouse**: Columnar database for logs
  - Tables: `logs`, `logs_v2` (depending on SigNoz version)
  - Optimized for analytical queries

### 3. Security Analysis Service (new component)

#### Option A: OTEL → Sigma (recommended for quick start)

```
┌─────────────────────────────────────────────────────────────┐
│  ClickHouse Consumer Module                                 │
│  - Polling interval: 1-5s                                   │
│  - or ClickHouse Kafka Engine for streaming                │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  OTEL to ECS/Sigma Mapper                                   │
│  - Map OTEL semantic conventions                            │
│  - Normalize field names                                    │
│  - Extract EventID, LogSource, etc.                         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Sigma Rules Engine                                         │
│  - Load sigma-rules from repo                               │
│  - Parse YAML rules                                         │
│  - Apply detection logic                                    │
│  - Libraries: pySigma, sigma-cli                            │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  Alert Generator                                            │
│  - Format alert payload                                     │
│  - Enrich with context                                      │
│  - Send webhook to Keep                                     │
└─────────────────────────────────────────────────────────────┘
```

#### Option B: SIEM Format Layer

```
┌─────────────────────────────────────────────────────────────┐
│  ClickHouse Materialized View                               │
│  - Transform OTEL → ECS/OSSEM format                        │
│  - Pre-compute common fields                                │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│  SIEM-Compatible Query Layer                                │
│  - Query standardized fields                                │
│  - Direct Sigma rule application                            │
└─────────────────────────────────────────────────────────────┘
```

## Technology Stack

### Core Components

```yaml
Language: Python 3.11+
Framework: FastAPI / Flask

Libraries:
  - pySigma: Sigma rule parsing and conversion
  - sigma-cli: CLI tools for sigma rules
  - clickhouse-driver: ClickHouse client
  - httpx/requests: Webhook calls
  - pydantic: Data validation
  - redis: Caching and deduplication
```

### Sigma Rules Integration

```yaml
sigma-rules-repo: https://github.com/SigmaHQ/sigma
Key directories:
  - rules/windows/
  - rules/linux/
  - rules/cloud/

Tools:
  - pySigma: Python library
  - sigmac: Rule converter
  - sigma backends: ClickHouse backend
```

## Mapping Strategy

### OTEL Semantic Conventions → Sigma Fields

```yaml
# Windows Security Events
OTEL Field → Sigma Field:
  body.EventID → EventID
  body.Channel → Channel
  attributes.host.name → Computer
  attributes.os.type → OSType
  body.EventData.TargetUserName → TargetUserName
  body.EventData.IpAddress → IpAddress
  severity_text → Level

# Linux Syslog
OTEL Field → Sigma Field:
  body.message → message
  attributes.host.name → hostname
  attributes.log.file.path → source
  body.severity → severity
```

### Example Mapping Code

```python
def map_otel_to_sigma(log_entry: dict) -> dict:
    """
    Convert OTEL log to Sigma-compatible format
    """
    mapped = {
        'EventID': log_entry.get('body', {}).get('EventID'),
        'Channel': log_entry.get('body', {}).get('Channel'),
        'Computer': log_entry.get('attributes', {}).get('host', {}).get('name'),
        'TimeCreated': log_entry.get('timestamp'),
        # Windows EventData
        'EventData': log_entry.get('body', {}).get('EventData', {}),
        # Metadata
        'source': 'opentelemetry',
        'collector': log_entry.get('attributes', {}).get('service', {}).get('name')
    }
    return mapped
```

## Project Structure

```
security-log-analyzer/
├── README.md
├── requirements.txt
├── docker-compose.yml
├── config/
│   ├── config.yaml
│   ├── field_mappings.yaml
│   └── sigma_rules/  # Git submodule
│       └── rules/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── consumers/
│   │   ├── __init__.py
│   │   ├── clickhouse_consumer.py
│   │   └── kafka_consumer.py  # optional
│   ├── mappers/
│   │   ├── __init__.py
│   │   ├── otel_mapper.py
│   │   └── field_mapper.py
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── sigma_engine.py
│   │   ├── rule_loader.py
│   │   └── rule_matcher.py
│   ├── alerts/
│   │   ├── __init__.py
│   │   ├── alert_manager.py
│   │   └── keep_webhook.py
│   └── utils/
│       ├── __init__.py
│       ├── cache.py
│       └── deduplication.py
├── tests/
│   ├── test_mapper.py
│   ├── test_sigma_engine.py
│   └── test_integration.py
└── deployment/
    ├── Dockerfile
    └── kubernetes/
```

## Implementation Phases

### Phase 1: MVP (2-3 weeks)

- ClickHouse consumer (polling)
- Basic OTEL → Sigma mapper
- Integration of 10-20 critical Sigma rules
- Webhook to Keep
- Basic logging and monitoring

### Phase 2: Production Ready (3-4 weeks)

- Redis for deduplication
- Full set of Sigma rules (500+)
- Streaming via ClickHouse Kafka engine
- Metrics and dashboards
- Alert throttling and grouping

### Phase 3: Advanced (4-6 weeks)

- ML-based anomaly detection
- Custom rule builder UI
- Automated rule tuning
- Threat intelligence integration
- SOAR integration

## Configuration

### config.yaml

```yaml
clickhouse:
  host: localhost
  port: 9000
  database: signoz_logs
  table: logs
  poll_interval: 5  # seconds
  batch_size: 1000

sigma:
  rules_path: ./config/sigma_rules/rules
  enabled_categories:
    - process_creation
    - network_connection
    - file_event
  severity_filter: [high, critical]

alerting:
  keep_webhook_url: https://keep.example.com/webhook
  deduplication_window: 300  # seconds
  max_alerts_per_minute: 100

logging:
  level: INFO
  file: /var/log/security-analyzer.log
```

## Sigma Rules Integration Options

### Option 1: pySigma (recommended)

```python
from sigma.collection import SigmaCollection
from sigma.backends.clickhouse import ClickHouseBackend

# Load rules
rules = SigmaCollection.load_ruleset("rules/windows/")

# Convert to ClickHouse queries
backend = ClickHouseBackend()
for rule in rules:
    query = backend.convert(rule)
    # Execute query on ClickHouse
```

**Advantages:**
- Native Python support
- Actively maintained
- Many backends (including ClickHouse)

### Option 2: Sigma-CLI + Custom Backend

```bash
# Convert Sigma rule to SQL
sigma convert -t clickhouse rule.yml > query.sql
```

### Option 3: SIEM Layer (OpenSearch/Elastic compatible)

- Create materialized view in ClickHouse with ECS schema
- Use ready-made Sigma → Elasticsearch backends
- More complex integration, but standardized approach

## Monitoring and Performance

### Metrics to Monitor

```yaml
- logs_processed_per_second
- rules_evaluated_per_second
- alerts_generated_per_minute
- clickhouse_query_latency
- false_positive_rate
- rule_match_rate
- webhook_delivery_success_rate
```

### Optimization Points

- **ClickHouse Indexes**: Create indexes on frequent fields (timestamp, host, EventID)
- **Caching**: Redis for rule results
- **Batch Processing**: Process logs in batches
- **Parallel Processing**: Multi-threading for rule evaluation

## Security Considerations

- **Credentials**: Use vault (HashiCorp Vault, AWS Secrets Manager)
- **Network**: VPC/firewall rules between components
- **Encryption**: TLS for all connections
- **Audit**: Log all alerts and decisions
- **Access Control**: RBAC for rule management

## Alternative Approaches

### Using Ready-Made SIEM

- **Wazuh**: Open-source SIEM with Sigma support
- **OpenSearch Security Analytics**: Built-in Sigma support
- **Velociraptor**: Endpoint visibility with Sigma rules

However, custom development provides:
- Full control over logic
- Optimization for your stack
- Flexibility in scaling
- No vendor lock-in

## Conclusion

**Recommended approach**: Option A with pySigma

### Why

- Fast MVP (2-3 weeks)
- Direct pipeline control
- Optimization for ClickHouse
- Flexibility for extensions
- Active Sigma rules community

### Next Steps

1. Setup dev environment
2. Implement ClickHouse consumer
3. Create field mapping layer
4. Integrate 10 high-priority Sigma rules
5. Test end-to-end flow
6. Deploy MVP
