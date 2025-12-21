# Testing Sigma Rules

This guide explains how to test and validate Sigma rule matching in your security log analysis service.

## Quick Start - Automated Testing

### Use the Test Event Generator Script

The easiest way to test is using the provided script that sends 100 events to your OTEL collector:

```bash
# Generate 100 test events (default)
./test_otel_events.sh

# Generate custom number of events
./test_otel_events.sh 50

# Use custom OTEL collector URL
OTEL_COLLECTOR_URL=http://otel-collector:4318/v1/logs ./test_otel_events.sh 200
```

The script generates a realistic mix of security events:
- **40% Failed Logins** (EventID 4625) - Should trigger failed authentication alerts
- **20% Suspicious PowerShell** (EventID 4104) - Malicious script execution patterns
- **15% Mimikatz Detection** (EventID 10) - Credential dumping attempts
- **15% Privilege Escalation** (EventID 4728) - Admin group additions
- **10% Lateral Movement** (EventID 4624) - Suspicious NTLM logins

After running the script:
```bash
# Watch for alerts in real-time
docker-compose logs -f security-analyzer | grep -i alert

# Check alert statistics
docker-compose logs security-analyzer | grep "System Statistics" | tail -1

# Verify events in ClickHouse
clickhouse-client --query "SELECT count() FROM signoz_logs.logs_v2 WHERE timestamp > toUnixTimestamp64Nano(now64(9)) - (5 * 60 * 1000000000)"
```

---

## Manual Test Methods

### 1. Test Current Hardcoded Rule (EventID 4625)

The service currently detects Windows Event ID 4625 (Failed Login Attempts). To test:

#### Generate Test Event in ClickHouse

```sql
-- Insert a test failed login event
INSERT INTO signoz_logs.logs_v2 (
    timestamp,
    severity_text,
    severity_number,
    body,
    attributes_string,
    resources_string
) VALUES (
    toUnixTimestamp64Nano(now64(9)),  -- Current timestamp in nanoseconds
    'WARN',
    13,
    '{"EventID": 4625, "Channel": "Security", "EventData": {"TargetUserName": "testuser", "IpAddress": "192.168.1.100"}}',
    map('host.name', 'test-server', 'os.type', 'windows'),
    map('service.name', 'windows-security')
);
```

#### Verify Alert

```bash
# Watch logs for alert
docker-compose logs -f security-analyzer | grep -i "alert"

# Or check application logs
tail -f logs/security-analyzer.log | grep "Failed Login"
```

You should see:
```
Generated 1 alerts
```
If Keep alerting is configured (`alerting.keep_api_key`), you should also see:
```
Alert sent successfully: Failed Login Attempt
```

---

## 2. Test With Real Sigma Rules (After Integration)

### A. Using Test Script

Create a test script to inject sample events:

```bash
#!/bin/bash
# test_sigma_rules.sh

# Test Windows Mimikatz Detection (Sigma rule example)
curl -X POST http://localhost:9000 \
  -d "INSERT INTO signoz_logs.logs_v2 FORMAT JSONEachRow" \
  -d '{
    "timestamp": '$(date +%s%N)',
    "severity_text": "CRITICAL",
    "body": "{\"EventID\": 10, \"Channel\": \"Security\", \"EventData\": {\"TargetImage\": \"C:\\\\Windows\\\\System32\\\\lsass.exe\", \"GrantedAccess\": \"0x1010\"}}",
    "attributes_string": {"host.name": "victim-pc", "os.type": "windows"}
  }'

# Test Suspicious PowerShell
curl -X POST http://localhost:9000 \
  -d "INSERT INTO signoz_logs.logs_v2 FORMAT JSONEachRow" \
  -d '{
    "timestamp": '$(date +%s%N)',
    "body": "{\"EventID\": 4104, \"Channel\": \"Microsoft-Windows-PowerShell/Operational\", \"ScriptBlockText\": \"IEX (New-Object Net.WebClient).DownloadString\"}",
    "attributes_string": {"host.name": "test-server"}
  }'

echo "Test events injected. Check logs in 10 seconds..."
sleep 10
docker-compose logs security-analyzer | tail -20
```

### B. Monitor Specific Rule Matches

```bash
# Watch for specific rule matches
docker-compose logs -f security-analyzer | grep "rule_title"

# Count alerts by rule
docker-compose logs security-analyzer | grep "rule_title" | sort | uniq -c
```

---

## 3. Manual Log Analysis

### Check What's Being Processed

```python
#!/usr/bin/env python3
# debug_logs.py - Check what logs are being fetched

from clickhouse_driver import Client

client = Client(host='clickhouse', port=9000, database='signoz_logs')

# Get recent logs
rows = client.execute("""
    SELECT
        timestamp,
        body,
        attributes_string,
        severity_text
    FROM logs_v2
    ORDER BY timestamp DESC
    LIMIT 10
""")

for row in rows:
    print(f"Timestamp: {row[0]}")
    print(f"Body: {row[1]}")
    print(f"Attributes: {row[2]}")
    print(f"Severity: {row[3]}")
    print("-" * 80)
```

---

## 4. Test Field Mapping

Verify OTEL → Sigma field mapping is working:

```python
#!/usr/bin/env python3
# test_mapper.py

import sys
sys.path.insert(0, 'src')

from mappers.otel_mapper import OtelMapper
import yaml
import json

# Load mappings
with open('config/field_mappings.yaml') as f:
    mappings = yaml.safe_load(f)

mapper = OtelMapper(mappings)

# Test Windows log
test_log = {
    'timestamp': 1234567890,
    'body': '{"EventID": 4625, "Channel": "Security"}',
    'attributes_string': {'host.name': 'test-pc', 'os.type': 'windows'},
    'severity_text': 'WARN'
}

# Map it
mapped = mapper.map_to_sigma(test_log)

print("Original log:")
print(json.dumps(test_log, indent=2))
print("\nMapped log:")
print(json.dumps(mapped, indent=2))
print(f"\nDetected source type: {mapped.get('_source_type')}")
```

Run it:
```bash
python3 test_mapper.py
```

Expected output:
```json
{
  "EventID": 4625,
  "Channel": "Security",
  "Computer": "test-pc",
  "OSType": "windows",
  "Level": "WARN",
  "_source_type": "windows",
  "_timestamp": 1234567890
}
```

---

## 5. Integration Testing

### Test End-to-End Flow

Create comprehensive test:

```python
#!/usr/bin/env python3
# test_e2e.py - End-to-end test

import sys
sys.path.insert(0, 'src')

from clickhouse_driver import Client
import time
import json

# 1. Insert test event
client = Client(host='clickhouse', port=9000, database='signoz_logs')

test_event = {
    'timestamp': int(time.time() * 1e9),
    'severity_text': 'WARN',
    'severity_number': 13,
    'body': json.dumps({
        'EventID': 4625,
        'Channel': 'Security',
        'EventData': {
            'TargetUserName': 'admin',
            'IpAddress': '192.168.1.50'
        }
    }),
    'attributes_string': {
        'host.name': 'test-server',
        'os.type': 'windows'
    },
    'resources_string': {
        'service.name': 'security-test'
    }
}

print("Inserting test event...")
client.execute(
    """
    INSERT INTO logs_v2
    (timestamp, severity_text, severity_number, body, attributes_string, resources_string)
    VALUES
    """,
    [test_event]
)

print("Event inserted. Waiting 10 seconds for processing...")
time.sleep(10)

print("Check logs for alert!")
print("Run: docker-compose logs security-analyzer | tail -20")
```

---

## 6. Validate Sigma Rules Syntax

Before deploying new rules, validate them:

```bash
# Install sigma-cli
pip install sigma-cli

# Validate a rule
sigma check config/sigma_rules/rules/windows/process_creation/proc_creation_win_susp_powershell.yml

# Convert rule to see what it matches
sigma convert -t clickhouse config/sigma_rules/rules/windows/process_creation/proc_creation_win_susp_powershell.yml
```

---

## 7. Performance Testing

### Load Test

```python
#!/usr/bin/env python3
# load_test.py - Generate high volume of test logs

from clickhouse_driver import Client
import time
import random

client = Client(host='clickhouse', port=9000, database='signoz_logs')

event_ids = [4625, 4624, 4720, 4728]  # Various Windows events
hostnames = ['server1', 'server2', 'server3', 'workstation1']

print("Generating 1000 test events...")

batch = []
for i in range(1000):
    event = {
        'timestamp': int(time.time() * 1e9) + i,
        'severity_text': random.choice(['INFO', 'WARN', 'ERROR']),
        'severity_number': random.randint(1, 20),
        'body': f'{{"EventID": {random.choice(event_ids)}, "Channel": "Security"}}',
        'attributes_string': {
            'host.name': random.choice(hostnames),
            'os.type': 'windows'
        },
        'resources_string': {'service.name': 'load-test'}
    }
    batch.append(event)

client.execute(
    """
    INSERT INTO logs_v2
    (timestamp, severity_text, severity_number, body, attributes_string, resources_string)
    VALUES
    """,
    batch
)

print(f"Inserted {len(batch)} events")
print("Monitor processing:")
print("  docker-compose logs -f security-analyzer | grep 'Processing'")
```

---

## 8. Alert Verification

### Check Keep Platform

After generating test events:

1. **Login to Keep**: https://your-keep-instance.com
2. **Navigate to Alerts**: Check incoming alerts
3. **Verify Payload**: Ensure alert contains:
   - Rule title
   - Severity
   - Original log data
   - Timestamp

### Check Alert Deduplication

```bash
# Insert same event twice
for i in {1..2}; do
    clickhouse-client --query "INSERT INTO signoz_logs.logs_v2 (timestamp, body, attributes_string) VALUES ($(date +%s%N), '{\"EventID\": 4625}', map('host.name', 'test'))"
done

# Check logs - should only send 1 alert
docker-compose logs security-analyzer | grep "Skipping duplicate alert"
```

---

## 9. Debug Mode

Enable debug logging for detailed rule matching:

```yaml
# config/config.yaml
logging:
  level: DEBUG  # Change from INFO to DEBUG
  file: logs/security-analyzer.log
```

Restart and watch:
```bash
docker-compose restart
docker-compose logs -f security-analyzer
```

You'll see:
- Which rules are loaded
- Each log being processed
- Field mapping details
- Rule evaluation results

---

## 10. Statistics Dashboard

View real-time statistics:

```bash
# Watch stats output (every 60 seconds)
docker-compose logs -f security-analyzer | grep "System Statistics"
```

Output shows:
```
System Statistics:
Alert Manager: {
  'alerts_in_last_minute': 5,
  'max_alerts_per_minute': 100,
  'deduplication': {
    'backend': 'memory',
    'cached_alerts': 12,
    'window_seconds': 300
  }
}
```

---

## Common Test Scenarios

### Test 1: Failed Login Detection
```sql
-- Windows failed login
INSERT INTO logs_v2 (...) VALUES (...EventID: 4625...)
-- Expected: Alert "Failed Login Attempt"
```

### Test 2: Suspicious Process Creation
```sql
-- PowerShell download cradle
INSERT INTO logs_v2 (...) VALUES (...EventID: 4104, ScriptBlockText: "IEX(New-Object..."...)
-- Expected: Alert if Sigma rule enabled
```

### Test 3: Privilege Escalation
```sql
-- User added to admin group
INSERT INTO logs_v2 (...) VALUES (...EventID: 4728, MemberName: "testuser"...)
-- Expected: Alert if Sigma rule enabled
```

---

## Troubleshooting

### No Alerts Generated

1. **Check if logs are being fetched**:
   ```bash
   docker-compose logs security-analyzer | grep "Fetched.*logs"
   ```

2. **Check field mapping**:
   ```bash
   docker-compose logs security-analyzer | grep "Applying.*mappings"
   ```

3. **Check rule evaluation**:
   ```bash
   docker-compose logs security-analyzer | grep "Generated.*alerts"
   ```

### Alerts Not Reaching Keep

1. **Check webhook URL**:
   ```bash
   docker-compose logs security-analyzer | grep "Alert sent successfully"
   ```

2. **Check for errors**:
   ```bash
   docker-compose logs security-analyzer | grep "Failed to send alert"
   ```

3. **Test webhook manually**:
   ```bash
   curl -X POST https://api.keephq.dev/alerts/event \
     -H "X-API-KEY: your-key" \
     -H "Content-Type: application/json" \
     -d '{"source": "test", "severity": "high", "text": "Test alert"}'
   ```

---

## Next Steps

1. **Implement full Sigma engine** - Replace hardcoded rules
2. **Add unit tests** - Test each component
3. **CI/CD integration** - Automated testing
4. **Monitoring dashboard** - Grafana/Prometheus metrics

---

## Quick Reference

```bash
# Generate test event
./test_sigma_rules.sh

# Watch for alerts
docker-compose logs -f | grep alert

# Check statistics
docker-compose logs | grep "System Statistics"

# Debug field mapping
python3 test_mapper.py

# Load test
python3 load_test.py
```
