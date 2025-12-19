# Checkpoint Management

This document explains how the security log analysis service manages checkpoints to track processing progress.

## Overview

The service uses a checkpoint mechanism to remember the last processed log timestamp. This ensures:
- **No duplicate processing** after service restarts
- **Resilience** to crashes or outages
- **Efficient polling** of only new logs

## How It Works

### Checkpoint Storage

Checkpoints are stored in a JSON file (default: `data/checkpoint.json`):

```json
{
  "last_timestamp": 1734567890000000000,
  "last_updated": "2025-12-19T10:30:45.123456",
  "metadata": {
    "logs_count": 150
  }
}
```

**Fields**:
- `last_timestamp`: The timestamp (in nanoseconds) of the last processed log
- `last_updated`: ISO timestamp when the checkpoint was saved
- `metadata`: Additional information (e.g., how many logs were in the batch)

### Checkpoint Updates

The checkpoint is updated automatically:
1. **After each successful batch** of logs is processed
2. **Before alerts are sent** to ensure consistency
3. **Atomically** using a temporary file + rename (prevents corruption)

## Initial Start Behavior

When the service starts for the **first time** (no checkpoint file exists), it can behave in two ways:

### Mode 1: Start from Current Time (Default)

```yaml
clickhouse:
  initial_start_mode: "now"
```

**Behavior**:
- Service starts processing logs from the moment it starts
- **All historical logs are ignored**
- Only logs arriving after startup are analyzed

**Use Case**:
- Production deployments where you only care about new threats
- Large databases where processing historical logs would take too long
- Real-time monitoring scenarios

**Example**:
```
Service starts at: 2025-12-19 10:00:00
Checkpoint set to: 2025-12-19 10:00:00
Historical logs:   ❌ SKIPPED
New logs (>10:00): ✅ PROCESSED
```

### Mode 2: Start from Beginning

```yaml
clickhouse:
  initial_start_mode: "beginning"
```

**Behavior**:
- Service starts processing logs from timestamp 0 (beginning of time)
- **All historical logs will be processed**
- May take significant time depending on database size

**Use Case**:
- Initial threat hunting in existing infrastructure
- Post-incident analysis of historical logs
- Testing and validation with known historical events
- Migration from another security system

**Example**:
```
Service starts at: 2025-12-19 10:00:00
Checkpoint set to: 0 (beginning)
Historical logs:   ✅ PROCESSED (all of them)
New logs:          ✅ PROCESSED
```

### Mode Comparison

| Aspect | `initial_start_mode: "now"` | `initial_start_mode: "beginning"` |
|--------|---------------------------|----------------------------------|
| **Startup Time** | Immediate | May take hours/days |
| **Historical Logs** | Ignored | Processed |
| **Resource Usage** | Low | High (during catch-up) |
| **Recommended For** | Production monitoring | Threat hunting, testing |
| **Alert Flood Risk** | None | High (may need rate limiting) |

## Configuration

Edit `config/config.yaml`:

```yaml
clickhouse:
  host: clickhouse
  port: 9000
  database: signoz_logs
  table: logs_v2
  poll_interval: 5
  batch_size: 1000

  # Initial start behavior (only applies when no checkpoint exists)
  # Options: "now" (default) - start from current time
  #          "beginning" - process all historical logs
  initial_start_mode: "now"

# Checkpoint file location
checkpoint:
  file: data/checkpoint.json
```

## Subsequent Starts

**Important**: The `initial_start_mode` setting **only applies** when no checkpoint exists.

Once a checkpoint file is created:
- The service **always resumes** from the saved checkpoint
- Historical logs before the checkpoint are never reprocessed
- The `initial_start_mode` setting is ignored

**Example Timeline**:

```
Day 1 (no checkpoint):
  - initial_start_mode: "now"
  - Starts at 2025-12-19 10:00:00
  - Checkpoint saved: 2025-12-19 10:05:00

Service restarts on Day 2:
  - Loads checkpoint: 2025-12-19 10:05:00
  - Resumes from that point (ignores initial_start_mode)
  - Processes logs after 10:05:00

Service restarts on Day 3:
  - Loads checkpoint: 2025-12-20 08:30:00
  - Resumes from that point
```

## Checkpoint File Management

### View Current Checkpoint

```bash
# Pretty-print checkpoint
cat data/checkpoint.json | jq

# Quick view
cat data/checkpoint.json
```

### Reset Checkpoint (Process Historical Logs)

If you want to reprocess historical logs:

```bash
# Stop the service
docker-compose stop security-analyzer

# Delete checkpoint
rm data/checkpoint.json

# Update config to process from beginning
nano config/config.yaml
# Set: initial_start_mode: "beginning"

# Restart service
docker-compose start security-analyzer

# Monitor progress
docker-compose logs -f security-analyzer
```

### Backup Checkpoint

Before major changes:

```bash
# Backup
cp data/checkpoint.json data/checkpoint.json.backup

# Restore if needed
cp data/checkpoint.json.backup data/checkpoint.json
docker-compose restart security-analyzer
```

### Set Custom Starting Point

To start from a specific timestamp:

```bash
# Stop service
docker-compose stop security-analyzer

# Create checkpoint with custom timestamp (nanoseconds)
cat > data/checkpoint.json <<EOF
{
  "last_timestamp": 1734000000000000000,
  "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%S.%6N)",
  "metadata": {
    "notes": "Custom starting point"
  }
}
EOF

# Restart
docker-compose start security-analyzer
```

**Tip**: Convert human-readable date to nanoseconds:
```bash
# Linux
date -d "2025-12-01 00:00:00" +%s%N

# macOS
date -j -f "%Y-%m-%d %H:%M:%S" "2025-12-01 00:00:00" "+%s000000000"
```

## Monitoring

### Check Checkpoint Updates

```bash
# Watch checkpoint file changes
watch -n 1 'cat data/checkpoint.json | jq'

# View logs about checkpoint
docker-compose logs security-analyzer | grep -i checkpoint
```

### Troubleshooting

#### Checkpoint Not Updating

```bash
# Check if service is running
docker ps | grep security-log-analyzer

# Check for errors
docker-compose logs security-analyzer | grep -i error

# Verify ClickHouse connectivity
docker exec -it security-log-analyzer python3 -c "
from clickhouse_driver import Client
client = Client(host='clickhouse', port=9000, database='signoz_logs')
print(client.execute('SELECT count() FROM logs_v2'))
"
```

#### Checkpoint Corrupted

```bash
# Stop service
docker-compose stop security-analyzer

# Validate JSON
cat data/checkpoint.json | jq empty
# If error: JSON is corrupted

# Fix: Delete and let service recreate
rm data/checkpoint.json

# Restart
docker-compose start security-analyzer
```

#### Service Processes Same Logs Repeatedly

Possible causes:
1. Checkpoint file not writable
2. Checkpoint directory doesn't exist
3. Service running as wrong user

```bash
# Check permissions
ls -la data/checkpoint.json

# Fix permissions
chmod 644 data/checkpoint.json
chown 1000:1000 data/checkpoint.json  # Adjust UID/GID as needed

# Ensure directory exists
mkdir -p data
chmod 755 data
```

## Best Practices

### Production Deployments

1. **Use `initial_start_mode: "now"`** for new deployments
2. **Backup checkpoint** before major changes
3. **Monitor checkpoint updates** to ensure processing continues
4. **Use external storage** for checkpoint in containerized environments (already configured via volume mounts)

### Testing/Development

1. **Use `initial_start_mode: "beginning"`** to test with historical data
2. **Delete checkpoint** between test runs for consistency
3. **Use separate checkpoint files** for different environments

### Disaster Recovery

```bash
# Regular checkpoint backups
crontab -e
# Add:
0 * * * * cp /opt/opentelemetry-log-ai/data/checkpoint.json /backup/checkpoint-$(date +\%Y\%m\%d-\%H).json

# Keep last 7 days
find /backup -name "checkpoint-*.json" -mtime +7 -delete
```

## Performance Considerations

### Historical Log Processing

When using `initial_start_mode: "beginning"`:

1. **Batch Size**: Consider increasing `batch_size` for faster processing
   ```yaml
   clickhouse:
     batch_size: 5000  # Higher for historical processing
   ```

2. **Alert Rate Limiting**: Historical logs may trigger many alerts
   ```yaml
   alerting:
     max_alerts_per_minute: 1000  # Increase limit temporarily
   ```

3. **Monitor Progress**: Check logs to see how fast processing is happening
   ```bash
   docker-compose logs security-analyzer | grep "Fetched.*logs"
   ```

4. **Estimate Time**: Calculate based on batch processing rate
   ```
   Total logs: 1,000,000
   Batch size: 1000
   Processing rate: 1 batch/5 seconds

   Time = (1,000,000 / 1000) * 5 seconds = 5000 seconds ≈ 1.4 hours
   ```

## Security Considerations

The checkpoint file contains:
- ✅ Timestamps (not sensitive)
- ✅ Metadata about batch sizes (not sensitive)
- ❌ No log content
- ❌ No credentials

**File Permissions**: Set to `644` (readable by all, writable by owner)

---

## Quick Reference

```bash
# View checkpoint
cat data/checkpoint.json | jq

# Reset to beginning
rm data/checkpoint.json && \
sed -i 's/initial_start_mode: "now"/initial_start_mode: "beginning"/' config/config.yaml && \
docker-compose restart security-analyzer

# Reset to now
rm data/checkpoint.json && \
sed -i 's/initial_start_mode: "beginning"/initial_start_mode: "now"/' config/config.yaml && \
docker-compose restart security-analyzer

# Monitor checkpoint updates
watch -n 2 'cat data/checkpoint.json | jq'

# Check logs about checkpoint
docker-compose logs security-analyzer | grep checkpoint
```
